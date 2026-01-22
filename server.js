const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'catalog-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

const upload = multer({ storage: multer.memoryStorage() });

var zohoAccessToken = null;
var lastImportId = null;

async function initDB() {
    try {
        await pool.query('CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL, role VARCHAR(50) DEFAULT \'sales_rep\', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, style_id VARCHAR(100) NOT NULL, base_style VARCHAR(100), name VARCHAR(255) NOT NULL, category VARCHAR(100), image_url TEXT, first_seen_import INTEGER, ai_tags TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS product_colors (id SERIAL PRIMARY KEY, product_id INTEGER REFERENCES products(id) ON DELETE CASCADE, color_name VARCHAR(100) NOT NULL, available_qty INTEGER DEFAULT 0, on_hand INTEGER DEFAULT 0, open_order INTEGER DEFAULT 0, to_come INTEGER DEFAULT 0, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS sync_history (id SERIAL PRIMARY KEY, sync_type VARCHAR(50), status VARCHAR(50), records_synced INTEGER DEFAULT 0, error_message TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS zoho_tokens (id SERIAL PRIMARY KEY, access_token TEXT, refresh_token TEXT, expires_at TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS selections (id SERIAL PRIMARY KEY, share_id VARCHAR(50) UNIQUE NOT NULL, name VARCHAR(255), product_ids INTEGER[], created_by VARCHAR(255), share_type VARCHAR(50) DEFAULT \'link\', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS user_picks (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, product_id INTEGER REFERENCES products(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, product_id))');
        await pool.query('CREATE TABLE IF NOT EXISTS user_notes (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, product_id INTEGER REFERENCES products(id) ON DELETE CASCADE, note TEXT, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, product_id))');
        await pool.query('CREATE TABLE IF NOT EXISTS sales_history_cache (id SERIAL PRIMARY KEY, base_style VARCHAR(100) UNIQUE NOT NULL, summary JSONB, history JSONB, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS sales_data (id SERIAL PRIMARY KEY, document_type VARCHAR(50), document_number VARCHAR(100), doc_date DATE, customer_vendor VARCHAR(255), line_item_sku VARCHAR(255), base_style VARCHAR(100), status VARCHAR(50), quantity DECIMAL(12,2), amount DECIMAL(12,2), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_sales_data_base_style ON sales_data(base_style)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_sales_data_document_type ON sales_data(document_type)');
        
        // Add columns if they don't exist (for existing databases)
        try { await pool.query('ALTER TABLE selections ADD COLUMN IF NOT EXISTS share_type VARCHAR(50) DEFAULT \'link\''); } catch (e) {}
        try { await pool.query('ALTER TABLE products ADD COLUMN IF NOT EXISTS first_seen_import INTEGER'); } catch (e) {}
        try { await pool.query('ALTER TABLE products ADD COLUMN IF NOT EXISTS ai_tags TEXT'); } catch (e) {}
        try { await pool.query('ALTER TABLE product_colors ADD COLUMN IF NOT EXISTS left_to_sell INTEGER DEFAULT 0'); } catch (e) {}
        try { await pool.query('ALTER TABLE product_colors ADD COLUMN IF NOT EXISTS available_now INTEGER DEFAULT 0'); } catch (e) {}
        
        var userCheck = await pool.query('SELECT COUNT(*) FROM users');
        if (parseInt(userCheck.rows[0].count) === 0) {
            var hash = await bcrypt.hash('admin123', 10);
            await pool.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', ['admin', hash, 'admin']);
            console.log('Default admin user created (admin/admin123)');
        }
        
        var tokenResult = await pool.query('SELECT * FROM zoho_tokens ORDER BY id DESC LIMIT 1');
        if (tokenResult.rows.length > 0) {
            zohoAccessToken = tokenResult.rows[0].access_token;
            console.log('Loaded stored Zoho access token');
        }
        
        // Get last import ID for new arrivals tracking
        var importResult = await pool.query("SELECT id FROM sync_history WHERE sync_type = 'csv_import' AND status = 'success' ORDER BY id DESC LIMIT 1");
        if (importResult.rows.length > 0) {
            lastImportId = importResult.rows[0].id;
        }
        
        console.log('Database initialized successfully');
    } catch (err) { console.error('Database initialization error:', err); }
}

function requireAuth(req, res, next) { next(); }
function requireAdmin(req, res, next) { next(); }

app.post('/api/login', async function(req, res) {
    try {
        var username = req.body.username;
        var password = req.body.password;
        var result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        var user = result.rows[0];
        var valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        res.json({ success: true, username: user.username, role: user.role });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/logout', function(req, res) { req.session.destroy(); res.json({ success: true }); });

app.get('/api/session', function(req, res) {
    res.json({ loggedIn: true, username: req.session.username || 'admin', role: req.session.role || 'admin', userId: req.session.userId || 1 });
});

app.get('/api/products', requireAuth, async function(req, res) {
    try {
        var result = await pool.query('SELECT p.id, p.style_id, p.base_style, p.name, p.category, p.image_url, p.first_seen_import, p.ai_tags, json_agg(json_build_object(\'id\', pc.id, \'color_name\', pc.color_name, \'available_now\', COALESCE(pc.available_now, pc.available_qty, 0), \'left_to_sell\', COALESCE(pc.left_to_sell, pc.available_qty, 0), \'on_hand\', pc.on_hand, \'open_order\', COALESCE(pc.open_order, 0), \'to_come\', COALESCE(pc.to_come, 0))) FILTER (WHERE pc.id IS NOT NULL) as colors FROM products p LEFT JOIN product_colors pc ON p.id = pc.product_id GROUP BY p.id ORDER BY p.category, p.name');
        res.json({ products: result.rows, lastImportId: lastImportId });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// AI Analysis endpoint - analyze products without tags
app.post('/api/ai-analyze', requireAuth, requireAdmin, async function(req, res) {
    try {
        if (!process.env.ANTHROPIC_API_KEY) {
            return res.json({ success: false, error: 'ANTHROPIC_API_KEY not configured in environment variables' });
        }
        
        // Get products without AI tags that have images - batch of 100
        var result = await pool.query("SELECT id, style_id, name, image_url FROM products WHERE (ai_tags IS NULL OR ai_tags = '') AND image_url IS NOT NULL AND image_url != '' LIMIT 100");
        
        if (result.rows.length === 0) {
            return res.json({ success: true, message: 'All products already have AI tags', analyzed: 0, remaining: 0 });
        }
        
        var analyzed = 0;
        var errors = 0;
        for (var i = 0; i < result.rows.length; i++) {
            var product = result.rows[i];
            try {
                var tags = await analyzeProductImage(product.image_url, product.name);
                if (tags) {
                    await pool.query('UPDATE products SET ai_tags = $1 WHERE id = $2', [tags, product.id]);
                    analyzed++;
                } else {
                    errors++;
                }
            } catch (err) {
                console.error('AI analysis error for', product.style_id, err.message);
                errors++;
            }
            // Minimal delay (100ms) - Anthropic API can handle this
            await new Promise(function(resolve) { setTimeout(resolve, 100); });
        }
        
        // Check how many remain
        var remaining = await pool.query("SELECT COUNT(*) FROM products WHERE (ai_tags IS NULL OR ai_tags = '') AND image_url IS NOT NULL AND image_url != ''");
        
        res.json({ 
            success: true, 
            message: 'Analyzed ' + analyzed + ' products' + (errors > 0 ? ' (' + errors + ' errors)' : ''), 
            analyzed: analyzed, 
            remaining: parseInt(remaining.rows[0].count)
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get AI analysis status
app.get('/api/ai-status', requireAuth, async function(req, res) {
    try {
        var total = await pool.query('SELECT COUNT(*) FROM products WHERE image_url IS NOT NULL');
        var withTags = await pool.query("SELECT COUNT(*) FROM products WHERE ai_tags IS NOT NULL AND ai_tags != ''");
        var hasKey = !!process.env.ANTHROPIC_API_KEY;
        res.json({
            configured: hasKey,
            total: parseInt(total.rows[0].count),
            analyzed: parseInt(withTags.rows[0].count),
            remaining: parseInt(total.rows[0].count) - parseInt(withTags.rows[0].count)
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// User picks (My Picks / wishlist)
app.get('/api/picks', requireAuth, async function(req, res) {
    try {
        var userId = req.session.userId || 1;
        var result = await pool.query('SELECT product_id FROM user_picks WHERE user_id = $1', [userId]);
        res.json(result.rows.map(function(r) { return r.product_id; }));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/picks/:productId', requireAuth, async function(req, res) {
    try {
        var userId = req.session.userId || 1;
        var productId = parseInt(req.params.productId);
        await pool.query('INSERT INTO user_picks (user_id, product_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [userId, productId]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/picks/:productId', requireAuth, async function(req, res) {
    try {
        var userId = req.session.userId || 1;
        var productId = parseInt(req.params.productId);
        await pool.query('DELETE FROM user_picks WHERE user_id = $1 AND product_id = $2', [userId, productId]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// User notes
app.get('/api/notes', requireAuth, async function(req, res) {
    try {
        var userId = req.session.userId || 1;
        var result = await pool.query('SELECT product_id, note FROM user_notes WHERE user_id = $1', [userId]);
        var notes = {};
        result.rows.forEach(function(r) { notes[r.product_id] = r.note; });
        res.json(notes);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/notes/:productId', requireAuth, async function(req, res) {
    try {
        var userId = req.session.userId || 1;
        var productId = parseInt(req.params.productId);
        var note = req.body.note || '';
        if (note.trim() === '') {
            await pool.query('DELETE FROM user_notes WHERE user_id = $1 AND product_id = $2', [userId, productId]);
        } else {
            await pool.query('INSERT INTO user_notes (user_id, product_id, note, updated_at) VALUES ($1, $2, $3, NOW()) ON CONFLICT (user_id, product_id) DO UPDATE SET note = $3, updated_at = NOW()', [userId, productId, note]);
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

async function refreshZohoToken() {
    try {
        var clientId = process.env.ZOHO_CLIENT_ID;
        var clientSecret = process.env.ZOHO_CLIENT_SECRET;
        var refreshToken = process.env.ZOHO_REFRESH_TOKEN;
        if (!clientId || !clientSecret || !refreshToken) { console.log('Missing Zoho credentials'); return { success: false, error: 'Missing Zoho credentials' }; }
        var params = new URLSearchParams();
        params.append('refresh_token', refreshToken);
        params.append('client_id', clientId);
        params.append('client_secret', clientSecret);
        params.append('grant_type', 'refresh_token');
        var response = await fetch('https://accounts.zoho.com/oauth/v2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params.toString() });
        var data = await response.json();
        if (data.access_token) {
            zohoAccessToken = data.access_token;
            var expiresAt = new Date(Date.now() + (data.expires_in || 3600) * 1000);
            await pool.query('INSERT INTO zoho_tokens (access_token, refresh_token, expires_at, updated_at) VALUES ($1, $2, $3, NOW())', [zohoAccessToken, refreshToken, expiresAt]);
            console.log('Zoho token refreshed successfully');
            return { success: true };
        } else { console.error('Failed to refresh Zoho token:', data); return { success: false, error: data.error || 'Token refresh failed' }; }
    } catch (err) { console.error('Error refreshing Zoho token:', err); return { success: false, error: err.message }; }
}

function startTokenRefreshJob() {
    console.log('Starting background token refresh job (every 30 minutes)');
    refreshZohoToken();
    setInterval(function() { refreshZohoToken(); }, 30 * 60 * 1000);
}

// AI Image Analysis using Claude Vision
async function analyzeProductImage(imageUrl, productName) {
    try {
        var anthropicKey = process.env.ANTHROPIC_API_KEY;
        if (!anthropicKey) {
            console.log('ANTHROPIC_API_KEY not configured, skipping AI analysis');
            return null;
        }
        
        // Fetch the image
        var imgResponse;
        if (imageUrl.indexOf('download-accl.zoho.com') !== -1) {
            // WorkDrive image - need to fetch with auth
            if (!zohoAccessToken) await refreshZohoToken();
            var fileId = imageUrl.split('/').pop();
            var workdriveUrl = 'https://workdrive.zoho.com/api/v1/download/' + fileId;
            imgResponse = await fetch(workdriveUrl, { 
                headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken } 
            });
        } else {
            imgResponse = await fetch(imageUrl);
        }
        
        if (!imgResponse.ok) {
            console.log('Failed to fetch image:', imageUrl);
            return null;
        }
        
        var imgBuffer = Buffer.from(await imgResponse.arrayBuffer());
        var base64Image = imgBuffer.toString('base64');
        var mediaType = imgResponse.headers.get('content-type') || 'image/jpeg';
        
        // Call Claude Vision API
        var response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': anthropicKey,
                'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
                model: 'claude-sonnet-4-20250514',
                max_tokens: 300,
                messages: [{
                    role: 'user',
                    content: [
                        {
                            type: 'image',
                            source: { type: 'base64', media_type: mediaType, data: base64Image }
                        },
                        {
                            type: 'text',
                            text: 'Analyze this apparel product image. Return ONLY a comma-separated list of descriptive tags (no sentences). Be thorough and specific. Include:\n- Garment type: sweater, cardigan, hoodie, sweatshirt, t-shirt, tank top, blouse, dress, skirt, pants, jeans, shorts, jacket, coat, romper, jumpsuit, set, matching set, 2-piece, etc.\n- Neckline: crew neck, v-neck, scoop neck, turtleneck, mock neck, hoodie, collared, off-shoulder, etc.\n- Closure: button-front, zip-up, pullover, snap buttons, tie-front, open-front, etc.\n- Sleeves: long sleeve, short sleeve, sleeveless, 3/4 sleeve, cap sleeve, etc.\n- Fit: oversized, relaxed, slim, fitted, cropped, longline, regular, boxy, etc.\n- Length: mini, midi, maxi, cropped, full-length, etc.\n- Pattern: solid, striped, horizontal stripes, vertical stripes, floral, plaid, checkered, polka dot, animal print, leopard, camo, tie-dye, ombre, colorblock, graphic, logo, text print, heart print, star print, abstract, geometric, etc.\n- Material appearance: knit, ribbed, fleece, denim, leather, satin, lace, mesh, terry, velvet, sequin, etc.\n- Style: casual, athletic, sporty, loungewear, streetwear, bohemian, preppy, vintage, minimalist, glamorous, etc.\n- Details: pockets, kangaroo pocket, drawstring, hood, ribbed cuffs, distressed, embroidered, ruffle, lace trim, etc.\n- Season: spring, summer, fall, winter, all-season\n- Any visible text, brand names, or graphics on the garment\n\nExample output: cardigan, button-front, v-neck, long sleeve, cropped, relaxed fit, striped, horizontal stripes, knit, ribbed, casual, fall, cream and navy'
                        }
                    ]
                }]
            })
        });
        
        if (!response.ok) {
            var errorText = await response.text();
            console.log('Claude API error:', errorText);
            return null;
        }
        
        var data = await response.json();
        var tags = data.content[0].text.trim();
        console.log('AI tags for', productName, ':', tags);
        return tags;
        
    } catch (err) {
        console.error('AI analysis error:', err.message);
        return null;
    }
}

app.get('/api/zoho/status', requireAuth, function(req, res) {
    var hasCredentials = !!(process.env.ZOHO_CLIENT_ID && process.env.ZOHO_CLIENT_SECRET && process.env.ZOHO_REFRESH_TOKEN);
    var hasToken = !!zohoAccessToken;
    res.json({ configured: hasCredentials, connected: hasToken, viewId: process.env.ZOHO_VIEW_ID || null, workspaceId: process.env.ZOHO_WORKSPACE_ID || null });
});

// Debug endpoint to test PO API access
app.get('/api/debug/po-test/:styleId', requireAuth, async function(req, res) {
    try {
        var styleId = req.params.styleId;
        var orgId = process.env.ZOHO_BOOKS_ORG_ID || '677681121';
        
        if (!zohoAccessToken) {
            var tokenResult = await refreshZohoToken();
            if (!tokenResult.success) {
                return res.json({ success: false, error: 'Token refresh failed: ' + tokenResult.error });
            }
        }
        
        var debugResults = {
            styleId: styleId,
            baseStyle: styleId.split('-')[0],
            orgId: orgId,
            searches: [],
            errors: []
        };
        
        // Test 1: Try to list ANY purchase orders (test API access)
        try {
            var testUrl = 'https://www.zohoapis.com/books/v3/purchaseorders?organization_id=' + orgId + '&per_page=5';
            console.log('Testing PO API access:', testUrl);
            var testResponse = await fetch(testUrl, {
                headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken }
            });
            var testData = await testResponse.json();
            debugResults.searches.push({
                test: 'List any POs',
                url: testUrl,
                status: testResponse.status,
                poCount: testData.purchaseorders ? testData.purchaseorders.length : 0,
                message: testData.message || null,
                samplePO: testData.purchaseorders && testData.purchaseorders[0] ? {
                    number: testData.purchaseorders[0].purchaseorder_number,
                    vendor: testData.purchaseorders[0].vendor_name,
                    status: testData.purchaseorders[0].status,
                    date: testData.purchaseorders[0].date
                } : null
            });
        } catch (err) {
            debugResults.errors.push({ test: 'List any POs', error: err.message });
        }
        
        // Test 2: Search using search_text (should search custom fields too)
        var baseStyle = styleId.split('-')[0];
        try {
            var searchUrl = 'https://www.zohoapis.com/books/v3/purchaseorders?organization_id=' + orgId + '&search_text=' + encodeURIComponent(baseStyle);
            console.log('Searching POs with search_text:', searchUrl);
            var searchResponse = await fetch(searchUrl, {
                headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken }
            });
            var searchData = await searchResponse.json();
            debugResults.searches.push({
                test: 'Search by search_text: ' + baseStyle,
                url: searchUrl,
                status: searchResponse.status,
                poCount: searchData.purchaseorders ? searchData.purchaseorders.length : 0,
                message: searchData.message || null,
                pos: searchData.purchaseorders ? searchData.purchaseorders.slice(0, 10).map(function(po) {
                    return { 
                        number: po.purchaseorder_number, 
                        vendor: po.vendor_name, 
                        status: po.status,
                        date: po.date,
                        total: po.total
                    };
                }) : []
            });
            
            // If we found POs, get detail on the first one to see custom fields
            if (searchData.purchaseorders && searchData.purchaseorders.length > 0) {
                var firstPO = searchData.purchaseorders[0];
                var detailUrl = 'https://www.zohoapis.com/books/v3/purchaseorders/' + firstPO.purchaseorder_id + '?organization_id=' + orgId;
                var detailResponse = await fetch(detailUrl, {
                    headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken }
                });
                var detailData = await detailResponse.json();
                if (detailData.purchaseorder) {
                    debugResults.samplePODetail = {
                        number: detailData.purchaseorder.purchaseorder_number,
                        custom_fields: detailData.purchaseorder.custom_fields,
                        line_items_count: detailData.purchaseorder.line_items ? detailData.purchaseorder.line_items.length : 0,
                        first_line_item: detailData.purchaseorder.line_items && detailData.purchaseorder.line_items[0] ? {
                            name: detailData.purchaseorder.line_items[0].name,
                            sku: detailData.purchaseorder.line_items[0].sku,
                            quantity: detailData.purchaseorder.line_items[0].quantity
                        } : null
                    };
                }
            }
        } catch (err) {
            debugResults.errors.push({ test: 'Search by search_text', error: err.message });
        }
        
        // Test 3: Search item_name_contains (for comparison)
        try {
            var itemUrl = 'https://www.zohoapis.com/books/v3/purchaseorders?organization_id=' + orgId + '&item_name_contains=' + encodeURIComponent(baseStyle);
            console.log('Searching POs with item_name_contains:', itemUrl);
            var itemResponse = await fetch(itemUrl, {
                headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken }
            });
            var itemData = await itemResponse.json();
            debugResults.searches.push({
                test: 'Search by item_name_contains: ' + baseStyle,
                url: itemUrl,
                status: itemResponse.status,
                poCount: itemData.purchaseorders ? itemData.purchaseorders.length : 0,
                message: itemData.message || null
            });
        } catch (err) {
            debugResults.errors.push({ test: 'Search by item_name_contains', error: err.message });
        }
        
        res.json({ success: true, debug: debugResults });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// Clear sales history cache (to force re-fetch with updated logic)
app.delete('/api/sales-history-cache', requireAuth, requireAdmin, async function(req, res) {
    try {
        var result = await pool.query('DELETE FROM sales_history_cache');
        console.log('Sales history cache cleared');
        res.json({ success: true, message: 'Cache cleared. ' + result.rowCount + ' entries deleted.' });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.post('/api/zoho/test', requireAuth, requireAdmin, async function(req, res) {
    try {
        if (!zohoAccessToken) { var tokenResult = await refreshZohoToken(); if (!tokenResult.success) return res.json({ success: false, error: tokenResult.error }); }
        res.json({ success: true, message: 'Connection successful' });
    } catch (err) { res.json({ success: false, error: err.message }); }
});

app.post('/api/zoho/sync', requireAuth, requireAdmin, async function(req, res) {
    try {
        var workspaceId = process.env.ZOHO_WORKSPACE_ID; var viewId = process.env.ZOHO_VIEW_ID;
        if (!workspaceId) { await pool.query('INSERT INTO sync_history (sync_type, status, error_message) VALUES ($1, $2, $3)', ['zoho', 'failed', 'ZOHO_WORKSPACE_ID not configured']); return res.json({ success: false, error: 'ZOHO_WORKSPACE_ID not configured' }); }
        if (!viewId) { await pool.query('INSERT INTO sync_history (sync_type, status, error_message) VALUES ($1, $2, $3)', ['zoho', 'failed', 'ZOHO_VIEW_ID not configured']); return res.json({ success: false, error: 'ZOHO_VIEW_ID not configured' }); }
        if (!zohoAccessToken) { var tokenResult = await refreshZohoToken(); if (!tokenResult.success) { await pool.query('INSERT INTO sync_history (sync_type, status, error_message) VALUES ($1, $2, $3)', ['zoho', 'failed', tokenResult.error]); return res.json({ success: false, error: tokenResult.error }); } }
        var apiUrl = 'https://analyticsapi.zoho.com/restapi/v2/workspaces/' + workspaceId + '/views/' + viewId + '/data?CONFIG={"responseFormat":"json"}';
        var response = await fetch(apiUrl, { headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken } });
        if (response.status === 401) { var tokenResult = await refreshZohoToken(); if (!tokenResult.success) { return res.json({ success: false, error: tokenResult.error }); } response = await fetch(apiUrl, { headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken } }); }
        if (!response.ok) { var errorText = await response.text(); await pool.query('INSERT INTO sync_history (sync_type, status, error_message) VALUES ($1, $2, $3)', ['zoho', 'failed', 'API error: ' + response.status]); return res.json({ success: false, error: 'API error: ' + response.status }); }
        var data = await response.json();
        var rows = data.data || data.rows || []; var columns = data.column_order || data.columns || [];
        if (rows.length === 0) { await pool.query('INSERT INTO sync_history (sync_type, status, error_message) VALUES ($1, $2, $3)', ['zoho', 'failed', 'No data returned']); return res.json({ success: false, error: 'No data returned' }); }
        var colMap = {}; for (var ci = 0; ci < columns.length; ci++) { colMap[columns[ci].toLowerCase().replace(/\s+/g, '_')] = ci; }
        await pool.query('DELETE FROM product_colors'); await pool.query('DELETE FROM products');
        var productMap = {}; var recordCount = 0;
        for (var ri = 0; ri < rows.length; ri++) { var row = rows[ri]; var styleIdx = colMap['style_name'] !== undefined ? colMap['style_name'] : 0; var colorIdx = colMap['color'] !== undefined ? colMap['color'] : 1; var categoryIdx = colMap['commodity'] !== undefined ? colMap['commodity'] : 2; var qtyIdx = colMap['left_to_sell'] !== undefined ? colMap['left_to_sell'] : 3; var styleName = row[styleIdx] || 'Unknown'; var color = row[colorIdx] || 'Default'; var category = row[categoryIdx] || 'Uncategorized'; var qty = parseInt(row[qtyIdx]) || 0; var baseStyle = styleName.replace(/\s*-\s*\d+$/, '').trim(); if (!productMap[baseStyle]) { var insertResult = await pool.query('INSERT INTO products (style_id, base_style, name, category) VALUES ($1, $2, $3, $4) RETURNING id', [styleName, baseStyle, baseStyle, category]); productMap[baseStyle] = insertResult.rows[0].id; } await pool.query('INSERT INTO product_colors (product_id, color_name, available_qty) VALUES ($1, $2, $3)', [productMap[baseStyle], color, qty]); recordCount++; }
        await pool.query('INSERT INTO sync_history (sync_type, status, records_synced) VALUES ($1, $2, $3)', ['zoho', 'success', recordCount]);
        res.json({ success: true, message: 'Synced ' + recordCount + ' records' });
    } catch (err) { console.error('Sync error:', err); res.json({ success: false, error: err.message }); }
});

app.get('/api/zoho/sync-history', requireAuth, async function(req, res) { try { var result = await pool.query('SELECT * FROM sync_history ORDER BY created_at DESC LIMIT 20'); res.json(result.rows); } catch (err) { res.status(500).json({ error: err.message }); } });

// Data freshness endpoint - get last CSV import date
app.get('/api/data-freshness', requireAuth, async function(req, res) {
    try {
        var result = await pool.query("SELECT created_at, records_synced FROM sync_history WHERE sync_type = 'csv_import' AND status = 'success' ORDER BY created_at DESC LIMIT 1");
        if (result.rows.length > 0) {
            res.json({ lastUpdate: result.rows[0].created_at, recordCount: result.rows[0].records_synced });
        } else {
            res.json({ lastUpdate: null, recordCount: 0 });
        }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Sales History API - Get invoices and sales orders for a style
// Now uses imported sales_data table
app.get('/api/sales-history/:styleId', requireAuth, async function(req, res) {
    try {
        var styleId = req.params.styleId;
        var baseStyle = styleId.split('-')[0];
        
        console.log('Sales History Request - Style:', styleId, 'Base:', baseStyle);
        
        // Query sales_data table for this style
        var salesResult = await pool.query(
            'SELECT document_type, document_number, doc_date, customer_vendor, status, SUM(quantity) as total_qty, SUM(amount) as total_amount FROM sales_data WHERE base_style = $1 GROUP BY document_type, document_number, doc_date, customer_vendor, status ORDER BY doc_date DESC',
            [baseStyle]
        );
        
        var history = [];
        var totalInvoiced = 0;
        var totalInvoiceAmount = 0;
        var invoiceCount = 0;
        var totalOpenOrders = 0;
        var totalOpenOrdersAmount = 0;
        var openOrderCount = 0;
        var totalPO = 0;
        var totalPOAmount = 0;
        var poCount = 0;
        
        for (var i = 0; i < salesResult.rows.length; i++) {
            var row = salesResult.rows[i];
            var qty = parseFloat(row.total_qty) || 0;
            var amt = parseFloat(row.total_amount) || 0;
            var docType = (row.document_type || '').toLowerCase();
            var status = (row.status || '').toLowerCase();
            
            // Determine type for history display
            var historyType = 'salesorder';
            if (docType.indexOf('purchase') !== -1) {
                historyType = 'purchaseorder';
            } else if (docType.indexOf('invoice') !== -1) {
                historyType = 'invoice';
            }
            
            history.push({
                type: historyType,
                documentNumber: row.document_number,
                date: row.doc_date,
                customerName: row.customer_vendor,
                status: row.status,
                quantity: qty,
                amount: amt,
                isOpen: status !== 'invoiced' && status !== 'closed' && status !== 'fulfilled' && status !== 'paid'
            });
            
            // Categorize for summary
            if (docType.indexOf('purchase') !== -1) {
                // Purchase Orders
                totalPO += qty;
                totalPOAmount += amt;
                poCount++;
            } else if (docType.indexOf('sales') !== -1) {
                // Sales Orders - check if invoiced/closed or still open
                if (status === 'invoiced' || status === 'closed' || status === 'fulfilled') {
                    totalInvoiced += qty;
                    totalInvoiceAmount += amt;
                    invoiceCount++;
                } else {
                    // Open sales order (confirmed, open, pending, etc.)
                    totalOpenOrders += qty;
                    totalOpenOrdersAmount += amt;
                    openOrderCount++;
                }
            }
        }
        
        // Return with field names matching what frontend expects
        res.json({
            success: true,
            styleId: styleId,
            summary: {
                totalInvoiced: totalInvoiced,
                totalInvoicedDollars: totalInvoiceAmount,
                invoiceCount: invoiceCount,
                totalOpenOrders: totalOpenOrders,
                totalOpenOrdersDollars: totalOpenOrdersAmount,
                openOrderCount: openOrderCount,
                totalPO: totalPO,
                totalPODollars: totalPOAmount,
                poCount: poCount
            },
            history: history.slice(0, 50),
            recordCount: salesResult.rows.length
        });
        
    } catch (err) {
        console.error('Sales history error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

/* DISABLED - API calls commented out, will be replaced with CSV import

        var results = [];
        var seenIds = {};
        var debugInfo = { invoiceSearches: [], soSearches: [], errors: [] };
        
        // Helper function to make Zoho Books API calls with retry
        async function zohoApiCall(url, label) {
            console.log('API Call [' + label + ']:', url);
            try {
                var response = await fetch(url, {
                    headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken }
                });
                console.log('Response status [' + label + ']:', response.status);
                
                if (response.status === 401) {
                    console.log('401 - Refreshing token...');
                    await refreshZohoToken();
                    response = await fetch(url, {
                        headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken }
                    });
                    console.log('Retry status [' + label + ']:', response.status);
                }
                
                if (!response.ok) {
                    var errorText = await response.text();
                    console.log('Error response [' + label + ']:', errorText);
                    debugInfo.errors.push({ label: label, status: response.status, error: errorText });
                    return null;
                }
                
                var data = await response.json();
                return data;
            } catch (err) {
                console.log('Fetch error [' + label + ']:', err.message);
                debugInfo.errors.push({ label: label, error: err.message });
                return null;
            }
        }
        
        // Extract base style for broader search (e.g., "71187Y-AB" -> "71187Y")
        var baseStyle = styleId.split('-')[0];
        var searchTerms = [styleId];
        if (baseStyle !== styleId) {
            searchTerms.push(baseStyle);
        }
        
        // Search invoices with multiple strategies
        for (var st = 0; st < searchTerms.length; st++) {
            var searchTerm = searchTerms[st];
            try {
                // Strategy 1: item_name_contains
                var invoiceUrl = 'https://www.zohoapis.com/books/v3/invoices?organization_id=' + orgId + '&item_name_contains=' + encodeURIComponent(searchTerm);
                debugInfo.invoiceSearches.push({ term: searchTerm, strategy: 'item_name_contains' });
                var invoiceData = await zohoApiCall(invoiceUrl, 'invoice-item-' + searchTerm);
                
                if (invoiceData && invoiceData.invoices && invoiceData.invoices.length > 0) {
                    console.log('Found', invoiceData.invoices.length, 'invoices for', searchTerm);
                    
                    for (var i = 0; i < invoiceData.invoices.length; i++) {
                        var inv = invoiceData.invoices[i];
                        if (seenIds['inv-' + inv.invoice_id]) continue;
                        seenIds['inv-' + inv.invoice_id] = true;
                        
                        // Get full invoice details to get line items
                        var detailUrl = 'https://www.zohoapis.com/books/v3/invoices/' + inv.invoice_id + '?organization_id=' + orgId;
                        var detailData = await zohoApiCall(detailUrl, 'invoice-detail-' + inv.invoice_id);
                        
                        if (detailData && detailData.invoice && detailData.invoice.line_items) {
                            var totalQty = 0;
                            var totalAmount = 0;
                            var matchingItems = [];
                            
                            for (var j = 0; j < detailData.invoice.line_items.length; j++) {
                                var item = detailData.invoice.line_items[j];
                                var itemName = (item.name || item.item_name || '').toUpperCase();
                                var itemSku = (item.sku || '').toUpperCase();
                                var searchStyleUpper = styleId.toUpperCase();
                                var baseStyleUpper = baseStyle.toUpperCase();
                                
                                // Check if item name or SKU contains the style ID or base style
                                if (itemName.indexOf(searchStyleUpper) !== -1 || itemSku.indexOf(searchStyleUpper) !== -1 ||
                                    itemName.indexOf(baseStyleUpper) !== -1 || itemSku.indexOf(baseStyleUpper) !== -1) {
                                    totalQty += item.quantity || 0;
                                    totalAmount += item.item_total || 0;
                                    matchingItems.push({
                                        name: item.name || item.item_name,
                                        quantity: item.quantity,
                                        rate: item.rate,
                                        amount: item.item_total
                                    });
                                }
                            }
                            
                            if (totalQty > 0) {
                                results.push({
                                    type: 'invoice',
                                    documentNumber: inv.invoice_number,
                                    date: inv.date,
                                    customerName: inv.customer_name,
                                    status: inv.status,
                                    quantity: totalQty,
                                    amount: totalAmount,
                                    total: inv.total,
                                    items: matchingItems
                                });
                            }
                        }
                    }
                }
                
                // Strategy 2: search_text (general search)
                var searchUrl = 'https://www.zohoapis.com/books/v3/invoices?organization_id=' + orgId + '&search_text=' + encodeURIComponent(searchTerm);
                debugInfo.invoiceSearches.push({ term: searchTerm, strategy: 'search_text' });
                var searchData = await zohoApiCall(searchUrl, 'invoice-search-' + searchTerm);
                
                if (searchData && searchData.invoices && searchData.invoices.length > 0) {
                    console.log('Search found', searchData.invoices.length, 'invoices for', searchTerm);
                    
                    for (var i2 = 0; i2 < searchData.invoices.length; i2++) {
                        var inv2 = searchData.invoices[i2];
                        if (seenIds['inv-' + inv2.invoice_id]) continue;
                        seenIds['inv-' + inv2.invoice_id] = true;
                        
                        var detailUrl2 = 'https://www.zohoapis.com/books/v3/invoices/' + inv2.invoice_id + '?organization_id=' + orgId;
                        var detailData2 = await zohoApiCall(detailUrl2, 'invoice-detail2-' + inv2.invoice_id);
                        
                        if (detailData2 && detailData2.invoice && detailData2.invoice.line_items) {
                            var totalQty2 = 0;
                            var totalAmount2 = 0;
                            var matchingItems2 = [];
                            
                            for (var j2 = 0; j2 < detailData2.invoice.line_items.length; j2++) {
                                var item2 = detailData2.invoice.line_items[j2];
                                var itemName2 = (item2.name || item2.item_name || '').toUpperCase();
                                var itemSku2 = (item2.sku || '').toUpperCase();
                                var searchStyleUpper2 = styleId.toUpperCase();
                                var baseStyleUpper2 = baseStyle.toUpperCase();
                                
                                if (itemName2.indexOf(searchStyleUpper2) !== -1 || itemSku2.indexOf(searchStyleUpper2) !== -1 ||
                                    itemName2.indexOf(baseStyleUpper2) !== -1 || itemSku2.indexOf(baseStyleUpper2) !== -1) {
                                    totalQty2 += item2.quantity || 0;
                                    totalAmount2 += item2.item_total || 0;
                                    matchingItems2.push({
                                        name: item2.name || item2.item_name,
                                        quantity: item2.quantity,
                                        rate: item2.rate,
                                        amount: item2.item_total
                                    });
                                }
                            }
                            
                            if (totalQty2 > 0) {
                                results.push({
                                    type: 'invoice',
                                    documentNumber: inv2.invoice_number,
                                    date: inv2.date,
                                    customerName: inv2.customer_name,
                                    status: inv2.status,
                                    quantity: totalQty2,
                                    amount: totalAmount2,
                                    total: inv2.total,
                                    items: matchingItems2
                                });
                            }
                        }
                    }
                }
            } catch (invErr) {
                console.error('Invoice search error:', invErr.message);
                debugInfo.errors.push({ type: 'invoice', term: searchTerm, error: invErr.message });
            }
        }
        
        // Search sales orders with multiple strategies
        for (var st2 = 0; st2 < searchTerms.length; st2++) {
            var searchTerm2 = searchTerms[st2];
            try {
                // Strategy 1: item_name_contains
                var soUrl = 'https://www.zohoapis.com/books/v3/salesorders?organization_id=' + orgId + '&item_name_contains=' + encodeURIComponent(searchTerm2);
                debugInfo.soSearches.push({ term: searchTerm2, strategy: 'item_name_contains' });
                var soData = await zohoApiCall(soUrl, 'so-item-' + searchTerm2);
                
                if (soData && soData.salesorders && soData.salesorders.length > 0) {
                    console.log('Found', soData.salesorders.length, 'sales orders for', searchTerm2);
                    
                    for (var k = 0; k < soData.salesorders.length; k++) {
                        var so = soData.salesorders[k];
                        if (seenIds['so-' + so.salesorder_id]) continue;
                        seenIds['so-' + so.salesorder_id] = true;
                        
                        var soDetailUrl = 'https://www.zohoapis.com/books/v3/salesorders/' + so.salesorder_id + '?organization_id=' + orgId;
                        var soDetailData = await zohoApiCall(soDetailUrl, 'so-detail-' + so.salesorder_id);
                        
                        if (soDetailData && soDetailData.salesorder && soDetailData.salesorder.line_items) {
                            var soTotalQty = 0;
                            var soTotalAmount = 0;
                            var soMatchingItems = [];
                            
                            for (var m = 0; m < soDetailData.salesorder.line_items.length; m++) {
                                var soItem = soDetailData.salesorder.line_items[m];
                                var soItemName = (soItem.name || soItem.item_name || '').toUpperCase();
                                var soItemSku = (soItem.sku || '').toUpperCase();
                                var soSearchStyleUpper = styleId.toUpperCase();
                                var soBaseStyleUpper = baseStyle.toUpperCase();
                                
                                if (soItemName.indexOf(soSearchStyleUpper) !== -1 || soItemSku.indexOf(soSearchStyleUpper) !== -1 ||
                                    soItemName.indexOf(soBaseStyleUpper) !== -1 || soItemSku.indexOf(soBaseStyleUpper) !== -1) {
                                    soTotalQty += soItem.quantity || 0;
                                    soTotalAmount += soItem.item_total || 0;
                                    soMatchingItems.push({
                                        name: soItem.name || soItem.item_name,
                                        quantity: soItem.quantity,
                                        rate: soItem.rate,
                                        amount: soItem.item_total
                                    });
                                }
                            }
                            
                            if (soTotalQty > 0) {
                                results.push({
                                    type: 'salesorder',
                                    documentNumber: so.salesorder_number,
                                    date: so.date,
                                    customerName: so.customer_name,
                                    status: so.status,
                                    quantity: soTotalQty,
                                    amount: soTotalAmount,
                                    total: so.total,
                                    items: soMatchingItems,
                                    isOpen: so.status === 'open' || so.status === 'pending' || so.status === 'draft'
                                });
                            }
                        }
                    }
                }
                
                // Strategy 2: search_text
                var soSearchUrl = 'https://www.zohoapis.com/books/v3/salesorders?organization_id=' + orgId + '&search_text=' + encodeURIComponent(searchTerm2);
                debugInfo.soSearches.push({ term: searchTerm2, strategy: 'search_text' });
                var soSearchData = await zohoApiCall(soSearchUrl, 'so-search-' + searchTerm2);
                
                if (soSearchData && soSearchData.salesorders && soSearchData.salesorders.length > 0) {
                    console.log('Search found', soSearchData.salesorders.length, 'sales orders for', searchTerm2);
                    
                    for (var k2 = 0; k2 < soSearchData.salesorders.length; k2++) {
                        var so2 = soSearchData.salesorders[k2];
                        if (seenIds['so-' + so2.salesorder_id]) continue;
                        seenIds['so-' + so2.salesorder_id] = true;
                        
                        var soDetailUrl2 = 'https://www.zohoapis.com/books/v3/salesorders/' + so2.salesorder_id + '?organization_id=' + orgId;
                        var soDetailData2 = await zohoApiCall(soDetailUrl2, 'so-detail2-' + so2.salesorder_id);
                        
                        if (soDetailData2 && soDetailData2.salesorder && soDetailData2.salesorder.line_items) {
                            var soTotalQty2 = 0;
                            var soTotalAmount2 = 0;
                            var soMatchingItems2 = [];
                            
                            for (var m2 = 0; m2 < soDetailData2.salesorder.line_items.length; m2++) {
                                var soItem2 = soDetailData2.salesorder.line_items[m2];
                                var soItemName2 = (soItem2.name || soItem2.item_name || '').toUpperCase();
                                var soItemSku2 = (soItem2.sku || '').toUpperCase();
                                var soSearchStyleUpper2 = styleId.toUpperCase();
                                var soBaseStyleUpper2 = baseStyle.toUpperCase();
                                
                                if (soItemName2.indexOf(soSearchStyleUpper2) !== -1 || soItemSku2.indexOf(soSearchStyleUpper2) !== -1 ||
                                    soItemName2.indexOf(soBaseStyleUpper2) !== -1 || soItemSku2.indexOf(soBaseStyleUpper2) !== -1) {
                                    soTotalQty2 += soItem2.quantity || 0;
                                    soTotalAmount2 += soItem2.item_total || 0;
                                    soMatchingItems2.push({
                                        name: soItem2.name || soItem2.item_name,
                                        quantity: soItem2.quantity,
                                        rate: soItem2.rate,
                                        amount: soItem2.item_total
                                    });
                                }
                            }
                            
                            if (soTotalQty2 > 0) {
                                results.push({
                                    type: 'salesorder',
                                    documentNumber: so2.salesorder_number,
                                    date: so2.date,
                                    customerName: so2.customer_name,
                                    status: so2.status,
                                    quantity: soTotalQty2,
                                    amount: soTotalAmount2,
                                    total: so2.total,
                                    items: soMatchingItems2,
                                    isOpen: so2.status === 'open' || so2.status === 'pending' || so2.status === 'draft'
                                });
                            }
                        }
                    }
                }
            } catch (soErr) {
                console.error('Sales order search error:', soErr.message);
                debugInfo.errors.push({ type: 'salesorder', term: searchTerm2, error: soErr.message });
            }
        }
        
        // Search Purchase Orders (incoming inventory)
        debugInfo.poSearches = [];
        for (var pt = 0; pt < searchTerms.length; pt++) {
            var poSearchTerm = searchTerms[pt];
            try {
                // Strategy 1: item_name_contains (all statuses)
                var poStatuses = ['draft', 'open', 'issued', 'billed', 'closed'];
                for (var psi = 0; psi < poStatuses.length; psi++) {
                    var poStatus = poStatuses[psi];
                    
                    var poUrl = 'https://www.zohoapis.com/books/v3/purchaseorders?organization_id=' + orgId + '&status=' + poStatus + '&item_name_contains=' + encodeURIComponent(poSearchTerm);
                    debugInfo.poSearches.push({ term: poSearchTerm, strategy: 'item_name_contains', status: poStatus });
                    var poData = await zohoApiCall(poUrl, 'po-' + poStatus + '-' + poSearchTerm);
                
                if (poData && poData.purchaseorders && poData.purchaseorders.length > 0) {
                    console.log('Found', poData.purchaseorders.length, 'purchase orders for', poSearchTerm);
                    
                    for (var pi = 0; pi < poData.purchaseorders.length; pi++) {
                        var po = poData.purchaseorders[pi];
                        if (seenIds['po-' + po.purchaseorder_id]) continue;
                        seenIds['po-' + po.purchaseorder_id] = true;
                        
                        var poDetailUrl = 'https://www.zohoapis.com/books/v3/purchaseorders/' + po.purchaseorder_id + '?organization_id=' + orgId;
                        var poDetailData = await zohoApiCall(poDetailUrl, 'po-detail-' + po.purchaseorder_id);
                        
                        if (poDetailData && poDetailData.purchaseorder && poDetailData.purchaseorder.line_items) {
                            var poTotalQty = 0;
                            var poTotalAmount = 0;
                            var poMatchingItems = [];
                            var poDetailObj = poDetailData.purchaseorder;
                            
                            // Check if style is in custom fields
                            var poCustomMatch1 = false;
                            var poCustomFields1 = JSON.stringify(poDetailObj.custom_fields || []).toUpperCase();
                            if (poCustomFields1.indexOf(styleId.toUpperCase()) !== -1 || poCustomFields1.indexOf(baseStyle.toUpperCase()) !== -1) {
                                poCustomMatch1 = true;
                                console.log('PO custom field match for', po.purchaseorder_number);
                            }
                            
                            for (var pj = 0; pj < poDetailObj.line_items.length; pj++) {
                                var poItem = poDetailObj.line_items[pj];
                                var poItemName = (poItem.name || poItem.item_name || poItem.description || '').toUpperCase();
                                var poItemSku = (poItem.sku || poItem.item_id || '').toUpperCase();
                                var poSearchStyleUpper = styleId.toUpperCase();
                                var poBaseStyleUpper = baseStyle.toUpperCase();
                                
                                var itemMatch1 = poItemName.indexOf(poSearchStyleUpper) !== -1 || poItemSku.indexOf(poSearchStyleUpper) !== -1 ||
                                    poItemName.indexOf(poBaseStyleUpper) !== -1 || poItemSku.indexOf(poBaseStyleUpper) !== -1;
                                
                                if (itemMatch1 || poCustomMatch1) {
                                    poTotalQty += poItem.quantity || 0;
                                    poTotalAmount += poItem.item_total || 0;
                                    poMatchingItems.push({
                                        name: poItem.name || poItem.item_name,
                                        quantity: poItem.quantity,
                                        rate: poItem.rate,
                                        amount: poItem.item_total
                                    });
                                }
                            }
                            
                            if (poTotalQty > 0) {
                                results.push({
                                    type: 'purchaseorder',
                                    documentNumber: po.purchaseorder_number,
                                    date: po.date,
                                    customerName: po.vendor_name,
                                    status: po.status,
                                    quantity: poTotalQty,
                                    amount: poTotalAmount,
                                    total: po.total,
                                    items: poMatchingItems,
                                    isOpen: po.status === 'open' || po.status === 'draft' || po.status === 'issued'
                                });
                            }
                        }
                    }
                }
                } // End status loop
                
                // Strategy 2: search_text (includes all statuses by default)
                var poSearchUrl = 'https://www.zohoapis.com/books/v3/purchaseorders?organization_id=' + orgId + '&search_text=' + encodeURIComponent(poSearchTerm);
                debugInfo.poSearches.push({ term: poSearchTerm, strategy: 'search_text' });
                var poSearchData = await zohoApiCall(poSearchUrl, 'po-search-' + poSearchTerm);
                
                if (poSearchData && poSearchData.purchaseorders && poSearchData.purchaseorders.length > 0) {
                    console.log('Search found', poSearchData.purchaseorders.length, 'purchase orders for', poSearchTerm);
                    
                    for (var pi2 = 0; pi2 < poSearchData.purchaseorders.length; pi2++) {
                        var po2 = poSearchData.purchaseorders[pi2];
                        if (seenIds['po-' + po2.purchaseorder_id]) continue;
                        seenIds['po-' + po2.purchaseorder_id] = true;
                        
                        var poDetailUrl2 = 'https://www.zohoapis.com/books/v3/purchaseorders/' + po2.purchaseorder_id + '?organization_id=' + orgId;
                        var poDetailData2 = await zohoApiCall(poDetailUrl2, 'po-detail2-' + po2.purchaseorder_id);
                        
                        if (poDetailData2 && poDetailData2.purchaseorder && poDetailData2.purchaseorder.line_items) {
                            var poTotalQty2 = 0;
                            var poTotalAmount2 = 0;
                            var poMatchingItems2 = [];
                            var poDetail = poDetailData2.purchaseorder;
                            
                            // Check if style is in custom fields
                            var poCustomMatch = false;
                            var poCustomFields = JSON.stringify(poDetail.custom_fields || []).toUpperCase();
                            if (poCustomFields.indexOf(styleId.toUpperCase()) !== -1 || poCustomFields.indexOf(baseStyle.toUpperCase()) !== -1) {
                                poCustomMatch = true;
                                console.log('PO custom field match for', po2.purchaseorder_number);
                            }
                            
                            for (var pj2 = 0; pj2 < poDetail.line_items.length; pj2++) {
                                var poItem2 = poDetail.line_items[pj2];
                                var poItemName2 = (poItem2.name || poItem2.item_name || poItem2.description || '').toUpperCase();
                                var poItemSku2 = (poItem2.sku || poItem2.item_id || '').toUpperCase();
                                var poSearchStyleUpper2 = styleId.toUpperCase();
                                var poBaseStyleUpper2 = baseStyle.toUpperCase();
                                
                                // Match if item contains style OR if PO custom fields matched (include all items)
                                var itemMatch = poItemName2.indexOf(poSearchStyleUpper2) !== -1 || poItemSku2.indexOf(poSearchStyleUpper2) !== -1 ||
                                    poItemName2.indexOf(poBaseStyleUpper2) !== -1 || poItemSku2.indexOf(poBaseStyleUpper2) !== -1;
                                
                                if (itemMatch || poCustomMatch) {
                                    poTotalQty2 += poItem2.quantity || 0;
                                    poTotalAmount2 += poItem2.item_total || 0;
                                    poMatchingItems2.push({
                                        name: poItem2.name || poItem2.item_name,
                                        quantity: poItem2.quantity,
                                        rate: poItem2.rate,
                                        amount: poItem2.item_total
                                    });
                                }
                            }
                            
                            if (poTotalQty2 > 0) {
                                results.push({
                                    type: 'purchaseorder',
                                    documentNumber: po2.purchaseorder_number,
                                    date: po2.date,
                                    customerName: po2.vendor_name,
                                    status: po2.status,
                                    quantity: poTotalQty2,
                                    amount: poTotalAmount2,
                                    total: po2.total,
                                    items: poMatchingItems2,
                                    isOpen: po2.status === 'open' || po2.status === 'draft' || po2.status === 'issued'
                                });
                            }
                        }
                    }
                }
            } catch (poErr) {
                console.error('Purchase order search error:', poErr.message);
                debugInfo.errors.push({ type: 'purchaseorder', term: poSearchTerm, error: poErr.message });
            }
        }
        
        // Sort by date descending
        results.sort(function(a, b) {
            return new Date(b.date) - new Date(a.date);
        });
        
        // Calculate summary
        var totalInvoicedQty = 0;
        var totalInvoicedDollars = 0;
        var totalOpenOrdersQty = 0;
        var totalOpenOrdersDollars = 0;
        var totalPOQty = 0;
        var totalPODollars = 0;
        var invoiceCount = 0;
        var openOrderCount = 0;
        var poCount = 0;
        
        for (var n = 0; n < results.length; n++) {
            if (results[n].type === 'invoice') {
                totalInvoicedQty += results[n].quantity;
                totalInvoicedDollars += results[n].amount || 0;
                invoiceCount++;
            } else if (results[n].type === 'purchaseorder') {
                totalPOQty += results[n].quantity;
                totalPODollars += results[n].amount || 0;
                poCount++;
            } else if (results[n].isOpen) {
                totalOpenOrdersQty += results[n].quantity;
                totalOpenOrdersDollars += results[n].amount || 0;
                openOrderCount++;
            }
        }
        
        console.log('Sales History Results:', results.length, 'records found');
        
        var summary = {
            totalInvoiced: totalInvoicedQty,
            totalInvoicedDollars: totalInvoicedDollars,
            invoiceCount: invoiceCount,
            totalOpenOrders: totalOpenOrdersQty,
            totalOpenOrdersDollars: totalOpenOrdersDollars,
            openOrderCount: openOrderCount,
            totalPO: totalPOQty,
            totalPODollars: totalPODollars,
            poCount: poCount
        };
        
        // Save to cache
        try {
            await pool.query(
                'INSERT INTO sales_history_cache (base_style, summary, history, updated_at) VALUES ($1, $2, $3, NOW()) ON CONFLICT (base_style) DO UPDATE SET summary = $2, history = $3, updated_at = NOW()',
                [baseStyle, JSON.stringify(summary), JSON.stringify(results)]
            );
            console.log('Sales History cached for', baseStyle);
        } catch (cacheErr) {
            console.error('Cache save error:', cacheErr.message);
        }
        
        res.json({
            success: true,
            styleId: styleId,
            summary: summary,
            history: results,
            cached: false
        });
        
    } catch (err) {
        console.error('Sales history error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

END OF DISABLED API CODE */

// Get cache status
app.get('/api/sales-history-cache/status', requireAuth, async function(req, res) {
    try {
        var totalResult = await pool.query('SELECT COUNT(*) as total FROM sales_history_cache');
        var freshResult = await pool.query('SELECT COUNT(*) as fresh FROM sales_history_cache WHERE updated_at > NOW() - INTERVAL \'1 hour\'');
        var oldestResult = await pool.query('SELECT MIN(updated_at) as oldest FROM sales_history_cache');
        var newestResult = await pool.query('SELECT MAX(updated_at) as newest FROM sales_history_cache');
        
        res.json({
            total: parseInt(totalResult.rows[0].total),
            fresh: parseInt(freshResult.rows[0].fresh),
            stale: parseInt(totalResult.rows[0].total) - parseInt(freshResult.rows[0].fresh),
            oldest: oldestResult.rows[0].oldest,
            newest: newestResult.rows[0].newest
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Clear cache for a style (force refresh next time)
app.delete('/api/sales-history-cache/:styleId', requireAuth, async function(req, res) {
    try {
        var baseStyle = req.params.styleId.split('-')[0];
        await pool.query('DELETE FROM sales_history_cache WHERE base_style = $1', [baseStyle]);
        res.json({ success: true, message: 'Cache cleared for ' + baseStyle });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Clear ALL cache
app.delete('/api/sales-history-cache', requireAuth, async function(req, res) {
    try {
        var result = await pool.query('DELETE FROM sales_history_cache');
        res.json({ success: true, message: 'All cache cleared', deleted: result.rowCount });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

function parseCSVLine(line) { var result = []; var current = ''; var inQuotes = false; for (var i = 0; i < line.length; i++) { var char = line[i]; if (char === '"') { inQuotes = !inQuotes; } else if (char === ',' && !inQuotes) { result.push(current.trim()); current = ''; } else { current += char; } } result.push(current.trim()); return result; }
function parseNumber(val) { if (!val) return 0; return parseInt(val.toString().replace(/,/g, '').replace(/"/g, '').trim()) || 0; }

app.post('/api/import', requireAuth, requireAdmin, upload.single('file'), async function(req, res) {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        
        // Create sync history entry first to get the import ID
        var syncResult = await pool.query('INSERT INTO sync_history (sync_type, status, records_synced) VALUES ($1, $2, $3) RETURNING id', ['csv_import', 'success', 0]);
        var currentImportId = syncResult.rows[0].id;
        
        // Get existing style_ids before import to track new arrivals
        var existingStyles = await pool.query('SELECT DISTINCT style_id FROM products');
        var existingStyleSet = {};
        existingStyles.rows.forEach(function(r) { existingStyleSet[r.style_id] = true; });
        
        var content = req.file.buffer.toString('utf-8'); 
        var allLines = content.split('\n'); 
        var lines = []; 
        for (var i = 0; i < allLines.length; i++) { 
            if (allLines[i].trim()) lines.push(allLines[i]); 
        } 
        if (lines.length < 2) return res.status(400).json({ error: 'File appears empty' });
        
        var headerLine = lines[0]; 
        if (headerLine.charCodeAt(0) === 0xFEFF) headerLine = headerLine.slice(1); 
        var headersRaw = parseCSVLine(headerLine); 
        var headers = []; 
        for (var h = 0; h < headersRaw.length; h++) { 
            headers.push(headersRaw[h].toLowerCase().replace(/[^\w\s]/g, '').trim()); 
        }
        var headerMap = {}; 
        for (var hi = 0; hi < headers.length; hi++) { 
            headerMap[headers[hi]] = hi; 
        }
        
        var imported = 0, skipped = 0, newArrivals = 0; 
        var lastStyleId = null, lastImageUrl = null, lastCategory = null;
        
        for (var li = 1; li < lines.length; li++) { 
            try { 
                var values = parseCSVLine(lines[li]); 
                if (values[0] && values[0].indexOf('Grand Summary') !== -1) { skipped++; continue; } 
                
                var styleId = values[headerMap['style name']] || values[0]; 
                var imageUrl = values[headerMap['style image']] || values[1]; 
                var color = values[headerMap['color']] || values[2]; 
                var category = values[headerMap['commodity']] || values[3]; 
                var onHand = parseNumber(values[headerMap['net on hand']] || values[4]); 
                var availableNow = parseNumber(values[headerMap['available now']] || values[7]); 
                var openOrder = parseNumber(values[headerMap['open order']] || values[8]); 
                var toCome = parseNumber(values[headerMap['to come']] || values[9]); 
                var leftToSell = parseNumber(values[headerMap['left to sell']] || values[10]); 
                
                // Handle rows where style is inherited from previous row
                if (!styleId && color) { 
                    styleId = lastStyleId; 
                    if (!imageUrl || imageUrl === '-No Value-') imageUrl = lastImageUrl; 
                    if (!category || category === '-No Value-') category = lastCategory; 
                } 
                if (!styleId) { skipped++; continue; } 
                
                lastStyleId = styleId; 
                if (imageUrl && imageUrl !== '-No Value-' && imageUrl.indexOf('http') === 0) lastImageUrl = imageUrl; 
                if (category && category !== '-No Value-') lastCategory = category; 
                
                var baseStyle = styleId.split('-')[0]; 
                var validCategory = (category && category !== '-No Value-') ? category : 'Uncategorized'; 
                var name = validCategory + ' - ' + baseStyle; 
                var validImageUrl = (imageUrl && imageUrl !== '-No Value-' && imageUrl.indexOf('http') === 0) ? imageUrl : lastImageUrl; 
                
                var isNewStyle = !existingStyleSet[styleId];
                var productResult = await pool.query('SELECT id, image_url FROM products WHERE style_id = $1', [styleId]); 
                var productId; 
                
                if (productResult.rows.length > 0) { 
                    productId = productResult.rows[0].id; 
                    var finalImage = validImageUrl || productResult.rows[0].image_url; 
                    await pool.query('UPDATE products SET name=$1, category=$2, base_style=$3, image_url=$4, updated_at=CURRENT_TIMESTAMP WHERE id=$5', [name, validCategory, baseStyle, finalImage, productId]); 
                } else { 
                    var ins = await pool.query('INSERT INTO products (style_id, base_style, name, category, image_url, first_seen_import) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id', [styleId, baseStyle, name, validCategory, validImageUrl, currentImportId]); 
                    productId = ins.rows[0].id;
                    if (isNewStyle) newArrivals++;
                    existingStyleSet[styleId] = true;
                } 
                
                if (color && color !== '-No Value-') { 
                    var colorResult = await pool.query('SELECT id FROM product_colors WHERE product_id=$1 AND color_name=$2', [productId, color]); 
                    if (colorResult.rows.length > 0) { 
                        await pool.query('UPDATE product_colors SET available_now=$1, left_to_sell=$2, on_hand=$3, open_order=$4, to_come=$5, available_qty=$6, updated_at=CURRENT_TIMESTAMP WHERE id=$7', 
                            [availableNow, leftToSell, onHand, openOrder, toCome, availableNow, colorResult.rows[0].id]); 
                    } else { 
                        await pool.query('INSERT INTO product_colors (product_id, color_name, available_now, left_to_sell, on_hand, open_order, to_come, available_qty) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', 
                            [productId, color, availableNow, leftToSell, onHand, openOrder, toCome, availableNow]); 
                    } 
                } 
                imported++; 
            } catch (rowErr) { 
                console.error('Row error:', rowErr.message);
                skipped++; 
            } 
        }
        
        // Update sync history with actual count
        await pool.query('UPDATE sync_history SET records_synced = $1 WHERE id = $2', [imported, currentImportId]);
        lastImportId = currentImportId;
        
        res.json({ success: true, imported: imported, skipped: skipped, newArrivals: newArrivals });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/products/clear', requireAuth, requireAdmin, async function(req, res) { try { await pool.query('DELETE FROM product_colors'); await pool.query('DELETE FROM products'); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); } });

// Import Sales Data CSV (PO-SO Query)
app.post('/api/import-sales', requireAuth, requireAdmin, upload.single('file'), async function(req, res) {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        
        var content = req.file.buffer.toString('utf-8');
        // Remove BOM if present
        if (content.charCodeAt(0) === 0xFEFF) content = content.slice(1);
        
        var lines = content.split('\n').filter(function(line) { return line.trim(); });
        if (lines.length < 2) return res.json({ success: false, error: 'CSV file is empty' });
        
        // Parse header
        var headerLine = lines[0];
        var headers = [];
        var inQuote = false;
        var current = '';
        for (var i = 0; i < headerLine.length; i++) {
            var char = headerLine[i];
            if (char === '"') { inQuote = !inQuote; }
            else if (char === ',' && !inQuote) { headers.push(current.trim().toLowerCase().replace(/\s+/g, '_')); current = ''; }
            else { current += char; }
        }
        headers.push(current.trim().toLowerCase().replace(/\s+/g, '_'));
        
        console.log('Sales CSV Headers:', headers);
        
        // Find column indices
        var colMap = {};
        for (var h = 0; h < headers.length; h++) { colMap[headers[h]] = h; }
        
        // Required columns
        var docTypeIdx = colMap['document_type'];
        var docNumIdx = colMap['document_number'];
        var dateIdx = colMap['date'];
        var custIdx = colMap['customer_vendor'];
        var skuIdx = colMap['line_item_sku'];
        var styleIdx = colMap['line_item_style'];
        var statusIdx = colMap['status'];
        var qtyIdx = colMap['quantity'];
        var amtIdx = colMap['amount'];
        
        if (docTypeIdx === undefined || docNumIdx === undefined) {
            return res.json({ success: false, error: 'Missing required columns: document_type, document_number' });
        }
        
        // Clear existing sales data
        await pool.query('DELETE FROM sales_data');
        
        var imported = 0;
        var errors = 0;
        var batchSize = 500;
        var batch = [];
        
        for (var r = 1; r < lines.length; r++) {
            try {
                // Parse CSV row
                var row = [];
                var inQuote2 = false;
                var cell = '';
                var line = lines[r];
                for (var c = 0; c < line.length; c++) {
                    var ch = line[c];
                    if (ch === '"') { inQuote2 = !inQuote2; }
                    else if (ch === ',' && !inQuote2) { row.push(cell.trim()); cell = ''; }
                    else { cell += ch; }
                }
                row.push(cell.trim());
                
                var docType = row[docTypeIdx] || '';
                var docNum = row[docNumIdx] || '';
                var docDate = row[dateIdx] || null;
                var customer = row[custIdx] || '';
                var sku = skuIdx !== undefined ? row[skuIdx] || '' : '';
                var style = styleIdx !== undefined ? row[styleIdx] || '' : '';
                var status = statusIdx !== undefined ? row[statusIdx] || '' : '';
                var qty = qtyIdx !== undefined ? parseFloat((row[qtyIdx] || '0').replace(/,/g, '')) || 0 : 0;
                var amt = amtIdx !== undefined ? parseFloat((row[amtIdx] || '0').replace(/,/g, '')) || 0 : 0;
                
                // Extract base style (e.g., "80414J-AA" -> "80414J")
                var baseStyle = style ? style.split('-')[0] : (sku ? sku.split('-')[0] : '');
                
                if (docType && docNum && baseStyle) {
                    batch.push([docType, docNum, docDate, customer, sku, baseStyle, status, qty, amt]);
                    
                    if (batch.length >= batchSize) {
                        // Batch insert
                        var values = [];
                        var placeholders = [];
                        var paramIdx = 1;
                        for (var b = 0; b < batch.length; b++) {
                            var item = batch[b];
                            placeholders.push('($' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ')');
                            values = values.concat(item);
                        }
                        await pool.query('INSERT INTO sales_data (document_type, document_number, doc_date, customer_vendor, line_item_sku, base_style, status, quantity, amount) VALUES ' + placeholders.join(','), values);
                        imported += batch.length;
                        batch = [];
                    }
                }
            } catch (rowErr) {
                errors++;
                if (errors < 5) console.log('Row error:', rowErr.message);
            }
        }
        
        // Insert remaining batch
        if (batch.length > 0) {
            var values = [];
            var placeholders = [];
            var paramIdx = 1;
            for (var b = 0; b < batch.length; b++) {
                var item = batch[b];
                placeholders.push('($' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ')');
                values = values.concat(item);
            }
            await pool.query('INSERT INTO sales_data (document_type, document_number, doc_date, customer_vendor, line_item_sku, base_style, status, quantity, amount) VALUES ' + placeholders.join(','), values);
            imported += batch.length;
        }
        
        // Log to sync history
        await pool.query('INSERT INTO sync_history (sync_type, status, records_synced) VALUES ($1, $2, $3)', ['sales_import', 'success', imported]);
        
        console.log('Sales data import complete:', imported, 'records imported,', errors, 'errors');
        res.json({ success: true, imported: imported, errors: errors });
    } catch (err) {
        console.error('Sales import error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users', requireAuth, requireAdmin, async function(req, res) { try { var result = await pool.query('SELECT id, username, role, created_at FROM users ORDER BY created_at'); res.json(result.rows); } catch (err) { res.status(500).json({ error: err.message }); } });

// Sales data stats
app.get('/api/sales-stats', requireAuth, async function(req, res) {
    try {
        var totalResult = await pool.query('SELECT COUNT(*) as count FROM sales_data');
        var soResult = await pool.query("SELECT COUNT(*) as count FROM sales_data WHERE document_type = 'Sales Order'");
        var poResult = await pool.query("SELECT COUNT(*) as count FROM sales_data WHERE document_type = 'Purchase Order'");
        var stylesResult = await pool.query('SELECT COUNT(DISTINCT base_style) as count FROM sales_data');
        
        res.json({
            success: true,
            totalRecords: parseInt(totalResult.rows[0].count),
            salesOrders: parseInt(soResult.rows[0].count),
            purchaseOrders: parseInt(poResult.rows[0].count),
            uniqueStyles: parseInt(stylesResult.rows[0].count)
        });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});
app.post('/api/users', requireAuth, requireAdmin, async function(req, res) { try { var hash = await bcrypt.hash(req.body.password, 10); await pool.query('INSERT INTO users (username, password, role) VALUES ($1,$2,$3)', [req.body.username, hash, req.body.role || 'sales_rep']); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete('/api/users/:id', requireAuth, requireAdmin, async function(req, res) { try { await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); } });

// Create shareable selection
app.post('/api/selections', requireAuth, async function(req, res) {
    try {
        var productIds = req.body.productIds;
        var name = req.body.name || 'Selection';
        var shareType = req.body.shareType || 'link';
        if (!productIds || productIds.length === 0) return res.json({ success: false, error: 'No products selected' });
        var shareId = Math.random().toString(36).substring(2, 10) + Date.now().toString(36);
        await pool.query('INSERT INTO selections (share_id, name, product_ids, created_by, share_type) VALUES ($1, $2, $3, $4, $5)', [shareId, name, productIds, req.session.username || 'anonymous', shareType]);
        res.json({ success: true, shareId: shareId, url: '/share/' + shareId });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get all selections (sharing history)
app.get('/api/selections', requireAuth, async function(req, res) {
    try {
        var result = await pool.query('SELECT share_id, name, product_ids, created_by, share_type, created_at FROM selections ORDER BY created_at DESC LIMIT 100');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get selection by share ID (public)
app.get('/api/selections/:shareId', async function(req, res) {
    try {
        var result = await pool.query('SELECT * FROM selections WHERE share_id = $1', [req.params.shareId]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Selection not found' });
        var selection = result.rows[0];
        var productsResult = await pool.query('SELECT p.id, p.style_id, p.name, p.category, p.image_url, json_agg(json_build_object(\'color_name\', pc.color_name, \'available_qty\', pc.available_qty)) FILTER (WHERE pc.id IS NOT NULL) as colors FROM products p LEFT JOIN product_colors pc ON p.id = pc.product_id WHERE p.id = ANY($1) GROUP BY p.id', [selection.product_ids]);
        res.json({ selection: selection, products: productsResult.rows });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/image/:fileId', async function(req, res) {
    var retryCount = 0;
    async function fetchImage() {
        try {
            var fileId = req.params.fileId;
            if (!zohoAccessToken) { var tokenResult = await refreshZohoToken(); if (!tokenResult.success) { return res.status(401).send('No valid token'); } }
            var imageUrl = 'https://workdrive.zoho.com/api/v1/download/' + fileId;
            var response = await fetch(imageUrl, { headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken, 'Accept': 'application/vnd.api+json' } });
            if (response.status === 401) { if (retryCount === 0) { retryCount++; await refreshZohoToken(); return fetchImage(); } return res.status(401).send('Auth failed'); }
            if (!response.ok) { return res.status(response.status).send('Image not found'); }
            res.setHeader('Content-Type', response.headers.get('content-type') || 'image/jpeg');
            res.setHeader('Cache-Control', 'public, max-age=86400');
            res.send(Buffer.from(await response.arrayBuffer()));
        } catch (err) { res.status(500).send('Error'); }
    }
    fetchImage();
});

// Share page (public - no auth)
app.get('/share/:shareId', async function(req, res) { res.send(getShareHTML(req.params.shareId)); });

// PDF generation - also record as a share
app.get('/api/selections/:shareId/pdf', async function(req, res) {
    try {
        var result = await pool.query('SELECT * FROM selections WHERE share_id = $1', [req.params.shareId]);
        if (result.rows.length === 0) return res.status(404).send('Not found');
        var selection = result.rows[0];
        var productsResult = await pool.query('SELECT p.id, p.style_id, p.name, p.category, p.image_url, json_agg(json_build_object(\'color_name\', pc.color_name, \'available_qty\', pc.available_qty)) FILTER (WHERE pc.id IS NOT NULL) as colors FROM products p LEFT JOIN product_colors pc ON p.id = pc.product_id WHERE p.id = ANY($1) GROUP BY p.id ORDER BY p.name', [selection.product_ids]);
        res.send(getPDFHTML(selection, productsResult.rows));
    } catch (err) { res.status(500).send('Error generating PDF view'); }
});

// Record PDF download separately
app.post('/api/selections/:shareId/record-pdf', requireAuth, async function(req, res) {
    try {
        var result = await pool.query('SELECT * FROM selections WHERE share_id = $1', [req.params.shareId]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
        var selection = result.rows[0];
        var shareId = Math.random().toString(36).substring(2, 10) + Date.now().toString(36);
        await pool.query('INSERT INTO selections (share_id, name, product_ids, created_by, share_type) VALUES ($1, $2, $3, $4, $5)', 
            [shareId, selection.name + ' (PDF)', selection.product_ids, req.session.username || 'anonymous', 'pdf']);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// System Health API endpoint
app.get('/api/system-health', requireAuth, requireAdmin, async function(req, res) {
    try {
        // Database stats
        var dbStats = {};
        
        // Table row counts
        var tables = ['products', 'product_colors', 'users', 'user_picks', 'user_notes', 'selections', 'sync_history', 'sales_history_cache'];
        for (var i = 0; i < tables.length; i++) {
            var t = tables[i];
            try {
                var result = await pool.query('SELECT COUNT(*) as count FROM ' + t);
                dbStats[t] = parseInt(result.rows[0].count);
            } catch (e) {
                dbStats[t] = 'N/A';
            }
        }
        
        // Database size (PostgreSQL)
        var dbSizeResult = await pool.query("SELECT pg_size_pretty(pg_database_size(current_database())) as size");
        dbStats.totalSize = dbSizeResult.rows[0].size;
        
        // Products with AI tags
        var aiTagsResult = await pool.query("SELECT COUNT(*) as count FROM products WHERE ai_tags IS NOT NULL AND ai_tags != ''");
        var aiTagsCount = parseInt(aiTagsResult.rows[0].count);
        
        // Recent activity
        var recentShares = await pool.query("SELECT COUNT(*) as count FROM selections WHERE created_at > NOW() - INTERVAL '7 days'");
        var recentSyncs = await pool.query("SELECT COUNT(*) as count FROM sync_history WHERE created_at > NOW() - INTERVAL '7 days'");
        
        // Last sync info
        var lastSync = await pool.query("SELECT * FROM sync_history WHERE status = 'success' ORDER BY created_at DESC LIMIT 1");
        
        // Active sessions (approximate - count distinct users with picks)
        var activeUserCount = 0;
        try {
            var recentActivity = await pool.query("SELECT COUNT(DISTINCT user_id) as users FROM user_picks");
            activeUserCount = parseInt(recentActivity.rows[0].users) || 0;
        } catch (e) {
            console.log('Could not count active users:', e.message);
        }
        
        // Memory usage (Node.js)
        var memUsage = process.memoryUsage();
        
        // Uptime
        var uptime = process.uptime();
        var uptimeStr = Math.floor(uptime / 86400) + 'd ' + Math.floor((uptime % 86400) / 3600) + 'h ' + Math.floor((uptime % 3600) / 60) + 'm';
        
        res.json({
            success: true,
            database: {
                tables: dbStats,
                totalSize: dbStats.totalSize,
                productsWithAI: aiTagsCount,
                productsWithoutAI: dbStats.products - aiTagsCount
            },
            activity: {
                sharesLast7Days: parseInt(recentShares.rows[0].count),
                syncsLast7Days: parseInt(recentSyncs.rows[0].count),
                lastSuccessfulSync: lastSync.rows[0] ? lastSync.rows[0].created_at : null,
                lastSyncRecords: lastSync.rows[0] ? lastSync.rows[0].records_updated : null,
                activeUsers: activeUserCount
            },
            server: {
                uptime: uptimeStr,
                uptimeSeconds: Math.floor(uptime),
                memoryUsed: Math.round(memUsage.heapUsed / 1024 / 1024) + ' MB',
                memoryTotal: Math.round(memUsage.heapTotal / 1024 / 1024) + ' MB',
                nodeVersion: process.version,
                platform: process.platform
            },
            apiStatus: {
                anthropicConfigured: !!process.env.ANTHROPIC_API_KEY,
                zohoConfigured: !!(process.env.ZOHO_CLIENT_ID && process.env.ZOHO_REFRESH_TOKEN),
                zohoConnected: !!zohoAccessToken
            },
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('System health error:', err);
        res.json({ success: false, error: err.message });
    }
});

// Chat API endpoint - AI-powered product assistant
app.post('/api/chat', requireAuth, async function(req, res) {
    try {
        var userMessage = req.body.message;
        var context = req.body.context || {};
        
        if (!process.env.ANTHROPIC_API_KEY) {
            return res.json({ success: false, error: 'AI not configured' });
        }
        
        // Get inventory summary for context
        var categoriesResult = await pool.query('SELECT DISTINCT category FROM products ORDER BY category');
        var categories = categoriesResult.rows.map(function(r) { return r.category; });
        
        var colorsResult = await pool.query('SELECT DISTINCT color_name FROM product_colors ORDER BY color_name');
        var colors = colorsResult.rows.map(function(r) { return r.color_name; });
        
        var statsResult = await pool.query(`
            SELECT 
                COUNT(DISTINCT p.id) as total_styles,
                COUNT(DISTINCT p.base_style) as total_groups,
                COALESCE(SUM(pc.available_now), 0) as total_available_now,
                COALESCE(SUM(pc.left_to_sell), 0) as total_left_to_sell
            FROM products p
            LEFT JOIN product_colors pc ON p.id = pc.product_id
        `);
        var stats = statsResult.rows[0];
        
        var systemPrompt = `You are a helpful assistant for the Mark Edwards Apparel Product Catalog. You help sales reps find products and answer inventory questions.

AVAILABLE DATA:
- Categories: ${categories.join(', ')}
- Colors available: ${colors.slice(0, 30).join(', ')}${colors.length > 30 ? '... and more' : ''}
- Total styles: ${stats.total_styles}
- Total groups (base styles): ${stats.total_groups}
- Total Available Now: ${parseInt(stats.total_available_now).toLocaleString()} units
- Total Left to Sell: ${parseInt(stats.total_left_to_sell).toLocaleString()} units

ACTIONS YOU CAN TRIGGER:
You can respond with JSON actions that the app will execute. Include an "actions" array in your response.

Available actions:
1. {"action": "search", "value": "search terms"} - Search for products
2. {"action": "setCategory", "value": "category name"} - Filter by category (use exact category name from list above, or "all")
3. {"action": "setColor", "value": "color name"} - Filter by color
4. {"action": "setMinQty", "value": number} - Set minimum quantity filter
5. {"action": "setMaxQty", "value": number} - Set maximum quantity filter
6. {"action": "setMinColors", "value": number} - Set minimum number of color options filter
7. {"action": "clearFilters"} - Clear all filters
8. {"action": "setSort", "value": "qty-high" | "qty-low" | "name-asc" | "name-desc" | "newest"} - Sort products
9. {"action": "showNewArrivals"} - Show new arrivals filter
10. {"action": "showPicks"} - Show user's picks

RESPONSE FORMAT:
Always respond with valid JSON in this format:
{
  "message": "Your friendly response to the user",
  "actions": [{"action": "...", "value": "..."}]
}

Keep messages concise and helpful. If you're applying filters, briefly confirm what you're showing.

EXAMPLES:
User: "Do we have any navy sweaters?"
Response: {"message": "Let me search for navy sweaters for you!", "actions": [{"action": "setCategory", "value": "Sweater"}, {"action": "search", "value": "navy"}]}

User: "Show me joggers with more than 1000 units"
Response: {"message": "Here are joggers with over 1,000 units available:", "actions": [{"action": "setCategory", "value": "Jogger"}, {"action": "setMinQty", "value": 1000}]}

User: "Joggers with more than 2 color options"
Response: {"message": "Here are joggers available in 3 or more colors:", "actions": [{"action": "setCategory", "value": "Jogger"}, {"action": "setMinColors", "value": 3}]}

User: "What categories do we have?"
Response: {"message": "We have these categories: ${categories.join(', ')}. Which would you like to explore?", "actions": []}

User: "Clear everything and start fresh"
Response: {"message": "All filters cleared! Showing all products.", "actions": [{"action": "clearFilters"}]}`;

        var response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': process.env.ANTHROPIC_API_KEY,
                'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
                model: 'claude-sonnet-4-20250514',
                max_tokens: 500,
                system: systemPrompt,
                messages: [{ role: 'user', content: userMessage }]
            })
        });
        
        var data = await response.json();
        
        if (data.content && data.content[0] && data.content[0].text) {
            var aiResponse = data.content[0].text;
            
            // Try to parse as JSON
            try {
                var parsed = JSON.parse(aiResponse);
                return res.json({ 
                    success: true, 
                    message: parsed.message || aiResponse,
                    actions: parsed.actions || []
                });
            } catch (e) {
                // If not valid JSON, return as plain message
                return res.json({ 
                    success: true, 
                    message: aiResponse,
                    actions: []
                });
            }
        } else {
            return res.json({ success: false, error: 'No response from AI' });
        }
    } catch (err) {
        console.error('Chat error:', err);
        res.json({ success: false, error: err.message });
    }
});

// Catch-all routes - MUST BE LAST
app.get('/', function(req, res) { res.send(getHTML()); });
app.get('*', function(req, res) { res.send(getHTML()); });

function getShareHTML(shareId) {
    return '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Product Selection - Mark Edwards Apparel</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#f5f5f5;padding:2rem}.header{text-align:center;margin-bottom:2rem}.header h1{font-size:1.5rem;color:#333}.header p{color:#666;margin-top:0.5rem}.product-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:1.5rem;max-width:1200px;margin:0 auto}.product-card{background:white;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)}.product-image{height:200px;background:#f8f8f8;display:flex;align-items:center;justify-content:center}.product-image img{max-width:100%;max-height:100%;object-fit:contain}.product-info{padding:1rem}.product-name{font-size:1.1rem;font-weight:600;margin-bottom:0.5rem}.product-style{font-size:0.75rem;color:#666;margin-bottom:0.75rem}.color-row{display:flex;justify-content:space-between;padding:0.25rem 0;font-size:0.875rem}.total-row{margin-top:0.5rem;padding-top:0.5rem;border-top:1px solid #eee;font-weight:bold;display:flex;justify-content:space-between}.actions{text-align:center;margin-top:2rem}.btn{padding:0.75rem 2rem;border:none;border-radius:4px;cursor:pointer;font-size:1rem;text-decoration:none;display:inline-block;margin:0.5rem}.btn-primary{background:#2c5545;color:white}.loading{text-align:center;padding:3rem;color:#666}</style></head><body><div class="header"><h1 id="selectionName">Product Selection</h1><p id="selectionInfo"></p></div><div class="product-grid" id="productGrid"><div class="loading">Loading products...</div></div><div class="actions"><a class="btn btn-primary" id="pdfBtn" href="/api/selections/' + shareId + '/pdf" target="_blank">Download / Print PDF</a></div><script>fetch("/api/selections/' + shareId + '").then(function(r){return r.json()}).then(function(d){if(d.error){document.getElementById("productGrid").innerHTML="<p>Selection not found</p>";return}document.getElementById("selectionName").textContent=d.selection.name||"Product Selection";document.getElementById("selectionInfo").textContent="Created "+new Date(d.selection.created_at).toLocaleDateString()+" • "+d.products.length+" items";var h="";for(var i=0;i<d.products.length;i++){var p=d.products[i];var cols=p.colors||[];var tot=0;for(var c=0;c<cols.length;c++)tot+=cols[c].available_qty||0;var ch="";for(var j=0;j<cols.length;j++){ch+="<div class=\\"color-row\\"><span>"+cols[j].color_name+"</span><span>"+(cols[j].available_qty||0).toLocaleString()+"</span></div>"}var imgUrl=p.image_url;if(imgUrl&&imgUrl.indexOf("download-accl.zoho.com")!==-1){var parts=imgUrl.split("/");imgUrl="/api/image/"+parts[parts.length-1]}var im=imgUrl?"<img src=\\""+imgUrl+"\\" onerror=\\"this.parentElement.innerHTML=\'No Image\'\\">":"No Image";h+="<div class=\\"product-card\\"><div class=\\"product-image\\">"+im+"</div><div class=\\"product-info\\"><div class=\\"product-name\\">"+p.name+"</div><div class=\\"product-style\\">"+p.style_id+"</div>"+ch+"<div class=\\"total-row\\"><span>Total Available</span><span>"+tot.toLocaleString()+"</span></div></div></div>"}document.getElementById("productGrid").innerHTML=h}).catch(function(e){document.getElementById("productGrid").innerHTML="<p>Error loading selection</p>"});</script></body></html>';
}

function getPDFHTML(selection, products) {
    var html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>' + (selection.name || 'Product Selection') + ' - Mark Edwards Apparel</title><style>@media print{@page{margin:0.5in;size:letter}body{-webkit-print-color-adjust:exact;print-color-adjust:exact}}*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial,sans-serif;padding:20px;background:white}.header{text-align:center;margin-bottom:30px;padding-bottom:20px;border-bottom:2px solid #333}.header h1{font-size:24px;margin-bottom:5px}.header p{color:#666}.product-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:24px}.product-card{border:1px solid #ddd;border-radius:8px;overflow:hidden;page-break-inside:avoid}.product-image{height:320px;background:#f5f5f5;display:flex;align-items:center;justify-content:center;padding:10px}.product-image img{max-width:100%;max-height:100%;object-fit:contain}.product-info{padding:16px}.product-name{font-size:16px;font-weight:bold;margin-bottom:4px}.product-style{font-size:12px;color:#666;margin-bottom:10px}.color-row{display:flex;justify-content:space-between;font-size:12px;padding:3px 0}.total-row{margin-top:10px;padding-top:10px;border-top:1px solid #eee;font-weight:bold;display:flex;justify-content:space-between;font-size:14px}.footer{margin-top:30px;text-align:center;color:#666;font-size:12px}.print-btn{position:fixed;top:20px;right:20px;padding:10px 20px;background:#2c5545;color:white;border:none;border-radius:4px;cursor:pointer;font-size:14px}@media print{.print-btn{display:none}}</style></head><body>';
    html += '<button class="print-btn" onclick="window.print()">Print / Save PDF</button>';
    html += '<div class="header"><h1>' + (selection.name || 'Product Selection') + '</h1><p>Mark Edwards Apparel • Generated ' + new Date().toLocaleDateString() + ' • ' + products.length + ' items</p></div>';
    html += '<div class="product-grid">';
    for (var i = 0; i < products.length; i++) {
        var p = products[i];
        var cols = p.colors || [];
        var tot = 0;
        for (var c = 0; c < cols.length; c++) tot += cols[c].available_qty || 0;
        var colHtml = '';
        for (var j = 0; j < cols.length; j++) {
            colHtml += '<div class="color-row"><span>' + cols[j].color_name + '</span><span>' + (cols[j].available_qty || 0).toLocaleString() + '</span></div>';
        }
        var imgUrl = p.image_url;
        if (imgUrl && imgUrl.indexOf('download-accl.zoho.com') !== -1) {
            var parts = imgUrl.split('/');
            imgUrl = '/api/image/' + parts[parts.length - 1];
        }
        var imgHtml = imgUrl ? '<img src="' + imgUrl + '" onerror="this.parentElement.innerHTML=\'No Image\'">' : 'No Image';
        html += '<div class="product-card"><div class="product-image">' + imgHtml + '</div><div class="product-info"><div class="product-name">' + p.name + '</div><div class="product-style">' + p.style_id + '</div>' + colHtml + '<div class="total-row"><span>Total Available</span><span>' + tot.toLocaleString() + '</span></div></div></div>';
    }
    html += '</div><div class="footer">Mark Edwards Apparel • Product availability subject to change</div></body></html>';
    return html;
}

function getHTML() {
    var html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Mark Edwards Apparel - Product Catalog</title><style>';
    html += '*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#f5f5f5}';
    html += '.login-page{min-height:100vh;display:flex;align-items:center;justify-content:center}.login-box{background:white;padding:2rem;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:100%;max-width:360px}.login-box h1{margin-bottom:1.5rem;font-size:1.5rem;text-align:center}';
    html += '.form-group{margin-bottom:1rem}.form-group label{display:block;margin-bottom:0.5rem;font-weight:500}.form-group input{width:100%;padding:0.75rem;border:1px solid #ddd;border-radius:4px;font-size:1rem}';
    html += '.btn{padding:0.75rem 1.5rem;border:none;border-radius:4px;cursor:pointer;font-size:1rem}.btn-primary{background:#2c5545;color:white}.btn-secondary{background:#eee;color:#333}.btn-danger{background:#c4553d;color:white}.btn-success{background:#2e7d32;color:white}';
    html += '.error{color:#c4553d;margin-top:1rem;text-align:center}.success{color:#2e7d32}.hidden{display:none!important}';
    html += '.header{background:white;padding:0.75rem 2rem;border-bottom:1px solid #ddd;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.75rem;position:sticky;top:0;z-index:100;transition:all 0.3s ease}.header.compact{padding:0.5rem 2rem;box-shadow:0 2px 8px rgba(0,0,0,0.1)}.header.compact h1{font-size:0.95rem}.header h1{font-size:1.1rem;transition:font-size 0.3s;white-space:nowrap}.header-right{display:flex;gap:0.75rem;align-items:center}';
    html += '.search-box{position:relative}.search-box input{padding:0.5rem 1rem;border:1px solid #ddd;border-radius:4px;width:250px}';
    html += '.ai-search-indicator{position:absolute;top:100%;left:0;font-size:0.7rem;color:#059669;margin-top:0.2rem;white-space:nowrap}.ai-search-indicator.hidden{display:none}';
    html += '.main{max-width:1400px;margin:0 auto;padding:2rem}';
    html += '.admin-panel{background:white;padding:1.5rem;border-radius:8px;margin-bottom:2rem}.admin-panel h2{margin-bottom:1rem}';
    html += '.tabs{display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap}.tab{padding:0.5rem 1rem;border:none;background:#eee;cursor:pointer;border-radius:4px}.tab.active{background:#2c5545;color:white}.tab-content{display:none}.tab-content.active{display:block}';
    html += '.upload-area{border:2px dashed #ddd;padding:2rem;text-align:center;border-radius:4px;margin-bottom:1rem}.upload-area input{display:none}.upload-area label{color:#2c5545;cursor:pointer}';
    html += '.stats{display:flex;gap:2rem;margin-bottom:0;padding:1rem;background:white;border-radius:0;align-items:center;flex-wrap:wrap;position:sticky;top:52px;z-index:90;border-bottom:1px solid #eee;transition:all 0.3s ease}.stats.compact{padding:0.5rem 1rem;gap:1rem;top:42px}.stats.compact .stat-value{font-size:1.1rem}.stats.compact .stat-label{font-size:0.7rem}.stat-value{font-size:1.5rem;font-weight:bold;transition:font-size 0.3s}.stat-label{color:#666;font-size:0.875rem;transition:font-size 0.3s}.stat-box{padding:0.5rem 1rem;border-radius:8px;transition:all 0.2s ease}.stat-box.stat-active{background:#e8f5e9;border:2px solid #4CAF50}.stat-box.stat-active .stat-value{color:#2e7d32;font-weight:800}.stat-box:not(.stat-active){opacity:0.6}.feature-toggle.active-indicator{background:#e3f2fd;border-radius:4px;padding:0.25rem 0.5rem}';
    html += '.qty-toggle{display:flex;background:#e0e0e0;border-radius:6px;padding:3px;margin-left:auto}.qty-toggle-btn{padding:0.5rem 1rem;border:none;background:transparent;cursor:pointer;font-size:0.875rem;font-weight:500;border-radius:4px;transition:all 0.2s;color:#666}.qty-toggle-btn.active{background:#2c5545;color:white;box-shadow:0 2px 4px rgba(0,0,0,0.15)}.qty-toggle-btn:hover:not(.active){background:#d0d0d0}';
    html += '.filters{display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap;align-items:center}.filter-btn{padding:0.5rem 1rem;border:1px solid #ddd;background:white;border-radius:20px;cursor:pointer}.filter-btn.active{background:#2c5545;color:white;border-color:#2c5545}';
    html += '.color-dropdown{position:absolute;top:100%;left:0;background:white;border:1px solid #ddd;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.15);padding:0.5rem;z-index:100;max-height:300px;overflow-y:auto;min-width:200px}.color-dropdown.hidden{display:none}.color-option{display:block;padding:0.5rem 1rem;cursor:pointer;border-radius:4px;font-size:0.875rem}.color-option:hover{background:#f5f5f5}.color-option.active{background:#2c5545;color:white}';
    html += '.product-grid{display:grid;gap:1.5rem}.product-grid.size-small{grid-template-columns:repeat(auto-fill,minmax(200px,1fr))}.product-grid.size-medium{grid-template-columns:repeat(auto-fill,minmax(300px,1fr))}.product-grid.size-large{grid-template-columns:repeat(auto-fill,minmax(400px,1fr))}.product-grid.size-list{display:flex;flex-direction:column;gap:0.5rem}';
    html += '.product-card.list-view{display:flex;flex-direction:row;height:auto}.product-card.list-view .product-image{width:80px;height:80px;min-height:80px}.product-card.list-view .product-info{flex:1;padding:0.75rem;display:flex;align-items:center;gap:1rem}.product-card.list-view .product-name{margin:0}.product-card.list-view .product-style{margin:0}.product-card.list-view .color-list{display:none}.product-card.list-view .total-row{margin:0;padding:0;border:none}.product-card.list-view .list-colors{display:flex;gap:0.5rem;flex-wrap:wrap;font-size:0.8rem;color:#666}';
    html += '.product-card{background:white;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);cursor:pointer;transition:transform 0.2s;position:relative}.product-card:hover{transform:translateY(-2px);box-shadow:0 4px 16px rgba(0,0,0,0.15)}';
    html += '.product-card.selected{outline:3px solid #2c5545;outline-offset:-3px}';
    html += '.product-card.selection-mode:hover{outline:2px dashed #2c5545;outline-offset:-2px}';
    html += '.product-card.focused{outline:2px solid #1976d2;outline-offset:2px}';
    html += '.select-badge{position:absolute;top:10px;right:10px;width:28px;height:28px;background:#2c5545;color:white;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px;opacity:0;transition:opacity 0.2s;z-index:5}.product-card.selection-mode:hover .select-badge{opacity:0.7}.product-card.selected .select-badge{opacity:1}';
    html += '.pick-badge{position:absolute;top:10px;left:10px;width:28px;height:28px;background:#ff9800;color:white;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:16px;cursor:pointer;opacity:0;transition:opacity 0.2s;z-index:5}.product-card:hover .pick-badge{opacity:0.7}.product-card .pick-badge.active{opacity:1}';
    html += '.note-badge{position:absolute;top:10px;left:44px;width:28px;height:28px;background:#2196f3;color:white;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;z-index:5;opacity:0}.product-card .note-badge.has-note{opacity:1}';
    html += '.color-count-badge{position:absolute;top:10px;right:10px;background:#2c5545;color:white;padding:0.25rem 0.6rem;border-radius:12px;font-size:0.75rem;font-weight:500;z-index:5}';
    html += '.product-card.grouped{border:2px solid #e0e0e0}.product-card.grouped:hover{border-color:#2c5545}';
    html += '.product-image{height:220px;background:#f8f8f8;display:flex;align-items:center;justify-content:center;overflow:hidden}.product-image img{max-width:100%;max-height:100%;object-fit:contain}';
    html += '.product-info{padding:1rem}.product-style{font-size:0.75rem;color:#666;text-transform:uppercase}.product-name{font-size:1.1rem;font-weight:600;margin:0.25rem 0}.color-list{margin-top:0.75rem}.color-row{display:flex;justify-content:space-between;padding:0.25rem 0;font-size:0.875rem}.total-row{margin-top:0.5rem;padding-top:0.5rem;border-top:1px solid #eee;font-weight:bold;display:flex;justify-content:space-between}';
    html += '.empty{text-align:center;padding:3rem;color:#666}';
    html += '.modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:none;align-items:center;justify-content:center;z-index:1000}.modal.active{display:flex}.modal-content{background:white;border-radius:8px;max-width:98vw;width:1600px;max-height:98vh;overflow:auto;position:relative}.modal-body{display:flex;min-height:850px}.modal-image{width:60%;background:#f0f0f0;min-height:850px;display:flex;align-items:center;justify-content:center;padding:2rem}.modal-image img{max-width:100%;max-height:900px;object-fit:contain}.modal-details{width:40%;padding:2rem;overflow-y:auto;max-height:850px}.modal-close{position:absolute;top:1rem;right:1rem;background:white;border:none;font-size:1.5rem;cursor:pointer;border-radius:50%;width:36px;height:36px;z-index:10}';
    html += '.modal-actions{margin-top:1.5rem;padding-top:1rem;border-top:1px solid #eee;display:flex;gap:0.5rem;flex-wrap:wrap}';
    html += '.note-section{margin-top:1rem;padding-top:1rem;border-top:1px solid #eee}.note-section textarea{width:100%;height:80px;margin-top:0.5rem;padding:0.5rem;border:1px solid #ddd;border-radius:4px;font-family:inherit;resize:vertical}';
    html += '.selection-bar{position:fixed;bottom:0;left:0;right:0;background:#2e7d32;color:white;padding:0.75rem 2rem;display:flex;justify-content:space-between;align-items:center;z-index:100;transform:translateY(100%);transition:transform 0.3s}.selection-bar.visible{transform:translateY(0)}';
    
    // Help modal styles
    html += '.help-modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:none;align-items:center;justify-content:center;z-index:1002;overflow-y:auto;padding:2rem}.help-modal.active{display:flex}.help-content{background:white;border-radius:12px;max-width:900px;width:95%;max-height:90vh;overflow-y:auto;padding:2rem;position:relative}';
    html += '.help-content h2{margin-bottom:1.5rem;color:#2c5545}.help-sections{display:flex;flex-direction:column;gap:2rem}';
    html += '.help-section{border-bottom:1px solid #eee;padding-bottom:1.5rem}.help-section:last-child{border-bottom:none}.help-section h3{color:#333;margin-bottom:1rem;font-size:1.1rem}';
    html += '.help-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem}.help-card{background:#f8f9fa;border-radius:8px;padding:1.25rem;text-align:center}.help-icon{font-size:2rem;margin-bottom:0.5rem}.help-card h4{margin-bottom:0.5rem;color:#2c5545}.help-card p{font-size:0.875rem;color:#666;margin:0}';
    html += '.help-table{width:100%;border-collapse:collapse}.help-table td{padding:0.75rem;border-bottom:1px solid #eee;vertical-align:top}.help-table tr:last-child td{border-bottom:none}.help-feature{width:180px;white-space:nowrap}';
    html += '.help-steps{display:flex;flex-direction:column;gap:1rem}.help-step{display:flex;align-items:flex-start;gap:1rem}.step-num{width:32px;height:32px;background:#2c5545;color:white;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:bold;flex-shrink:0}.step-content p{margin:0.25rem 0 0;color:#666;font-size:0.875rem}';
    html += '.help-section ul{margin:0.5rem 0 0 1.5rem;color:#666}.help-section ul li{margin-bottom:0.25rem}';
    html += '.faq-item{margin-bottom:1rem;padding:1rem;background:#f8f9fa;border-radius:8px}.faq-item strong{color:#333}.faq-item p{margin:0.5rem 0 0;color:#666;font-size:0.875rem}';
    
    // Chat UI CSS
    html += '.chat-bubble{position:fixed;bottom:24px;right:24px;width:60px;height:60px;background:#2c5545;border-radius:50%;display:flex;align-items:center;justify-content:center;cursor:pointer;box-shadow:0 4px 12px rgba(0,0,0,0.2);z-index:999;transition:transform 0.2s}.chat-bubble:hover{transform:scale(1.1)}.chat-bubble svg{width:28px;height:28px;fill:white}';
    html += '.chat-panel{position:fixed;bottom:100px;right:24px;width:380px;max-width:calc(100vw - 48px);height:500px;max-height:calc(100vh - 150px);background:white;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.15);display:none;flex-direction:column;z-index:998;overflow:hidden}.chat-panel.active{display:flex}';
    html += '.chat-header{background:#2c5545;color:white;padding:1rem;display:flex;justify-content:space-between;align-items:center}.chat-header h3{margin:0;font-size:1rem;display:flex;align-items:center;gap:0.5rem}.chat-close{background:none;border:none;color:white;font-size:1.5rem;cursor:pointer;padding:0;line-height:1}';
    html += '.chat-messages{flex:1;overflow-y:auto;padding:1rem;display:flex;flex-direction:column;gap:0.75rem}';
    html += '.chat-message{max-width:85%;padding:0.75rem 1rem;border-radius:12px;font-size:0.9rem;line-height:1.4}.chat-message.user{background:#e3f2fd;align-self:flex-end;border-bottom-right-radius:4px}.chat-message.assistant{background:#f5f5f5;align-self:flex-start;border-bottom-left-radius:4px}.chat-message.system{background:#fff3cd;align-self:center;font-size:0.8rem;color:#856404}';
    html += '.chat-input-area{padding:1rem;border-top:1px solid #eee;display:flex;gap:0.5rem}.chat-input{flex:1;padding:0.75rem;border:1px solid #ddd;border-radius:8px;font-size:0.9rem;resize:none}.chat-input:focus{outline:none;border-color:#2c5545}.chat-send{background:#2c5545;color:white;border:none;border-radius:8px;padding:0.75rem 1rem;cursor:pointer;font-weight:500}.chat-send:hover{background:#1a3b2e}.chat-send:disabled{background:#ccc;cursor:not-allowed}';
    html += '.chat-typing{display:flex;gap:4px;padding:0.5rem}.chat-typing span{width:8px;height:8px;background:#999;border-radius:50%;animation:typing 1.4s infinite}.chat-typing span:nth-child(2){animation-delay:0.2s}.chat-typing span:nth-child(3){animation-delay:0.4s}@keyframes typing{0%,60%,100%{transform:translateY(0)}30%{transform:translateY(-4px)}}';
    
    html += 'kbd{background:#eee;border:1px solid #ccc;border-radius:4px;padding:0.2rem 0.5rem;font-family:monospace;font-size:0.875rem}';
    html += 'table{width:100%;border-collapse:collapse}th,td{padding:0.75rem;text-align:left;border-bottom:1px solid #eee}';
    html += '.add-form{display:flex;gap:0.5rem;margin-top:1rem;flex-wrap:wrap}.add-form input,.add-form select{padding:0.5rem;border:1px solid #ddd;border-radius:4px}';
    html += '.status-box{padding:1rem;background:#f9f9f9;border-radius:4px;margin-bottom:1rem}.status-item{margin-bottom:0.5rem}.status-label{font-weight:500}.status-value{color:#666}.status-value.connected{color:#2e7d32}.status-value.disconnected{color:#c4553d}';
    html += '.system-health-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem}.health-card{background:#f9f9f9;border-radius:8px;padding:1rem}.health-card h4{margin:0 0 0.75rem;font-size:1rem;color:#333}.health-stats{display:flex;flex-direction:column;gap:0.5rem}.health-row{display:flex;justify-content:space-between;font-size:0.875rem}.health-row span{color:#666}.health-row strong{color:#333}.status-ok{color:#2e7d32}.status-warn{color:#f57c00}';
    html += '.view-controls{display:flex;align-items:center;gap:1rem;margin-bottom:1rem;padding:0.75rem 1rem;background:white;border-radius:0;flex-wrap:wrap;position:sticky;top:110px;z-index:80;border-bottom:1px solid #eee;transition:all 0.3s ease}.view-controls.compact{padding:0.5rem 1rem;gap:0.5rem;top:82px}.view-controls label{font-weight:500;color:#333}';
    html += '.size-btn{padding:0.5rem 1rem;border:1px solid #ddd;background:white;cursor:pointer}.size-btn:first-of-type{border-radius:4px 0 0 4px}.size-btn:last-of-type{border-radius:0 4px 4px 0}.size-btn.active{background:#2c5545;color:white;border-color:#2c5545}';
    html += '.selection-bar{position:fixed;bottom:0;left:0;right:0;background:white;padding:1rem 2rem;box-shadow:0 -2px 10px rgba(0,0,0,0.1);display:flex;justify-content:space-between;align-items:center;z-index:100;transform:translateY(100%);transition:transform 0.3s}.selection-bar.visible{transform:translateY(0)}';
    html += '.selection-count{font-weight:600;font-size:1.1rem}.selection-actions{display:flex;gap:0.5rem}';
    html += '.share-modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:none;align-items:center;justify-content:center;z-index:1001}.share-modal.active{display:flex}.share-modal-content{background:white;border-radius:8px;padding:2rem;max-width:500px;width:90%}.share-modal h3{margin-bottom:1rem}.share-modal input{width:100%;padding:0.75rem;border:1px solid #ddd;border-radius:4px;margin-bottom:1rem}.share-modal-actions{display:flex;gap:0.5rem;justify-content:flex-end}';
    html += '.share-result{margin-top:1rem;padding:1rem;background:#f0f9f0;border-radius:4px}.share-result a{color:#2c5545;word-break:break-all}';
    html += '.share-buttons{display:flex;flex-direction:column;gap:0.75rem}.share-action-btn{display:block;width:100%;padding:1rem;border:1px solid #ddd;background:white;border-radius:8px;font-size:1rem;cursor:pointer;text-align:left;text-decoration:none;color:#333;transition:background 0.2s}.share-action-btn:hover{background:#f5f5f5}';
    html += '.select-mode-btn{padding:0.5rem 1rem;border:2px solid #2c5545;background:white;color:#2c5545;border-radius:4px;cursor:pointer;font-weight:500;transition:all 0.2s}.select-mode-btn:hover{background:#f0f7f4}.select-mode-btn.active{background:#2c5545;color:white}';
    html += '.feature-toggle{display:inline-flex;align-items:center;margin:0 1rem;background:#f0f4f8;border-radius:6px;padding:0.25rem;border:1px solid #d0d8e0}.feature-toggle input{display:none}.feature-toggle label{padding:0.4rem 0.75rem;border-radius:4px;cursor:pointer;font-size:0.875rem;font-weight:500;color:#666;transition:all 0.2s}.feature-toggle input:checked+label{background:#2c5545;color:white}';
    html += '.freshness-info{padding:1rem;background:#f0f9f0;border-radius:4px;margin-bottom:1rem}.freshness-info.stale{background:#fff3e0}';
    html += '.share-history-table{font-size:0.875rem}.share-history-table td{padding:0.5rem 0.75rem}.share-type-badge{display:inline-block;padding:0.125rem 0.5rem;border-radius:4px;font-size:0.75rem;font-weight:500}.share-type-badge.link{background:#e3f2fd;color:#1565c0}.share-type-badge.pdf{background:#fce4ec;color:#c62828}';
    html += '</style></head><body>';
    
    html += '<div id="loginPage" class="login-page"><div class="login-box"><h1>Mark Edwards Apparel<br><span style="font-size:0.8em;font-weight:normal">Product Catalog</span></h1><form id="loginForm"><div class="form-group"><label>Username</label><input type="text" id="username" required></div><div class="form-group"><label>Password</label><input type="password" id="password" required></div><button type="submit" class="btn btn-primary" style="width:100%">Sign In</button><div id="loginError" class="error hidden"></div></form></div></div>';
    
    html += '<div id="mainApp" class="hidden"><header class="header"><h1>Mark Edwards Apparel Product Catalog</h1><div class="search-box"><input type="text" id="searchInput" placeholder="Search products..."><button id="clearSearchBtn" style="margin-left:0.5rem;padding:0.5rem 0.75rem;border:1px solid #ddd;background:#f5f5f5;border-radius:4px;cursor:pointer">Clear</button><div id="aiSearchIndicator" class="ai-search-indicator hidden">🤖 AI-enhanced search active</div></div><div class="header-right"><span id="userInfo"></span><button class="btn btn-secondary" id="helpBtn">Help</button><button class="btn btn-secondary" id="historyBtn">History</button><button class="btn btn-secondary" id="adminBtn" style="display:none">Admin</button><button class="btn btn-secondary" id="logoutBtn">Sign Out</button></div></header>';
    
    // History panel (visible to all users)
    html += '<main class="main"><div id="historyPanel" class="admin-panel hidden"><h2>History & Status</h2><div class="tabs"><button class="tab active" data-tab="shares">Sharing History</button><button class="tab" data-tab="freshness">Data Freshness</button><button class="tab" data-tab="history">Sync History</button></div>';
    html += '<div id="sharesTab" class="tab-content active"><table class="share-history-table"><thead><tr><th>Date</th><th>Name</th><th>Sales Rep</th><th>Type</th><th>Items</th><th>Actions</th></tr></thead><tbody id="sharesTable"></tbody></table></div>';
    html += '<div id="freshnessTab" class="tab-content"><div class="freshness-info" id="freshnessInfo"><p><strong>Last Data Update:</strong> <span id="lastUpdateTime">Loading...</span></p><p><strong>Records Imported:</strong> <span id="lastUpdateRecords">-</span></p></div><p style="color:#666;font-size:0.875rem;margin-top:1rem">This shows when the product catalog data was last updated via CSV import.</p></div>';
    html += '<div id="historyTab" class="tab-content"><table><thead><tr><th>Date</th><th>Type</th><th>Status</th><th>Records</th><th>Error</th></tr></thead><tbody id="historyTable"></tbody></table></div></div>';
    
    // Admin panel (admin only)
    html += '<div id="adminPanel" class="admin-panel hidden"><h2>Admin Settings</h2><div class="tabs"><button class="tab active" data-tab="zoho2">Zoho Sync</button><button class="tab" data-tab="import2">Import CSV</button><button class="tab" data-tab="sales2">Import Sales</button><button class="tab" data-tab="ai2">AI Analysis</button><button class="tab" data-tab="users2">Users</button><button class="tab" data-tab="system2">System Health</button></div>';
    html += '<div id="zoho2Tab" class="tab-content active"><div class="status-box"><div class="status-item"><span class="status-label">Status: </span><span class="status-value" id="zohoStatusText">Checking...</span></div><div class="status-item"><span class="status-label">Workspace ID: </span><span class="status-value" id="zohoWorkspaceId">-</span></div><div class="status-item"><span class="status-label">View ID: </span><span class="status-value" id="zohoViewId">-</span></div></div><div style="display:flex;gap:1rem"><button class="btn btn-secondary" id="testZohoBtn">Test Connection</button><button class="btn btn-success" id="syncZohoBtn">Sync Now</button></div><div id="zohoMessage" style="margin-top:1rem"></div></div>';
    html += '<div id="import2Tab" class="tab-content"><div class="upload-area"><input type="file" id="csvFile" accept=".csv"><label for="csvFile">Click to upload CSV file</label></div><div id="importStatus"></div><button class="btn btn-danger" id="clearBtn" style="margin-top:1rem">Clear All Products</button></div>';
    html += '<div id="sales2Tab" class="tab-content"><p style="margin-bottom:1rem;color:#666">Import sales data (Sales Orders and Purchase Orders) from the PO-SO Query CSV export.</p><div class="upload-area"><input type="file" id="salesCsvFile" accept=".csv"><label for="salesCsvFile">Click to upload Sales CSV file</label></div><div id="salesImportStatus"></div><div id="salesDataStats" style="margin-top:1rem"></div></div>';
    html += '<div id="ai2Tab" class="tab-content"><div class="status-box"><div class="status-item"><span class="status-label">API Status: </span><span class="status-value" id="aiStatusText">Checking...</span></div><div class="status-item"><span class="status-label">Products Analyzed: </span><span class="status-value" id="aiAnalyzedCount">-</span></div><div class="status-item"><span class="status-label">Remaining: </span><span class="status-value" id="aiRemainingCount">-</span></div></div><p style="color:#666;font-size:0.875rem;margin-bottom:1rem">AI analysis uses Claude Vision to generate searchable tags from product images. This enables searching by garment type (cardigan, hoodie), style (casual, formal), pattern (striped, floral), and more.</p><button class="btn btn-primary" id="runAiBtn">Analyze Next 100 Products</button><button class="btn btn-success" id="runAllAiBtn" style="margin-left:0.5rem">Analyze All (Background)</button><button class="btn btn-secondary" id="stopAiBtn" style="margin-left:0.5rem;display:none">Stop</button><div id="aiMessage" style="margin-top:1rem"></div></div>';
    html += '<div id="users2Tab" class="tab-content"><table><thead><tr><th>Username</th><th>Role</th><th>Actions</th></tr></thead><tbody id="usersTable"></tbody></table><div class="add-form"><input type="text" id="newUser" placeholder="Username"><input type="password" id="newPass" placeholder="Password"><select id="newRole"><option value="sales_rep">Sales Rep</option><option value="admin">Admin</option></select><button class="btn btn-primary" id="addUserBtn">Add</button></div></div>';
    html += '<div id="system2Tab" class="tab-content"><div id="systemHealthContent"><p>Loading system health data...</p></div><button class="btn btn-secondary" id="refreshSystemBtn" style="margin-top:1rem">🔄 Refresh</button></div></div>';
    
    html += '<div class="stats"><div><div class="stat-value" id="totalStyles">0</div><div class="stat-label">Styles</div></div><div id="availNowStat" class="stat-box stat-active"><div class="stat-value" id="totalAvailNow">0</div><div class="stat-label">📦 Avail Now</div></div><div id="leftToSellStat" class="stat-box"><div class="stat-value" id="totalLeftToSell">0</div><div class="stat-label">📊 Left to Sell</div></div><div class="qty-toggle"><button class="qty-toggle-btn active" id="toggleAvailableNow" data-mode="available_now">📦 Available Now</button><button class="qty-toggle-btn" id="toggleLeftToSell" data-mode="left_to_sell">📊 Left to Sell</button></div></div>';
    html += '<div class="view-controls"><label>View:</label><button class="size-btn" data-size="list">List</button><button class="size-btn" data-size="small">Small</button><button class="size-btn active" data-size="medium">Medium</button><button class="size-btn" data-size="large">Large</button><div class="feature-toggle active-indicator" id="groupByStyleWrapper"><input type="checkbox" id="groupByStyleToggle" checked><label for="groupByStyleToggle">🎨 Grouped by Style ✓</label></div><label>Sort:</label><select id="sortSelect" style="padding:0.4rem;border:1px solid #ddd;border-radius:4px"><option value="name-asc">Name A-Z</option><option value="name-desc">Name Z-A</option><option value="qty-high">Qty High→Low</option><option value="qty-low">Qty Low→High</option><option value="newest">Newest First</option></select><span style="margin-left:1rem"></span><label>Qty:</label><input type="number" id="minQty" placeholder="Min" style="width:70px;padding:0.4rem;border:1px solid #ddd;border-radius:4px"><span style="margin:0 0.25rem">-</span><input type="number" id="maxQty" placeholder="Max" style="width:70px;padding:0.4rem;border:1px solid #ddd;border-radius:4px"><button id="resetQtyBtn" style="margin-left:0.5rem;padding:0.4rem 0.75rem;border:1px solid #ddd;background:#f5f5f5;border-radius:4px;cursor:pointer;font-size:0.875rem">Reset</button><span style="margin-left:auto"></span><button class="select-mode-btn" id="selectModeBtn">📤 Select for Sharing</button></div>';
    html += '<div class="filters"><button class="filter-btn" data-special="new">New Arrivals</button><button class="filter-btn" data-special="picks">My Picks</button><button class="filter-btn" data-special="notes">Has Notes</button><span style="margin:0 0.5rem;color:#ccc">|</span><div style="display:inline-block;position:relative"><button class="filter-btn" id="colorFilterBtn">Color: All ▼</button><button class="filter-btn hidden" id="clearColorBtn" style="margin-left:0.25rem;padding:0.5rem 0.75rem">✕</button><div id="colorDropdown" class="color-dropdown hidden"></div></div><span style="margin:0 0.5rem;color:#ccc">|</span><span id="categoryFilters"></span></div>';
    html += '<div class="product-grid size-medium" id="productGrid"></div><div class="empty hidden" id="emptyState">No products found.</div></main></div>';
    
    // Selection bar
    html += '<div class="selection-bar" id="selectionBar"><span class="selection-count"><span id="selectedCount">0</span> items selected</span><div class="selection-actions"><button class="btn btn-secondary" id="clearSelectionBtn">Clear</button><button class="btn btn-secondary" id="exitSelectionBtn">Exit Selection Mode</button><button class="btn btn-primary" id="shareSelectionBtn">Share / Download</button></div></div>';
    
    // Chat UI
    html += '<div class="chat-bubble" id="chatBubble" title="Ask me anything about inventory"><svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z"/></svg></div>';
    html += '<div class="chat-panel" id="chatPanel"><div class="chat-header"><h3>💬 Product Assistant</h3><button class="chat-close" id="chatClose">&times;</button></div><div class="chat-messages" id="chatMessages"><div class="chat-message assistant">Hi! I can help you find products. Try asking me things like:<br><br>• "Show me navy sweaters"<br>• "Joggers with more than 1,000 units"<br>• "What categories do we have?"<br>• "Show new arrivals"</div></div><div class="chat-input-area"><textarea class="chat-input" id="chatInput" placeholder="Ask about products..." rows="1"></textarea><button class="chat-send" id="chatSend">Send</button></div></div>';
    
    // Share modal
    html += '<div class="share-modal" id="shareModal"><div class="share-modal-content"><h3>Share Selection</h3><div id="shareForm"><input type="text" id="selectionName" placeholder="Name this selection (e.g. Spring Collection for Acme Co)"><div class="share-modal-actions"><button class="btn btn-secondary" id="cancelShareBtn">Cancel</button><button class="btn btn-primary" id="createShareBtn">Create Link</button></div></div><div class="share-result hidden" id="shareResult"><p style="margin-bottom:1rem;color:#666" id="shareNameDisplay"></p><div class="share-buttons"><button class="share-action-btn" id="emailLinkBtn">📧 Email Link</button><button class="share-action-btn" id="textLinkBtn">💬 Text Link</button><button class="share-action-btn" id="copyLinkBtn">🔗 Copy Link</button><a class="share-action-btn" id="pdfLink" href="" target="_blank">📄 Download PDF</a></div><div style="margin-top:1.5rem;text-align:center"><button class="btn btn-secondary" id="closeShareModalBtn">Done</button></div></div></div></div>';
    
    // Product modal
    html += '<div class="modal" id="modal"><div class="modal-content"><button class="modal-close" id="modalClose">&times;</button><div class="modal-body"><div class="modal-image"><img id="modalImage" src="" alt=""></div><div class="modal-details"><div class="product-style" id="modalStyle"></div><h2 id="modalName"></h2><p id="modalCategory" style="color:#666;margin-bottom:1rem"></p><div id="modalColors"></div><div class="total-row"><span>Total Available</span><span id="modalTotal"></span></div><div class="modal-actions"><button class="btn btn-secondary btn-sm" id="modalPickBtn">♡ Add to My Picks</button></div><div class="sales-history-section"><h3 style="margin:1rem 0 0.75rem;font-size:1rem;display:flex;align-items:center;gap:0.5rem">📊 Sales History <span id="salesHistoryLoading" style="font-size:0.75rem;color:#666;font-weight:normal">(loading...)</span></h3><div id="salesHistorySummary" style="display:flex;gap:1.5rem;margin-bottom:0.75rem;font-size:0.875rem"></div><div id="salesHistoryList" style="max-height:200px;overflow-y:auto;font-size:0.875rem"></div></div><div class="note-section"><label><strong>My Notes:</strong></label><textarea id="modalNote" placeholder="Add private notes about this product..."></textarea><button class="btn btn-sm btn-primary" id="saveNoteBtn">Save Note</button></div></div></div></div></div>';
    
    // Help modal
    html += '<div class="help-modal" id="helpModal"><div class="help-content"><button class="modal-close" id="helpClose">&times;</button><h2>📖 Product Catalog Guide</h2><div class="help-sections">';
    
    // Quick Start
    html += '<div class="help-section"><h3>🚀 Quick Start</h3><div class="help-cards"><div class="help-card"><div class="help-icon">🔍</div><h4>Search</h4><p>Type in the search bar to find products by name, style ID, or visual features (AI-powered)</p></div><div class="help-card"><div class="help-icon">🎨</div><h4>Group by Style</h4><p>Products are grouped by base style showing all color variants together (ON by default)</p></div><div class="help-card"><div class="help-icon">📦</div><h4>Quantity Views</h4><p>Toggle between "Available Now" (ready to ship) and "Left to Sell" (including incoming)</p></div><div class="help-card"><div class="help-icon">📤</div><h4>Share</h4><p>Select products and share via email, text, or PDF with your customers</p></div></div></div>';
    
    // Quantity Toggle
    html += '<div class="help-section"><h3>📦 Available Now vs Left to Sell</h3><table class="help-table"><tr><td class="help-feature">📦 <strong>Available Now</strong></td><td>Inventory that is currently in stock and ready to ship immediately. Use this when discussing what you can deliver TODAY.</td></tr><tr><td class="help-feature">📊 <strong>Left to Sell</strong></td><td>Available Now PLUS uncommitted incoming inventory. Use this for seasonal planning and future commitments.</td></tr><tr><td class="help-feature">🔘 <strong>Toggle Button</strong></td><td>Click the toggle buttons in the stats bar to switch views. The selected quantity type is highlighted in green. All filtering, sorting, and product displays update based on your selection.</td></tr></table></div>';
    
    // Group by Style
    html += '<div class="help-section"><h3>🎨 Group by Style</h3><p>When "Grouped by Style ✓" is active (default), products with the same base style but different colors are shown as a single card with a color count badge (e.g., "5 colors").</p><table class="help-table"><tr><td class="help-feature"><strong>Grouped View</strong></td><td>Shows one card per base style with total quantities across all colors. Click to see all color variants with swatches.</td></tr><tr><td class="help-feature"><strong>Ungrouped View</strong></td><td>Uncheck the toggle to see each color variant as a separate card. Useful when you need to find specific colors.</td></tr></table></div>';
    
    // Features Guide
    html += '<div class="help-section"><h3>✨ Features Guide</h3><table class="help-table"><tr><td class="help-feature">🔍 <strong>Search Bar</strong></td><td>Search by style ID, product name, or descriptive terms like "striped hoodie" or "floral dress". Multi-word searches find products matching ALL terms.</td></tr><tr><td class="help-feature">📂 <strong>Category Filter</strong></td><td>Click category buttons (Sweater, Dress, etc.) to show only that category. Click "All" to reset.</td></tr><tr><td class="help-feature">🎨 <strong>Color Filter</strong></td><td>Click "Color: All ▼" dropdown to filter by specific colors. Click ✕ to clear.</td></tr><tr><td class="help-feature">📊 <strong>Sort Options</strong></td><td>Sort by Name (A-Z, Z-A), Quantity (High/Low), or Newest arrivals. Sorting uses the selected quantity mode.</td></tr><tr><td class="help-feature">📏 <strong>View Options</strong></td><td>Switch between List, Small, Medium, and Large tile views.</td></tr><tr><td class="help-feature">🔢 <strong>Quantity Filter</strong></td><td>Set Min/Max quantity to find products within a specific inventory range. Click "Reset" to clear.</td></tr><tr><td class="help-feature">🆕 <strong>New Arrivals</strong></td><td>Click "New Arrivals" to see products added in the most recent data import.</td></tr></table></div>';
    
    // Product Details & Sales History
    html += '<div class="help-section"><h3>📋 Product Details & Sales History</h3><p>Click any product to open the detail modal with:</p><table class="help-table"><tr><td class="help-feature"><strong>Color Breakdown</strong></td><td>See Available Now and Left to Sell quantities for each color variant.</td></tr><tr><td class="help-feature"><strong>Color Swatches</strong></td><td>In grouped view, click color swatches to switch the displayed image.</td></tr><tr><td class="help-feature">📈 <strong>Sales History Tab</strong></td><td>View past invoices and open sales orders for this style from Zoho Books, including customer names, quantities, and dollar amounts.</td></tr><tr><td class="help-feature">📦 <strong>Import POs Tab</strong></td><td>See purchase orders (incoming inventory) for this style.</td></tr></table></div>';
    
    // My Picks & Notes
    html += '<div class="help-section"><h3>💾 Save & Organize</h3><table class="help-table"><tr><td class="help-feature">♥ <strong>My Picks</strong></td><td>Click the heart icon on any product to save it to your personal favorites. Click "My Picks" filter to see only saved items. Your picks are saved to your account.</td></tr><tr><td class="help-feature">📝 <strong>Notes</strong></td><td>Click a product to open it, then add private notes in the "My Notes" section. Products with notes show a 📝 badge. Click "Has Notes" filter to find them.</td></tr></table></div>';
    
    // Sharing Guide
    html += '<div class="help-section"><h3>📤 Sharing Products</h3><div class="help-steps"><div class="help-step"><div class="step-num">1</div><div class="step-content"><strong>Enter Selection Mode</strong><p>Click "📤 Select for Sharing" button in the view controls</p></div></div><div class="help-step"><div class="step-num">2</div><div class="step-content"><strong>Select Products</strong><p>Click products to select them (green checkmark appears). Click again to deselect.</p></div></div><div class="help-step"><div class="step-num">3</div><div class="step-content"><strong>Share / Download</strong><p>Click "Share / Download" in the bottom bar that appears</p></div></div><div class="help-step"><div class="step-num">4</div><div class="step-content"><strong>Choose Method</strong><p>📧 Email Link, 💬 Text Link, 🔗 Copy Link, or 📄 Download PDF</p></div></div></div><p style="margin-top:1rem;color:#666"><strong>Note:</strong> Shared links are view-only. Customers see product images and quantities but cannot place orders directly. Sales history is NOT shown on shared links.</p></div>';
    
    // Keyboard Shortcuts
    html += '<div class="help-section"><h3>⌨️ Keyboard Shortcuts</h3><table class="help-table"><tr><td><kbd>←</kbd> <kbd>→</kbd> <kbd>↑</kbd> <kbd>↓</kbd></td><td>Navigate between products</td></tr><tr><td><kbd>Enter</kbd></td><td>Open selected product / Toggle selection in selection mode</td></tr><tr><td><kbd>Space</kbd></td><td>Toggle selection (in selection mode)</td></tr><tr><td><kbd>Esc</kbd></td><td>Close any open modal</td></tr></table></div>';
    
    // AI Search
    html += '<div class="help-section"><h3>🤖 AI-Enhanced Search</h3><p>When you see "🤖 AI-enhanced search active" below the search bar, the catalog has been analyzed by AI to understand what\'s in each product image.</p><p><strong>This means you can search by:</strong></p><ul><li>Garment type: "cardigan", "hoodie", "romper", "jogger"</li><li>Style: "casual", "bohemian", "preppy", "streetwear"</li><li>Pattern: "striped", "floral", "graphic print", "heart print", "tie-dye"</li><li>Features: "v-neck", "button-front", "cropped", "oversized", "zip-up"</li><li>Neckline: "crew neck", "turtleneck", "mock neck", "off-shoulder"</li><li>Combinations: "striped cardigan buttons" or "oversized hoodie graphic"</li></ul><p style="margin-top:0.5rem;color:#666">The AI analyzes product images when data is imported. Search matches both CSV data AND AI-detected visual features.</p></div>';
    
    // History Panel
    html += '<div class="help-section"><h3>📊 History Panel</h3><p>Click "History" in the header to access:</p><table class="help-table"><tr><td class="help-feature"><strong>Sharing History</strong></td><td>See all shared selections you\'ve created, with links to view or copy them again.</td></tr><tr><td class="help-feature"><strong>Data Freshness</strong></td><td>Check when inventory data was last updated (CSV import or Zoho sync).</td></tr><tr><td class="help-feature"><strong>Sync History</strong></td><td>View history of all data syncs and imports with status and record counts.</td></tr></table></div>';
    
    // FAQ
    html += '<div class="help-section"><h3>❓ FAQ</h3><div class="faq-item"><strong>Q: What\'s the difference between Available Now and Left to Sell?</strong><p>A: "Available Now" is what you can ship today. "Left to Sell" includes Available Now plus incoming inventory that hasn\'t arrived yet - use this for seasonal planning.</p></div><div class="faq-item"><strong>Q: Why do I see "546 groups" instead of "1110 Styles"?</strong><p>A: When "Group by Style" is ON, products with the same base style but different colors are combined into one group. Toggle it OFF to see individual style/color combinations.</p></div><div class="faq-item"><strong>Q: Why can\'t I find a product I know exists?</strong><p>A: Check if filters are applied (category, color, quantity range). Try clearing the search and filters, or toggle "Group by Style" off to see all variants.</p></div><div class="faq-item"><strong>Q: Are my picks and notes visible to others?</strong><p>A: No, your picks and notes are private to your account.</p></div><div class="faq-item"><strong>Q: Can customers see sales history on shared links?</strong><p>A: No, sales history is only visible to logged-in users. Shared links show products and quantities only.</p></div><div class="faq-item"><strong>Q: How current is the inventory data?</strong><p>A: Check History → Data Freshness to see when data was last updated. Sales history is cached and refreshes automatically.</p></div></div>';
    
    html += '</div></div></div>';
    
    html += '<script>';
    html += 'var products=[];var allProducts=[];var groupedProducts=[];var lastImportId=null;var currentFilter="all";var colorFilter=null;var specialFilter=null;var currentSort="name-asc";var currentSize="medium";var selectedProducts=[];var selectionMode=false;var currentShareId=null;var userPicks=[];var userNotes={};var currentModalProductId=null;var focusedIndex=-1;var qtyMode="available_now";var groupByStyle=true;var minColorsFilter=0;';
    
    html += 'function checkSession(){fetch("/api/session").then(function(r){return r.json()}).then(function(d){if(d.loggedIn){showApp(d.username,d.role);loadProducts();loadPicks();loadNotes();loadZohoStatus();loadDataFreshness();loadShares();loadHistory();if(d.role==="admin"){loadUsers();loadAiStatus()}}})}';
    html += 'function showApp(u,r){document.getElementById("loginPage").classList.add("hidden");document.getElementById("mainApp").classList.remove("hidden");document.getElementById("userInfo").textContent="Welcome, "+u;if(r==="admin")document.getElementById("adminBtn").style.display="block"}';
    
    html += 'document.getElementById("loginForm").addEventListener("submit",function(e){e.preventDefault();fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:document.getElementById("username").value,password:document.getElementById("password").value})}).then(function(r){return r.json()}).then(function(d){if(d.success){showApp(d.username,d.role);loadProducts();loadPicks();loadNotes();loadZohoStatus();loadDataFreshness();loadShares();loadHistory();if(d.role==="admin"){loadUsers();loadAiStatus()}}else{document.getElementById("loginError").textContent=d.error;document.getElementById("loginError").classList.remove("hidden")}})});';
    
    html += 'document.getElementById("logoutBtn").addEventListener("click",function(){fetch("/api/logout",{method:"POST"}).then(function(){location.reload()})});';
    html += 'document.getElementById("helpBtn").addEventListener("click",function(){document.getElementById("helpModal").classList.add("active")});';
    html += 'document.getElementById("helpClose").addEventListener("click",function(){document.getElementById("helpModal").classList.remove("active")});';
    html += 'document.getElementById("helpModal").addEventListener("click",function(e){if(e.target.id==="helpModal")document.getElementById("helpModal").classList.remove("active")});';
    html += 'document.getElementById("historyBtn").addEventListener("click",function(){document.getElementById("historyPanel").classList.toggle("hidden");document.getElementById("adminPanel").classList.add("hidden")});';
    html += 'document.getElementById("adminBtn").addEventListener("click",function(){document.getElementById("adminPanel").classList.toggle("hidden");document.getElementById("historyPanel").classList.add("hidden");if(!document.getElementById("adminPanel").classList.contains("hidden")){loadSystemHealth();loadSalesStats()}});';
    
    // Chat functionality
    html += 'var chatOpen=false;';
    html += 'document.getElementById("chatBubble").addEventListener("click",function(){chatOpen=!chatOpen;document.getElementById("chatPanel").classList.toggle("active",chatOpen);if(chatOpen)document.getElementById("chatInput").focus()});';
    html += 'document.getElementById("chatClose").addEventListener("click",function(){chatOpen=false;document.getElementById("chatPanel").classList.remove("active")});';
    html += 'document.getElementById("chatSend").addEventListener("click",sendChatMessage);';
    html += 'document.getElementById("chatInput").addEventListener("keypress",function(e){if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();sendChatMessage()}});';
    html += 'document.getElementById("chatInput").addEventListener("input",function(){this.style.height="auto";this.style.height=Math.min(this.scrollHeight,80)+"px"});';
    
    html += 'function addChatMessage(text,type){var msgs=document.getElementById("chatMessages");var div=document.createElement("div");div.className="chat-message "+type;div.innerHTML=text;msgs.appendChild(div);msgs.scrollTop=msgs.scrollHeight}';
    
    html += 'function showTyping(){var msgs=document.getElementById("chatMessages");var div=document.createElement("div");div.className="chat-message assistant";div.id="typingIndicator";div.innerHTML="<div class=\\"chat-typing\\"><span></span><span></span><span></span></div>";msgs.appendChild(div);msgs.scrollTop=msgs.scrollHeight}';
    
    html += 'function hideTyping(){var el=document.getElementById("typingIndicator");if(el)el.remove()}';
    
    html += 'function executeChatActions(actions){if(!actions||!actions.length)return;actions.forEach(function(a){switch(a.action){case"search":document.getElementById("searchInput").value=a.value||"";break;case"setCategory":currentFilter=a.value==="all"?"all":a.value;document.querySelectorAll(".filter-btn[data-cat]").forEach(function(b){b.classList.toggle("active",b.getAttribute("data-cat")===currentFilter)});break;case"setColor":colorFilter=a.value||null;var btn=document.getElementById("colorFilterBtn");btn.textContent=colorFilter?"Color: "+colorFilter+" ▼":"Color: All ▼";document.getElementById("clearColorBtn").classList.toggle("hidden",!colorFilter);break;case"setMinQty":document.getElementById("minQty").value=a.value||"";break;case"setMaxQty":document.getElementById("maxQty").value=a.value||"";break;case"setMinColors":minColorsFilter=a.value||0;break;case"clearFilters":document.getElementById("searchInput").value="";document.getElementById("minQty").value="";document.getElementById("maxQty").value="";currentFilter="all";colorFilter=null;specialFilter=null;minColorsFilter=0;document.querySelectorAll(".filter-btn").forEach(function(b){b.classList.remove("active")});document.querySelector(".filter-btn[data-cat=\\"all\\"]").classList.add("active");document.getElementById("colorFilterBtn").textContent="Color: All ▼";document.getElementById("clearColorBtn").classList.add("hidden");break;case"setSort":currentSort=a.value||"name-asc";document.getElementById("sortSelect").value=currentSort;break;case"showNewArrivals":specialFilter="new";document.querySelectorAll(".filter-btn[data-special]").forEach(function(b){b.classList.toggle("active",b.getAttribute("data-special")==="new")});break;case"showPicks":specialFilter="picks";document.querySelectorAll(".filter-btn[data-special]").forEach(function(b){b.classList.toggle("active",b.getAttribute("data-special")==="picks")});break}});renderProducts()}';
    
    html += 'async function sendChatMessage(){var input=document.getElementById("chatInput");var msg=input.value.trim();if(!msg)return;addChatMessage(msg,"user");input.value="";input.style.height="auto";document.getElementById("chatSend").disabled=true;showTyping();try{var resp=await fetch("/api/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({message:msg})});var data=await resp.json();hideTyping();if(data.success){addChatMessage(data.message,"assistant");if(data.actions&&data.actions.length>0){executeChatActions(data.actions)}}else{addChatMessage("Sorry, I encountered an error. Please try again.","assistant")}}catch(err){hideTyping();addChatMessage("Sorry, something went wrong. Please try again.","assistant")}document.getElementById("chatSend").disabled=false}';
    
    html += 'var tabs=document.querySelectorAll(".tab");for(var i=0;i<tabs.length;i++){tabs[i].addEventListener("click",function(e){var panel=e.target.closest(".admin-panel");panel.querySelectorAll(".tab").forEach(function(t){t.classList.remove("active")});panel.querySelectorAll(".tab-content").forEach(function(c){c.classList.remove("active")});e.target.classList.add("active");document.getElementById(e.target.getAttribute("data-tab")+"Tab").classList.add("active")})}';
    
    html += 'var sizeBtns=document.querySelectorAll(".size-btn");sizeBtns.forEach(function(btn){btn.addEventListener("click",function(e){sizeBtns.forEach(function(b){b.classList.remove("active")});e.target.classList.add("active");currentSize=e.target.getAttribute("data-size");document.getElementById("productGrid").className="product-grid size-"+currentSize;renderProducts()})});';
    
    // Group by style toggle
    html += 'document.getElementById("groupByStyleToggle").addEventListener("change",function(){groupByStyle=this.checked;var wrapper=document.getElementById("groupByStyleWrapper");var label=wrapper.querySelector("label");if(this.checked){wrapper.classList.add("active-indicator");label.textContent="🎨 Grouped by Style ✓"}else{wrapper.classList.remove("active-indicator");label.textContent="🎨 Group by Style"}renderProducts()});';
    
    // Sort handler
    html += 'document.getElementById("sortSelect").addEventListener("change",function(e){currentSort=e.target.value;renderProducts()});';
    
    // Quantity mode toggle handlers
    html += 'document.getElementById("toggleAvailableNow").addEventListener("click",function(){qtyMode="available_now";document.getElementById("toggleAvailableNow").classList.add("active");document.getElementById("toggleLeftToSell").classList.remove("active");document.getElementById("availNowStat").classList.add("stat-active");document.getElementById("leftToSellStat").classList.remove("stat-active");renderProducts()});';
    html += 'document.getElementById("toggleLeftToSell").addEventListener("click",function(){qtyMode="left_to_sell";document.getElementById("toggleLeftToSell").classList.add("active");document.getElementById("toggleAvailableNow").classList.remove("active");document.getElementById("leftToSellStat").classList.add("stat-active");document.getElementById("availNowStat").classList.remove("stat-active");renderProducts()});';
    
    html += 'function loadZohoStatus(){fetch("/api/zoho/status").then(function(r){return r.json()}).then(function(d){var st=document.getElementById("zohoStatusText");if(d.connected){st.textContent="Connected";st.className="status-value connected"}else{st.textContent="Not connected";st.className="status-value disconnected"}document.getElementById("zohoWorkspaceId").textContent=d.workspaceId||"Not set";document.getElementById("zohoViewId").textContent=d.viewId||"Not set"})}';
    
    html += 'function loadDataFreshness(){fetch("/api/data-freshness").then(function(r){return r.json()}).then(function(d){if(d.lastUpdate){var dt=new Date(d.lastUpdate);document.getElementById("lastUpdateTime").textContent=dt.toLocaleString();document.getElementById("lastUpdateRecords").textContent=d.recordCount.toLocaleString()+" records";var hoursSince=(Date.now()-dt.getTime())/(1000*60*60);if(hoursSince>24){document.getElementById("freshnessInfo").classList.add("stale")}}else{document.getElementById("lastUpdateTime").textContent="No data imported yet";document.getElementById("lastUpdateRecords").textContent="-"}})}';
    
    html += 'function loadShares(){fetch("/api/selections").then(function(r){return r.json()}).then(function(shares){var h="";shares.forEach(function(s){var dt=new Date(s.created_at).toLocaleString();var type=s.share_type||"link";var badge=type==="pdf"?"<span class=\\"share-type-badge pdf\\">PDF</span>":"<span class=\\"share-type-badge link\\">Link</span>";var itemCount=(s.product_ids||[]).length;h+="<tr><td>"+dt+"</td><td>"+s.name+"</td><td>"+s.created_by+"</td><td>"+badge+"</td><td>"+itemCount+"</td><td><a href=\\"/share/"+s.share_id+"\\" target=\\"_blank\\">View</a></td></tr>"});document.getElementById("sharesTable").innerHTML=h||"<tr><td colspan=6 style=\\"text-align:center;color:#666\\">No shares yet</td></tr>"})}';
    
    html += 'document.getElementById("testZohoBtn").addEventListener("click",function(){document.getElementById("zohoMessage").innerHTML="Testing...";fetch("/api/zoho/test",{method:"POST"}).then(function(r){return r.json()}).then(function(d){document.getElementById("zohoMessage").innerHTML=d.success?"<span class=success>"+d.message+"</span>":"<span class=error>"+d.error+"</span>";loadZohoStatus()})});';
    html += 'document.getElementById("syncZohoBtn").addEventListener("click",function(){document.getElementById("zohoMessage").innerHTML="Syncing...";fetch("/api/zoho/sync",{method:"POST"}).then(function(r){return r.json()}).then(function(d){document.getElementById("zohoMessage").innerHTML=d.success?"<span class=success>"+d.message+"</span>":"<span class=error>"+d.error+"</span>";loadProducts();loadHistory();loadDataFreshness()})});';
    
    html += 'function getImageUrl(url){if(!url)return null;if(url.indexOf("download-accl.zoho.com")!==-1){return"/api/image/"+url.split("/").pop()}return url}';
    html += 'function loadProducts(){fetch("/api/products").then(function(r){return r.json()}).then(function(d){allProducts=d.products||d;lastImportId=d.lastImportId;products=allProducts;var hasAiTags=allProducts.some(function(p){return p.ai_tags&&p.ai_tags.length>0});document.getElementById("aiSearchIndicator").classList.toggle("hidden",!hasAiTags);renderFilters();renderProducts()})}';
    
    html += 'function loadPicks(){fetch("/api/picks").then(function(r){return r.json()}).then(function(p){userPicks=p;renderProducts()})}';
    html += 'function loadNotes(){fetch("/api/notes").then(function(r){return r.json()}).then(function(n){userNotes=n;renderProducts()})}';
    
    html += 'function renderFilters(){var cats=[];var colors={};allProducts.forEach(function(p){if(p.category&&cats.indexOf(p.category)===-1)cats.push(p.category);(p.colors||[]).forEach(function(c){if(c.color_name)colors[c.color_name]=true})});cats.sort();var h="<button class=\\"filter-btn active\\" data-cat=\\"all\\">All</button>";cats.forEach(function(c){h+="<button class=\\"filter-btn\\" data-cat=\\""+c+"\\">"+c+"</button>"});document.getElementById("categoryFilters").innerHTML=h;var colorList=Object.keys(colors).sort();var ch="<div class=\\"color-option\\" data-color=\\"all\\">✓ All Colors</div>";colorList.forEach(function(c){ch+="<div class=\\"color-option\\" data-color=\\""+c+"\\">"+c+"</div>"});document.getElementById("colorDropdown").innerHTML=ch;document.querySelectorAll("[data-cat]").forEach(function(btn){btn.addEventListener("click",function(e){document.querySelectorAll("[data-cat]").forEach(function(b){b.classList.remove("active")});e.target.classList.add("active");currentFilter=e.target.getAttribute("data-cat");renderProducts()})});document.querySelectorAll(".color-option").forEach(function(opt){opt.addEventListener("click",function(e){document.querySelectorAll(".color-option").forEach(function(o){o.classList.remove("active")});e.target.classList.add("active");colorFilter=e.target.getAttribute("data-color");if(colorFilter==="all")colorFilter=null;document.getElementById("colorFilterBtn").textContent="Color: "+(colorFilter||"All")+" ▼";document.getElementById("clearColorBtn").classList.toggle("hidden",!colorFilter);document.getElementById("colorDropdown").classList.add("hidden");renderProducts()})});document.querySelectorAll("[data-special]").forEach(function(btn){btn.addEventListener("click",function(e){var sp=e.target.getAttribute("data-special");if(specialFilter===sp){specialFilter=null;e.target.classList.remove("active")}else{document.querySelectorAll("[data-special]").forEach(function(b){b.classList.remove("active")});specialFilter=sp;e.target.classList.add("active")}renderProducts()})})}';
    
    // Selection mode toggle - button toggles on/off
    html += 'document.getElementById("selectModeBtn").addEventListener("click",function(){selectionMode=!selectionMode;this.classList.toggle("active",selectionMode);this.textContent=selectionMode?"✕ Exit Selection Mode":"Select for Sharing";if(!selectionMode){selectedProducts=[];updateSelectionUI()}renderProducts()});';
    
    html += 'document.getElementById("exitSelectionBtn").addEventListener("click",function(){selectionMode=false;selectedProducts=[];document.getElementById("selectModeBtn").classList.remove("active");document.getElementById("selectModeBtn").textContent="Select for Sharing";updateSelectionUI();renderProducts()});';
    
    html += 'function handleCardClick(id,e){if(e.target.classList.contains("pick-badge")){togglePick(id,e);return}if(selectionMode){e.stopPropagation();var idx=selectedProducts.indexOf(id);if(idx===-1){selectedProducts.push(id)}else{selectedProducts.splice(idx,1)}updateSelectionUI();renderProducts()}else{showProductModal(id)}}';
    
    html += 'function togglePick(id,e){e.stopPropagation();var idx=userPicks.indexOf(id);if(idx===-1){fetch("/api/picks/"+id,{method:"POST"}).then(function(){userPicks.push(id);renderProducts()})}else{fetch("/api/picks/"+id,{method:"DELETE"}).then(function(){userPicks.splice(idx,1);renderProducts()})}}';
    
    html += 'function updateSelectionUI(){document.getElementById("selectedCount").textContent=selectedProducts.length;var bar=document.getElementById("selectionBar");if(selectedProducts.length>0&&selectionMode){bar.classList.add("visible")}else{bar.classList.remove("visible")}}';
    
    html += 'function showProductModal(id){currentModalProductId=id;var pr=products.find(function(p){return p.id===id});if(!pr)return;var imgUrl=getImageUrl(pr.image_url);document.getElementById("modalImage").src=imgUrl||"";document.getElementById("modalStyle").textContent=pr.style_id;document.getElementById("modalName").textContent=pr.name;var cols=pr.colors||[];var colorName=cols.length===1?cols[0].color_name:(pr.category||"");document.getElementById("modalCategory").textContent=colorName;var totNow=0,totLts=0;cols.forEach(function(c){var aNow=c.available_now||c.available_qty||0;var lts=c.left_to_sell||0;totNow+=aNow;totLts+=lts});var ch="";if(cols.length>1){ch="<table style=\\"width:100%;border-collapse:collapse;font-size:0.875rem\\"><thead><tr style=\\"border-bottom:1px solid #ddd\\"><th style=\\"text-align:left;padding:0.5rem 0;font-weight:600;color:#666\\">Color</th><th style=\\"text-align:right;padding:0.5rem 0;font-weight:600;color:#666;width:80px\\">Avail Now</th><th style=\\"text-align:right;padding:0.5rem 0;font-weight:600;color:#666;width:80px\\">Left to Sell</th></tr></thead><tbody>";cols.forEach(function(c){var aNow=c.available_now||c.available_qty||0;var lts=c.left_to_sell||0;ch+="<tr><td style=\\"padding:0.4rem 0\\">"+c.color_name+"</td><td style=\\"text-align:right;padding:0.4rem 0\\">"+aNow.toLocaleString()+"</td><td style=\\"text-align:right;padding:0.4rem 0;color:#666\\">"+lts.toLocaleString()+"</td></tr>"});ch+="</tbody></table>"}document.getElementById("modalColors").innerHTML=ch;document.getElementById("modalTotal").innerHTML="<span style=\\"margin-right:2rem\\">📦 Now: "+totNow.toLocaleString()+"</span><span>📊 LTS: "+totLts.toLocaleString()+"</span>";document.getElementById("modalNote").value=userNotes[id]||"";document.getElementById("modalPickBtn").style.display="";var isPicked=userPicks.indexOf(id)!==-1;document.getElementById("modalPickBtn").textContent=isPicked?"♥ In My Picks":"♡ Add to My Picks";document.getElementById("modal").classList.add("active");loadSalesHistory(pr.style_id)}';
    
    html += 'function loadSalesHistory(styleId){document.getElementById("salesHistoryLoading").textContent="(loading...)";document.getElementById("salesHistorySummary").innerHTML="";document.getElementById("salesHistoryList").innerHTML="<div style=\\"color:#666;padding:0.5rem\\">Loading sales history...</div>";fetch("/api/sales-history/"+encodeURIComponent(styleId)).then(function(r){return r.json()}).then(function(d){document.getElementById("salesHistoryLoading").textContent="";if(!d.success){document.getElementById("salesHistoryList").innerHTML="<div style=\\"color:#999;padding:0.5rem\\">Unable to load sales history"+(d.error?": "+d.error:"")+"</div>";return}var sum=d.summary;var invDollars=sum.totalInvoicedDollars?"$"+sum.totalInvoicedDollars.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}):"";var openDollars=sum.totalOpenOrdersDollars?"$"+sum.totalOpenOrdersDollars.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}):"";var poDollars=sum.totalPODollars?"$"+sum.totalPODollars.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}):"";document.getElementById("salesHistorySummary").innerHTML="<div style=\\"padding:0.5rem 0.75rem;background:#e8f5e9;border-radius:4px\\"><div style=\\"font-weight:bold;color:#2e7d32\\">"+sum.totalInvoiced.toLocaleString()+"</div><div style=\\"font-size:0.75rem;color:#666\\">Units Invoiced ("+sum.invoiceCount+")</div>"+(invDollars?"<div style=\\"font-size:0.8rem;color:#2e7d32;margin-top:0.25rem\\">"+invDollars+"</div>":"")+"</div><div style=\\"padding:0.5rem 0.75rem;background:#fff3e0;border-radius:4px\\"><div style=\\"font-weight:bold;color:#ef6c00\\">"+sum.totalOpenOrders.toLocaleString()+"</div><div style=\\"font-size:0.75rem;color:#666\\">Open SO ("+sum.openOrderCount+")</div>"+(openDollars?"<div style=\\"font-size:0.8rem;color:#ef6c00;margin-top:0.25rem\\">"+openDollars+"</div>":"")+"</div><div style=\\"padding:0.5rem 0.75rem;background:#e3f2fd;border-radius:4px\\"><div style=\\"font-weight:bold;color:#1565c0\\">"+(sum.totalPO||0).toLocaleString()+"</div><div style=\\"font-size:0.75rem;color:#666\\">Import PO ("+(sum.poCount||0)+")</div>"+(poDollars?"<div style=\\"font-size:0.8rem;color:#1565c0;margin-top:0.25rem\\">"+poDollars+"</div>":"")+"</div>";if(d.history.length===0){document.getElementById("salesHistoryList").innerHTML="<div style=\\"color:#999;padding:0.5rem\\">No sales history found for this style</div>";return}var h="<table style=\\"width:100%;border-collapse:collapse;font-size:0.8rem\\"><thead><tr style=\\"background:#f5f5f5\\"><th style=\\"text-align:left;padding:0.4rem\\">Date</th><th style=\\"text-align:left;padding:0.4rem\\">Vendor/Customer</th><th style=\\"text-align:left;padding:0.4rem\\">Type</th><th style=\\"text-align:right;padding:0.4rem\\">Qty</th><th style=\\"text-align:right;padding:0.4rem\\">Amount</th></tr></thead><tbody>";d.history.forEach(function(rec){var typeLabel;var st=(rec.status||"").toLowerCase();if(rec.type==="purchaseorder"){typeLabel="<span style=\\"color:#1565c0\\">PO "+rec.documentNumber+"</span>"}else if(st==="invoiced"||st==="closed"||st==="fulfilled"){typeLabel="<span style=\\"color:#2e7d32\\">INV "+rec.documentNumber+"</span>"}else{typeLabel="<span style=\\"color:#ef6c00\\">SO "+rec.documentNumber+" (Open)</span>"}var dt=new Date(rec.date).toLocaleDateString();var amt=rec.amount?"$"+rec.amount.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}):"-";h+="<tr style=\\"border-bottom:1px solid #eee\\"><td style=\\"padding:0.4rem\\">"+dt+"</td><td style=\\"padding:0.4rem\\">"+rec.customerName+"</td><td style=\\"padding:0.4rem\\">"+typeLabel+"</td><td style=\\"padding:0.4rem;text-align:right\\">"+rec.quantity.toLocaleString()+"</td><td style=\\"padding:0.4rem;text-align:right\\">"+amt+"</td></tr>"});h+="</tbody></table>";document.getElementById("salesHistoryList").innerHTML=h}).catch(function(err){document.getElementById("salesHistoryLoading").textContent="";document.getElementById("salesHistoryList").innerHTML="<div style=\\"color:#999;padding:0.5rem\\">Error loading sales history: "+err.message+"</div>"})}';
    html += 'function updateSelectionUI(){document.getElementById("selectedCount").textContent=selectedProducts.length;var bar=document.getElementById("selectionBar");if(selectedProducts.length>0&&selectionMode){bar.classList.add("visible")}else{bar.classList.remove("visible")}}';
    
    // Helper to group products by base style
    html += 'function groupProductsByStyle(prods){var groups={};prods.forEach(function(p){var base=p.style_id.split("-")[0];if(!groups[base]){groups[base]={baseStyle:base,name:p.name.replace(p.style_id,base),category:p.category,variants:[],firstSeenImport:p.first_seen_import}}groups[base].variants.push(p)});return Object.values(groups)}';
    
    html += 'function renderProducts(){var s=document.getElementById("searchInput").value.toLowerCase().trim();var searchWords=s?s.split(/\\s+/):[];var minQ=parseInt(document.getElementById("minQty").value)||1;var maxQ=parseInt(document.getElementById("maxQty").value)||999999999;var f=allProducts.filter(function(p){var searchText=p.style_id.toLowerCase()+" "+p.name.toLowerCase()+" "+(p.ai_tags||"").toLowerCase();var ms=searchWords.length===0||searchWords.every(function(word){return searchText.indexOf(word)!==-1});var mc=currentFilter==="all"||p.category===currentFilter;var colorNames=(p.colors||[]).map(function(c){return c.color_name});var mcolor=!colorFilter||colorNames.indexOf(colorFilter)!==-1;var tot=0;(p.colors||[]).forEach(function(c){tot+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))});var mq=tot>=minQ&&tot<=maxQ;var msp=true;if(specialFilter==="new"){msp=p.first_seen_import===lastImportId}else if(specialFilter==="picks"){msp=userPicks.indexOf(p.id)!==-1}else if(specialFilter==="notes"){msp=!!userNotes[p.id]}return ms&&mc&&mcolor&&mq&&msp});f.sort(function(a,b){var ta=0,tb=0;(a.colors||[]).forEach(function(c){ta+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))});(b.colors||[]).forEach(function(c){tb+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))});if(currentSort==="qty-high")return tb-ta;if(currentSort==="qty-low")return ta-tb;if(currentSort==="name-desc")return b.name.localeCompare(a.name);if(currentSort==="newest")return(b.first_seen_import||0)-(a.first_seen_import||0);return a.name.localeCompare(b.name)});products=f;if(f.length===0){document.getElementById("productGrid").innerHTML="";document.getElementById("emptyState").classList.remove("hidden")}else{document.getElementById("emptyState").classList.add("hidden");var h="";var isListView=currentSize==="list";if(groupByStyle){var grouped=groupProductsByStyle(f);var shownGroups=0;grouped.sort(function(a,b){var ta=0,tb=0;a.variants.forEach(function(v){(v.colors||[]).forEach(function(c){ta+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))})});b.variants.forEach(function(v){(v.colors||[]).forEach(function(c){tb+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))})});if(currentSort==="qty-high")return tb-ta;if(currentSort==="qty-low")return ta-tb;if(currentSort==="name-desc")return b.name.localeCompare(a.name);return a.name.localeCompare(b.name)});grouped.forEach(function(grp,idx){var totNow=0,totLts=0;grp.variants.forEach(function(v){(v.colors||[]).forEach(function(c){totNow+=(c.available_now||c.available_qty||0);totLts+=(c.left_to_sell||0)})});var primaryQty=qtyMode==="left_to_sell"?totLts:totNow;var secondaryQty=qtyMode==="left_to_sell"?totNow:totLts;var secondaryLabel=qtyMode==="left_to_sell"?"Now":"LTS";var imgUrl=getImageUrl(grp.variants[0].image_url);var im=imgUrl?"<img src=\\""+imgUrl+"\\" onerror=\\"this.parentElement.innerHTML=\'No Image\'\\">":"No Image";var uniqueColors={};grp.variants.forEach(function(v){(v.colors||[]).forEach(function(c){var cQty=qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0);if(cQty>0){uniqueColors[c.color_name]=true}})});var colorCount=Object.keys(uniqueColors).length||1;if(minColorsFilter>0&&colorCount<minColorsFilter)return;shownGroups++;var variantIds=grp.variants.map(function(v){return v.id}).join(",");var selModeClass=selectionMode?"selection-mode":"";h+="<div class=\\"product-card grouped "+selModeClass+"\\" data-idx=\\""+idx+"\\" data-variants=\\""+variantIds+"\\" onclick=\\"handleGroupClick(\'"+grp.baseStyle+"\',event)\\"><div class=\\"color-count-badge\\">"+colorCount+" colors</div><div class=\\"product-image\\">"+im+"</div><div class=\\"product-info\\"><div class=\\"product-style\\">"+grp.baseStyle+"</div><div class=\\"product-name\\">"+grp.name+"</div><div class=\\"total-row\\"><span>Total</span><span>"+primaryQty.toLocaleString()+"</span></div><div style=\\"font-size:0.75rem;color:#999;text-align:right\\">("+secondaryLabel+": "+secondaryQty.toLocaleString()+")</div></div></div>"});document.getElementById("totalStyles").textContent=shownGroups+" groups"}else{f.forEach(function(pr,idx){var cols=pr.colors||[];var totNow=0,totLts=0;cols.forEach(function(c){totNow+=(c.available_now||c.available_qty||0);totLts+=(c.left_to_sell||0)});var primaryQty=qtyMode==="left_to_sell"?totLts:totNow;var secondaryQty=qtyMode==="left_to_sell"?totNow:totLts;var secondaryLabel=qtyMode==="left_to_sell"?"Now":"LTS";var ch="";if(!isListView){var mx=Math.min(cols.length,3);for(var d=0;d<mx;d++){var cq=qtyMode==="left_to_sell"?(cols[d].left_to_sell||0):(cols[d].available_now||cols[d].available_qty||0);ch+="<div class=\\"color-row\\"><span>"+cols[d].color_name+"</span><span>"+cq.toLocaleString()+"</span></div>"}if(cols.length>3)ch+="<div class=\\"color-row\\" style=\\"color:#999\\">+"+(cols.length-3)+" more</div>"}var listCols="";if(isListView){cols.slice(0,5).forEach(function(c){var cq=qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0);listCols+=c.color_name+": "+cq.toLocaleString()+"; "});if(cols.length>5)listCols+="+"+(cols.length-5)+" more"}var imgUrl=getImageUrl(pr.image_url);var im=imgUrl?"<img src=\\""+imgUrl+"\\" onerror=\\"this.parentElement.innerHTML=\'No Image\'\\">":"No Image";var sel=selectedProducts.indexOf(pr.id)!==-1?"selected":"";var selModeClass=selectionMode?"selection-mode":"";var listClass=isListView?"list-view":"";var isPicked=userPicks.indexOf(pr.id)!==-1;var hasNote=!!userNotes[pr.id];h+="<div class=\\"product-card "+sel+" "+selModeClass+" "+listClass+"\\" data-idx=\\""+idx+"\\" onclick=\\"handleCardClick("+pr.id+",event)\\"><div class=\\"select-badge\\">✓</div><div class=\\"pick-badge "+(isPicked?"active":"")+"\\">"+(isPicked?"♥":"♡")+"</div><div class=\\"note-badge "+(hasNote?"has-note":"")+"\\">📝</div><div class=\\"product-image\\">"+im+"</div><div class=\\"product-info\\"><div class=\\"product-style\\">"+pr.style_id+"</div><div class=\\"product-name\\">"+pr.name+"</div>"+(isListView?"<div class=\\"list-colors\\">"+listCols+"</div>":"<div class=\\"color-list\\">"+ch+"</div>")+"<div class=\\"total-row\\"><span>Total</span><span>"+primaryQty.toLocaleString()+"</span></div><div style=\\"font-size:0.75rem;color:#999;text-align:right\\">("+secondaryLabel+": "+secondaryQty.toLocaleString()+")</div></div></div>"});document.getElementById("totalStyles").textContent=f.length}document.getElementById("productGrid").innerHTML=h}var totalNow=0;var totalLts=0;f.forEach(function(p){(p.colors||[]).forEach(function(c){totalNow+=(c.available_now||c.available_qty||0);totalLts+=(c.left_to_sell||0)})});document.getElementById("totalAvailNow").textContent=totalNow.toLocaleString();document.getElementById("totalLeftToSell").textContent=totalLts.toLocaleString();focusedIndex=-1}';
    
    // Handle click on grouped card - show group modal
    html += 'function handleGroupClick(baseStyle,e){if(e.target.classList.contains("pick-badge"))return;var variants=allProducts.filter(function(p){return p.style_id.split("-")[0]===baseStyle});showGroupModal(baseStyle,variants)}';
    
    // Show group modal with all color variants
    html += 'function showGroupModal(baseStyle,variants){var totNow=0,totLts=0;variants.forEach(function(v){(v.colors||[]).forEach(function(c){totNow+=(c.available_now||c.available_qty||0);totLts+=(c.left_to_sell||0)})});document.getElementById("modalStyle").textContent=baseStyle;document.getElementById("modalName").textContent=variants[0].name.replace(variants[0].style_id,baseStyle);document.getElementById("modalCategory").textContent=variants[0].category||"";var imgUrl=getImageUrl(variants[0].image_url);document.getElementById("modalImage").src=imgUrl||"";var swatchHtml="<div style=\\"display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:1rem\\">";variants.forEach(function(v,i){var vImg=getImageUrl(v.image_url);var colorCode=v.style_id.split("-")[1]||"";var colorName=(v.colors&&v.colors[0])?v.colors[0].color_name:colorCode;swatchHtml+="<div class=\\"color-swatch"+(i===0?" active":"")+"\\" data-idx=\\""+i+"\\" style=\\"padding:0.5rem 0.75rem;border:2px solid "+(i===0?"#1a3b5d":"#ddd")+";border-radius:4px;cursor:pointer;font-size:0.75rem;background:"+(i===0?"#f0f4f8":"#fff")+"\\" onclick=\\"switchVariantImage("+i+",\'"+baseStyle+"\')\\">"+colorName+"</div>"});swatchHtml+="</div>";var ch="<table style=\\"width:100%;border-collapse:collapse;font-size:0.875rem\\"><thead><tr style=\\"border-bottom:1px solid #ddd\\"><th style=\\"text-align:left;padding:0.5rem 0;font-weight:600;color:#666\\">Color Variant</th><th style=\\"text-align:right;padding:0.5rem 0;font-weight:600;color:#666;width:80px\\">Avail Now</th><th style=\\"text-align:right;padding:0.5rem 0;font-weight:600;color:#666;width:80px\\">Left to Sell</th></tr></thead><tbody>";variants.forEach(function(v){var vNow=0,vLts=0;(v.colors||[]).forEach(function(c){vNow+=(c.available_now||c.available_qty||0);vLts+=(c.left_to_sell||0)});var colorName=(v.colors&&v.colors[0])?v.colors[0].color_name:v.style_id;ch+="<tr><td style=\\"padding:0.4rem 0\\">"+colorName+"</td><td style=\\"text-align:right;padding:0.4rem 0\\">"+vNow.toLocaleString()+"</td><td style=\\"text-align:right;padding:0.4rem 0;color:#666\\">"+vLts.toLocaleString()+"</td></tr>"});ch+="</tbody></table>";document.getElementById("modalColors").innerHTML=swatchHtml+ch;document.getElementById("modalTotal").innerHTML="<span style=\\"margin-right:2rem\\">📦 Now: "+totNow.toLocaleString()+"</span><span>📊 LTS: "+totLts.toLocaleString()+"</span>";document.getElementById("modalNote").value="";document.getElementById("modalPickBtn").style.display="none";currentModalProductId=null;window.currentGroupVariants=variants;document.getElementById("modal").classList.add("active");loadSalesHistory(baseStyle)}';
    
    // Switch image when clicking color swatch
    html += 'function switchVariantImage(idx,baseStyle){var variants=window.currentGroupVariants||allProducts.filter(function(p){return p.style_id.split("-")[0]===baseStyle});if(variants[idx]){var imgUrl=getImageUrl(variants[idx].image_url);document.getElementById("modalImage").src=imgUrl||"";document.querySelectorAll(".color-swatch").forEach(function(sw,i){sw.style.border=i===idx?"2px solid #1a3b5d":"2px solid #ddd";sw.style.background=i===idx?"#f0f4f8":"#fff"})}}';
    
    
    html += 'document.getElementById("searchInput").addEventListener("input",renderProducts);';
    html += 'document.getElementById("clearSearchBtn").addEventListener("click",function(){document.getElementById("searchInput").value="";renderProducts()});';
    html += 'document.getElementById("colorFilterBtn").addEventListener("click",function(e){e.stopPropagation();document.getElementById("colorDropdown").classList.toggle("hidden")});';
    html += 'document.getElementById("clearColorBtn").addEventListener("click",function(){colorFilter=null;document.getElementById("colorFilterBtn").textContent="Color: All ▼";document.getElementById("clearColorBtn").classList.add("hidden");renderProducts()});';
    html += 'document.addEventListener("click",function(e){if(!e.target.closest("#colorDropdown")&&!e.target.closest("#colorFilterBtn")){document.getElementById("colorDropdown").classList.add("hidden")}});';
    html += 'document.getElementById("minQty").addEventListener("input",renderProducts);';
    html += 'document.getElementById("maxQty").addEventListener("input",renderProducts);';
    html += 'document.getElementById("resetQtyBtn").addEventListener("click",function(){document.getElementById("minQty").value="";document.getElementById("maxQty").value="";renderProducts()});';
    
    html += 'document.getElementById("clearSelectionBtn").addEventListener("click",function(){selectedProducts=[];updateSelectionUI();renderProducts()});';
    
    html += 'document.getElementById("shareSelectionBtn").addEventListener("click",function(){document.getElementById("shareModal").classList.add("active");document.getElementById("shareResult").classList.add("hidden");document.getElementById("shareForm").classList.remove("hidden");document.getElementById("selectionName").value=""});';
    html += 'document.getElementById("cancelShareBtn").addEventListener("click",function(){document.getElementById("shareModal").classList.remove("active")});';
    html += 'document.getElementById("closeShareModalBtn").addEventListener("click",function(){document.getElementById("shareModal").classList.remove("active")});';
    
    html += 'var currentShareUrl="";';
    html += 'document.getElementById("createShareBtn").addEventListener("click",function(){var name=document.getElementById("selectionName").value||"Product Selection";fetch("/api/selections",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({productIds:selectedProducts,name:name,shareType:"link"})}).then(function(r){return r.json()}).then(function(d){if(d.success){currentShareId=d.shareId;currentShareUrl=window.location.origin+"/share/"+d.shareId;document.getElementById("shareNameDisplay").textContent=name+" • "+selectedProducts.length+" items";document.getElementById("pdfLink").href="/api/selections/"+d.shareId+"/pdf";document.getElementById("shareForm").classList.add("hidden");document.getElementById("shareResult").classList.remove("hidden");loadShares()}else{alert(d.error)}})});';
    
    html += 'document.getElementById("copyLinkBtn").addEventListener("click",function(){navigator.clipboard.writeText(currentShareUrl).then(function(){var btn=document.getElementById("copyLinkBtn");btn.textContent="✓ Copied!";setTimeout(function(){btn.textContent="🔗 Copy Link"},2000)})});';
    
    html += 'document.getElementById("emailLinkBtn").addEventListener("click",function(){var name=document.getElementById("selectionName").value||"Product Selection";var subject=encodeURIComponent(name+" - Mark Edwards Apparel");var body=encodeURIComponent("Here is the product selection I wanted to share with you:\\n\\n"+currentShareUrl);window.location.href="mailto:?subject="+subject+"&body="+body});';
    
    html += 'document.getElementById("textLinkBtn").addEventListener("click",function(){var name=document.getElementById("selectionName").value||"Product Selection";var body=encodeURIComponent(name+"\\n"+currentShareUrl);window.location.href="sms:?body="+body});';
    
    // Record PDF download
    html += 'document.getElementById("pdfLink").addEventListener("click",function(){if(currentShareId){fetch("/api/selections/"+currentShareId+"/record-pdf",{method:"POST"}).then(function(){loadShares()})}});';
    
    html += 'document.getElementById("csvFile").addEventListener("change",function(e){var f=e.target.files[0];if(!f)return;var fd=new FormData();fd.append("file",f);document.getElementById("importStatus").innerHTML="Importing...";fetch("/api/import",{method:"POST",body:fd}).then(function(r){return r.json()}).then(function(d){document.getElementById("importStatus").innerHTML=d.success?"<span class=success>Imported "+d.imported+" products"+(d.newArrivals?" ("+d.newArrivals+" new)":"")+"</span>":"<span class=error>"+d.error+"</span>";loadProducts();loadHistory();loadDataFreshness()})});';
    
    // Sales CSV import handler
    html += 'document.getElementById("salesCsvFile").addEventListener("change",function(e){var f=e.target.files[0];if(!f)return;var fd=new FormData();fd.append("file",f);document.getElementById("salesImportStatus").innerHTML="<span style=\\"color:#666\\">Importing sales data... This may take a moment for large files.</span>";fetch("/api/import-sales",{method:"POST",body:fd}).then(function(r){return r.json()}).then(function(d){if(d.success){document.getElementById("salesImportStatus").innerHTML="<span class=\\"success\\">✓ Imported "+d.imported.toLocaleString()+" sales records"+(d.errors?" ("+d.errors+" errors)":"")+"</span>";loadSalesStats()}else{document.getElementById("salesImportStatus").innerHTML="<span class=\\"error\\">"+d.error+"</span>"}}).catch(function(e){document.getElementById("salesImportStatus").innerHTML="<span class=\\"error\\">Error: "+e.message+"</span>"})});';
    html += 'function loadSalesStats(){fetch("/api/sales-stats").then(function(r){return r.json()}).then(function(d){if(d.success){var h="<div class=\\"status-box\\"><div class=\\"status-item\\"><span class=\\"status-label\\">Total Records: </span><span class=\\"status-value\\">"+d.totalRecords.toLocaleString()+"</span></div><div class=\\"status-item\\"><span class=\\"status-label\\">Sales Orders: </span><span class=\\"status-value\\">"+d.salesOrders.toLocaleString()+"</span></div><div class=\\"status-item\\"><span class=\\"status-label\\">Purchase Orders: </span><span class=\\"status-value\\">"+d.purchaseOrders.toLocaleString()+"</span></div><div class=\\"status-item\\"><span class=\\"status-label\\">Unique Styles: </span><span class=\\"status-value\\">"+d.uniqueStyles.toLocaleString()+"</span></div></div>";document.getElementById("salesDataStats").innerHTML=h}}).catch(function(){})}';
    
    html += 'document.getElementById("clearBtn").addEventListener("click",function(){if(!confirm("Delete all products?"))return;fetch("/api/products/clear",{method:"POST"}).then(function(){loadProducts()})});';
    
    html += 'function loadUsers(){fetch("/api/users").then(function(r){return r.json()}).then(function(u){var h="";u.forEach(function(x){h+="<tr><td>"+x.username+"</td><td>"+x.role+"</td><td><button class=\\"btn btn-danger\\" onclick=\\"deleteUser("+x.id+")\\">Delete</button></td></tr>"});document.getElementById("usersTable").innerHTML=h})}';
    html += 'document.getElementById("addUserBtn").addEventListener("click",function(){var u=document.getElementById("newUser").value;var p=document.getElementById("newPass").value;if(!u||!p){alert("Enter username and password");return}fetch("/api/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p,role:document.getElementById("newRole").value})}).then(function(){document.getElementById("newUser").value="";document.getElementById("newPass").value="";loadUsers()})});';
    html += 'function deleteUser(id){if(!confirm("Delete user?"))return;fetch("/api/users/"+id,{method:"DELETE"}).then(function(){loadUsers()})}';
    
    // System Health functions
    html += 'function loadSystemHealth(){fetch("/api/system-health").then(function(r){return r.json()}).then(function(d){if(!d.success){document.getElementById("systemHealthContent").innerHTML="<p class=\\"error\\">Error loading system health</p>";return}var h="<div class=\\"system-health-grid\\">";h+="<div class=\\"health-card\\"><h4>📊 Database</h4><div class=\\"health-stats\\">";h+="<div class=\\"health-row\\"><span>Total Size:</span><strong>"+d.database.totalSize+"</strong></div>";h+="<div class=\\"health-row\\"><span>Products:</span><strong>"+d.database.tables.products.toLocaleString()+"</strong></div>";h+="<div class=\\"health-row\\"><span>Color Variants:</span><strong>"+d.database.tables.product_colors.toLocaleString()+"</strong></div>";h+="<div class=\\"health-row\\"><span>Users:</span><strong>"+d.database.tables.users+"</strong></div>";h+="<div class=\\"health-row\\"><span>Shares Created:</span><strong>"+d.database.tables.selections+"</strong></div>";h+="<div class=\\"health-row\\"><span>User Picks:</span><strong>"+d.database.tables.user_picks+"</strong></div>";h+="<div class=\\"health-row\\"><span>User Notes:</span><strong>"+d.database.tables.user_notes+"</strong></div>";h+="</div></div>";h+="<div class=\\"health-card\\"><h4>🤖 AI Analysis</h4><div class=\\"health-stats\\">";h+="<div class=\\"health-row\\"><span>Products Analyzed:</span><strong>"+d.database.productsWithAI.toLocaleString()+"</strong></div>";h+="<div class=\\"health-row\\"><span>Pending Analysis:</span><strong>"+d.database.productsWithoutAI.toLocaleString()+"</strong></div>";var aiPct=d.database.tables.products>0?Math.round(d.database.productsWithAI/d.database.tables.products*100):0;h+="<div class=\\"health-row\\"><span>Coverage:</span><strong>"+aiPct+"%</strong></div>";h+="<div class=\\"health-row\\"><span>Anthropic API:</span><strong class=\\"status-"+(d.apiStatus.anthropicConfigured?"ok":"warn")+"\\">"+(d.apiStatus.anthropicConfigured?"✓ Configured":"✗ Not Set")+"</strong></div>";h+="</div></div>";h+="<div class=\\"health-card\\"><h4>🔗 Integrations</h4><div class=\\"health-stats\\">";h+="<div class=\\"health-row\\"><span>Zoho Configured:</span><strong class=\\"status-"+(d.apiStatus.zohoConfigured?"ok":"warn")+"\\">"+(d.apiStatus.zohoConfigured?"✓ Yes":"✗ No")+"</strong></div>";h+="<div class=\\"health-row\\"><span>Zoho Connected:</span><strong class=\\"status-"+(d.apiStatus.zohoConnected?"ok":"warn")+"\\">"+(d.apiStatus.zohoConnected?"✓ Yes":"✗ No")+"</strong></div>";h+="<div class=\\"health-row\\"><span>Last Sync:</span><strong>"+(d.activity.lastSuccessfulSync?new Date(d.activity.lastSuccessfulSync).toLocaleDateString():"Never")+"</strong></div>";h+="<div class=\\"health-row\\"><span>Last Sync Records:</span><strong>"+(d.activity.lastSyncRecords||"-")+"</strong></div>";h+="</div></div>";h+="<div class=\\"health-card\\"><h4>⚡ Server</h4><div class=\\"health-stats\\">";h+="<div class=\\"health-row\\"><span>Uptime:</span><strong>"+d.server.uptime+"</strong></div>";h+="<div class=\\"health-row\\"><span>Memory Used:</span><strong>"+d.server.memoryUsed+"</strong></div>";h+="<div class=\\"health-row\\"><span>Memory Total:</span><strong>"+d.server.memoryTotal+"</strong></div>";h+="<div class=\\"health-row\\"><span>Node.js:</span><strong>"+d.server.nodeVersion+"</strong></div>";h+="<div class=\\"health-row\\"><span>Platform:</span><strong>"+d.server.platform+"</strong></div>";h+="</div></div>";h+="<div class=\\"health-card\\"><h4>📈 Activity (7 days)</h4><div class=\\"health-stats\\">";h+="<div class=\\"health-row\\"><span>Users with Picks:</span><strong>"+d.activity.activeUsers+"</strong></div>";h+="<div class=\\"health-row\\"><span>Shares Created:</span><strong>"+d.activity.sharesLast7Days+"</strong></div>";h+="<div class=\\"health-row\\"><span>Data Syncs:</span><strong>"+d.activity.syncsLast7Days+"</strong></div>";h+="</div></div>";h+="</div>";h+="<p style=\\"margin-top:1rem;font-size:0.8rem;color:#999\\">Last checked: "+new Date(d.timestamp).toLocaleString()+"</p>";document.getElementById("systemHealthContent").innerHTML=h}).catch(function(e){document.getElementById("systemHealthContent").innerHTML="<p class=\\"error\\">Error: "+e.message+"</p>"})}';
    html += 'document.getElementById("refreshSystemBtn").addEventListener("click",loadSystemHealth);';
    
    html += 'function loadHistory(){fetch("/api/zoho/sync-history").then(function(r){return r.json()}).then(function(h){var html="";h.forEach(function(x){html+="<tr><td>"+new Date(x.created_at).toLocaleString()+"</td><td>"+x.sync_type+"</td><td>"+x.status+"</td><td>"+(x.records_synced||"-")+"</td><td>"+(x.error_message||"-")+"</td></tr>"});document.getElementById("historyTable").innerHTML=html})}';
    
    // AI Analysis functions
    html += 'function loadAiStatus(){fetch("/api/ai-status").then(function(r){return r.json()}).then(function(d){var st=document.getElementById("aiStatusText");if(d.configured){st.textContent="Configured";st.className="status-value connected"}else{st.textContent="API Key Not Set";st.className="status-value disconnected"}document.getElementById("aiAnalyzedCount").textContent=d.analyzed+" / "+d.total;document.getElementById("aiRemainingCount").textContent=d.remaining})}';
    
    html += 'document.getElementById("runAiBtn").addEventListener("click",function(){var btn=this;btn.disabled=true;btn.textContent="Analyzing...";document.getElementById("aiMessage").innerHTML="<span style=\\"color:#666\\">Processing images with Claude Vision...</span>";fetch("/api/ai-analyze",{method:"POST"}).then(function(r){return r.json()}).then(function(d){btn.disabled=false;btn.textContent="Analyze Next 100 Products";if(d.success){document.getElementById("aiMessage").innerHTML="<span class=\\"success\\">"+d.message+". "+d.remaining+" remaining.</span>"}else{document.getElementById("aiMessage").innerHTML="<span class=\\"error\\">"+d.error+"</span>"}loadAiStatus();loadProducts()})});';
    
    // Analyze All button - runs in a loop
    html += 'var aiRunning=false;document.getElementById("runAllAiBtn").addEventListener("click",function(){aiRunning=true;document.getElementById("runAllAiBtn").style.display="none";document.getElementById("stopAiBtn").style.display="inline-block";document.getElementById("runAiBtn").disabled=true;runAiBatch()});';
    html += 'document.getElementById("stopAiBtn").addEventListener("click",function(){aiRunning=false;document.getElementById("stopAiBtn").style.display="none";document.getElementById("runAllAiBtn").style.display="inline-block";document.getElementById("runAiBtn").disabled=false;document.getElementById("aiMessage").innerHTML="<span style=\\"color:#666\\">Stopped. You can resume anytime.</span>"});';
    html += 'function runAiBatch(){if(!aiRunning)return;document.getElementById("aiMessage").innerHTML="<span style=\\"color:#666\\">Processing batch... (click Stop to pause)</span>";fetch("/api/ai-analyze",{method:"POST"}).then(function(r){return r.json()}).then(function(d){loadAiStatus();if(d.success&&d.remaining>0&&aiRunning){document.getElementById("aiMessage").innerHTML="<span class=\\"success\\">"+d.message+". "+d.remaining+" remaining. Continuing...</span>";setTimeout(runAiBatch,1000)}else if(d.remaining===0){aiRunning=false;document.getElementById("stopAiBtn").style.display="none";document.getElementById("runAllAiBtn").style.display="inline-block";document.getElementById("runAiBtn").disabled=false;document.getElementById("aiMessage").innerHTML="<span class=\\"success\\">All products analyzed!</span>";loadProducts()}else if(!d.success){aiRunning=false;document.getElementById("stopAiBtn").style.display="none";document.getElementById("runAllAiBtn").style.display="inline-block";document.getElementById("runAiBtn").disabled=false;document.getElementById("aiMessage").innerHTML="<span class=\\"error\\">"+d.error+"</span>"}})}';
    
    html += 'document.getElementById("modalClose").addEventListener("click",function(){document.getElementById("modal").classList.remove("active")});';
    html += 'document.getElementById("modal").addEventListener("click",function(e){if(e.target.id==="modal")document.getElementById("modal").classList.remove("active")});';
    
    // Modal pick button
    html += 'document.getElementById("modalPickBtn").addEventListener("click",function(){if(currentModalProductId){togglePick(currentModalProductId,{stopPropagation:function(){}});var isPicked=userPicks.indexOf(currentModalProductId)!==-1;this.textContent=isPicked?"♥ In My Picks":"♡ Add to My Picks"}});';
    
    // Save note button
    html += 'document.getElementById("saveNoteBtn").addEventListener("click",function(){if(currentModalProductId){var note=document.getElementById("modalNote").value;fetch("/api/notes/"+currentModalProductId,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({note:note})}).then(function(){if(note.trim()){userNotes[currentModalProductId]=note}else{delete userNotes[currentModalProductId]}renderProducts()})}});';
    
    // Keyboard navigation
    html += 'document.addEventListener("keydown",function(e){if(document.getElementById("modal").classList.contains("active")){if(e.key==="Escape"){document.getElementById("modal").classList.remove("active")}return}if(document.getElementById("shareModal").classList.contains("active")){if(e.key==="Escape"){document.getElementById("shareModal").classList.remove("active")}return}if(document.activeElement.tagName==="INPUT"||document.activeElement.tagName==="TEXTAREA")return;var cards=document.querySelectorAll(".product-card");if(cards.length===0)return;if(e.key==="ArrowRight"||e.key==="ArrowDown"){e.preventDefault();focusedIndex=Math.min(focusedIndex+1,cards.length-1);updateFocus(cards)}else if(e.key==="ArrowLeft"||e.key==="ArrowUp"){e.preventDefault();focusedIndex=Math.max(focusedIndex-1,0);updateFocus(cards)}else if(e.key==="Enter"&&focusedIndex>=0){e.preventDefault();var id=parseInt(products[focusedIndex].id);if(selectionMode){var idx=selectedProducts.indexOf(id);if(idx===-1){selectedProducts.push(id)}else{selectedProducts.splice(idx,1)}updateSelectionUI();renderProducts()}else{showProductModal(id)}}else if(e.key===" "&&focusedIndex>=0&&selectionMode){e.preventDefault();var id=parseInt(products[focusedIndex].id);var idx=selectedProducts.indexOf(id);if(idx===-1){selectedProducts.push(id)}else{selectedProducts.splice(idx,1)}updateSelectionUI();renderProducts()}});';
    
    html += 'function updateFocus(cards){cards.forEach(function(c,i){c.classList.toggle("focused",i===focusedIndex)});if(focusedIndex>=0&&cards[focusedIndex]){cards[focusedIndex].scrollIntoView({block:"nearest",behavior:"smooth"})}}';
    
    // Compact header on scroll
    html += 'var lastScrollY=0;var ticking=false;function updateHeaderCompact(){var header=document.querySelector(".header");var stats=document.querySelector(".stats");var viewControls=document.querySelector(".view-controls");var scrollY=window.scrollY;if(scrollY>100){header.classList.add("compact");if(stats)stats.classList.add("compact");if(viewControls)viewControls.classList.add("compact")}else{header.classList.remove("compact");if(stats)stats.classList.remove("compact");if(viewControls)viewControls.classList.remove("compact")}ticking=false}window.addEventListener("scroll",function(){if(!ticking){window.requestAnimationFrame(updateHeaderCompact);ticking=true}});';
    
    html += 'checkSession();';
    html += '</script></body></html>';
    return html;
}

// Background job to refresh sales history cache
async function refreshSalesHistoryCache() {
    console.log('Starting sales history cache refresh...');
    try {
        // Get unique base styles from products
        var stylesResult = await pool.query('SELECT DISTINCT split_part(style_id, \'-\', 1) as base_style FROM products');
        var baseStyles = stylesResult.rows.map(function(r) { return r.base_style; }).filter(function(s) { return s; });
        
        console.log('Found', baseStyles.length, 'unique base styles to cache');
        
        // Check which ones need refresh (older than 1 hour or missing)
        var staleResult = await pool.query(
            'SELECT base_style FROM sales_history_cache WHERE updated_at > NOW() - INTERVAL \'1 hour\''
        );
        var freshStyles = {};
        staleResult.rows.forEach(function(r) { freshStyles[r.base_style] = true; });
        
        var stylesToRefresh = baseStyles.filter(function(s) { return !freshStyles[s]; });
        console.log(stylesToRefresh.length, 'styles need refresh (no cache or stale)');
        
        // If all styles are fresh, refresh oldest ones anyway (rolling refresh)
        if (stylesToRefresh.length === 0) {
            var oldestResult = await pool.query(
                'SELECT base_style FROM sales_history_cache ORDER BY updated_at ASC LIMIT 20'
            );
            stylesToRefresh = oldestResult.rows.map(function(r) { return r.base_style; });
            console.log('All fresh - refreshing', stylesToRefresh.length, 'oldest cached styles');
        }
        
        // Process up to 20 per run (with 2s delays = conservative API usage)
        var batch = stylesToRefresh.slice(0, 20);
        var refreshed = 0;
        var errors = 0;
        
        for (var i = 0; i < batch.length; i++) {
            try {
                // 2 second delay between requests to stay well under rate limits
                if (i > 0) await new Promise(function(r) { setTimeout(r, 2000); });
                
                // Trigger the sales history endpoint internally
                var response = await fetch('http://localhost:' + PORT + '/api/sales-history/' + encodeURIComponent(batch[i]), {
                    headers: { 'Cookie': 'connect.sid=background' }
                });
                if (response.ok) {
                    refreshed++;
                } else {
                    errors++;
                    console.log('Cache refresh failed for', batch[i], '- status:', response.status);
                }
            } catch (err) {
                errors++;
                console.error('Cache refresh error for', batch[i], err.message);
            }
        }
        
        console.log('Sales history cache refresh complete:', refreshed, 'updated,', errors, 'errors,', (baseStyles.length - stylesToRefresh.length + refreshed), '/', baseStyles.length, 'total cached');
    } catch (err) {
        console.error('Sales history cache refresh error:', err.message);
    }
}

// Start background cache refresh every 30 minutes (reduced to save API calls)
// DISABLED - Switching to CSV import instead of API calls
function startSalesHistoryCacheJob() {
    console.log('Sales history cache job DISABLED - waiting for CSV import feature');
    // Job disabled to conserve API calls
    // Will be replaced with CSV import functionality
    /*
    console.log('Starting sales history cache job (every 30 minutes, 20 styles per run)');
    // Run 60 seconds after startup
    setTimeout(function() { refreshSalesHistoryCache(); }, 60000);
    // Then every 30 minutes
    setInterval(function() { refreshSalesHistoryCache(); }, 30 * 60 * 1000);
    */
}

initDB().then(function() {
    app.listen(PORT, function() { console.log("Product Catalog running on port " + PORT); });
    setTimeout(function() { startTokenRefreshJob(); }, 5000);
    setTimeout(function() { startSalesHistoryCacheJob(); }, 10000);
});
