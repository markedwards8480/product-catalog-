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
        
        // Get products without AI tags that have images
        var result = await pool.query("SELECT id, style_id, name, image_url FROM products WHERE (ai_tags IS NULL OR ai_tags = '') AND image_url IS NOT NULL AND image_url != '' LIMIT 10");
        
        if (result.rows.length === 0) {
            return res.json({ success: true, message: 'All products already have AI tags', analyzed: 0, remaining: 0 });
        }
        
        var analyzed = 0;
        for (var i = 0; i < result.rows.length; i++) {
            var product = result.rows[i];
            var tags = await analyzeProductImage(product.image_url, product.name);
            if (tags) {
                await pool.query('UPDATE products SET ai_tags = $1 WHERE id = $2', [tags, product.id]);
                analyzed++;
            }
            // Small delay to avoid rate limiting
            await new Promise(function(resolve) { setTimeout(resolve, 500); });
        }
        
        // Check how many remain
        var remaining = await pool.query("SELECT COUNT(*) FROM products WHERE (ai_tags IS NULL OR ai_tags = '') AND image_url IS NOT NULL AND image_url != ''");
        
        res.json({ 
            success: true, 
            message: 'Analyzed ' + analyzed + ' products', 
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

// Sales History API - Get invoices and sales orders for a style from Zoho Books
app.get('/api/sales-history/:styleId', requireAuth, async function(req, res) {
    try {
        var styleId = req.params.styleId;
        var orgId = process.env.ZOHO_BOOKS_ORG_ID || process.env.ZOHO_ORGANIZATION_ID || '677681121';
        
        console.log('Sales History Request - Style:', styleId, 'Org:', orgId);
        
        if (!zohoAccessToken) {
            var tokenResult = await refreshZohoToken();
            if (!tokenResult.success) {
                console.log('Token refresh failed:', tokenResult.error);
                return res.json({ success: false, error: 'Failed to get Zoho token: ' + tokenResult.error });
            }
        }
        
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
        
        // Sort by date descending
        results.sort(function(a, b) {
            return new Date(b.date) - new Date(a.date);
        });
        
        // Calculate summary
        var totalInvoicedQty = 0;
        var totalInvoicedDollars = 0;
        var totalOpenOrdersQty = 0;
        var totalOpenOrdersDollars = 0;
        var invoiceCount = 0;
        var openOrderCount = 0;
        
        for (var n = 0; n < results.length; n++) {
            if (results[n].type === 'invoice') {
                totalInvoicedQty += results[n].quantity;
                totalInvoicedDollars += results[n].amount || 0;
                invoiceCount++;
            } else if (results[n].isOpen) {
                totalOpenOrdersQty += results[n].quantity;
                totalOpenOrdersDollars += results[n].amount || 0;
                openOrderCount++;
            }
        }
        
        console.log('Sales History Results:', results.length, 'records found');
        
        res.json({
            success: true,
            styleId: styleId,
            summary: {
                totalInvoiced: totalInvoicedQty,
                totalInvoicedDollars: totalInvoicedDollars,
                invoiceCount: invoiceCount,
                totalOpenOrders: totalOpenOrdersQty,
                totalOpenOrdersDollars: totalOpenOrdersDollars,
                openOrderCount: openOrderCount
            },
            history: results,
            debug: debugInfo
        });
        
    } catch (err) {
        console.error('Sales history error:', err);
        res.status(500).json({ success: false, error: err.message });
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
app.get('/api/users', requireAuth, requireAdmin, async function(req, res) { try { var result = await pool.query('SELECT id, username, role, created_at FROM users ORDER BY created_at'); res.json(result.rows); } catch (err) { res.status(500).json({ error: err.message }); } });
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
    html += '.header{background:white;padding:1rem 2rem;border-bottom:1px solid #ddd;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem}.header h1{font-size:1.25rem}.header-right{display:flex;gap:1rem;align-items:center}';
    html += '.search-box{position:relative}.search-box input{padding:0.5rem 1rem;border:1px solid #ddd;border-radius:4px;width:250px}';
    html += '.ai-search-indicator{position:absolute;top:100%;left:0;font-size:0.7rem;color:#059669;margin-top:0.2rem;white-space:nowrap}.ai-search-indicator.hidden{display:none}';
    html += '.main{max-width:1400px;margin:0 auto;padding:2rem}';
    html += '.admin-panel{background:white;padding:1.5rem;border-radius:8px;margin-bottom:2rem}.admin-panel h2{margin-bottom:1rem}';
    html += '.tabs{display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap}.tab{padding:0.5rem 1rem;border:none;background:#eee;cursor:pointer;border-radius:4px}.tab.active{background:#2c5545;color:white}.tab-content{display:none}.tab-content.active{display:block}';
    html += '.upload-area{border:2px dashed #ddd;padding:2rem;text-align:center;border-radius:4px;margin-bottom:1rem}.upload-area input{display:none}.upload-area label{color:#2c5545;cursor:pointer}';
    html += '.stats{display:flex;gap:2rem;margin-bottom:1rem;padding:1rem;background:white;border-radius:8px;align-items:center;flex-wrap:wrap}.stat-value{font-size:1.5rem;font-weight:bold}.stat-label{color:#666;font-size:0.875rem}';
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
    html += '.modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:none;align-items:center;justify-content:center;z-index:1000}.modal.active{display:flex}.modal-content{background:white;border-radius:8px;max-width:95vw;width:1400px;max-height:95vh;overflow:auto;position:relative}.modal-body{display:flex;min-height:700px}.modal-image{width:65%;background:#f0f0f0;min-height:700px;display:flex;align-items:center;justify-content:center;padding:1.5rem}.modal-image img{max-width:100%;max-height:800px;object-fit:contain}.modal-details{width:35%;padding:2rem}.modal-close{position:absolute;top:1rem;right:1rem;background:white;border:none;font-size:1.5rem;cursor:pointer;border-radius:50%;width:36px;height:36px}';
    html += '.modal-actions{margin-top:1.5rem;padding-top:1rem;border-top:1px solid #eee;display:flex;gap:0.5rem;flex-wrap:wrap}';
    html += '.note-section{margin-top:1rem;padding-top:1rem;border-top:1px solid #eee}.note-section textarea{width:100%;height:80px;margin-top:0.5rem;padding:0.5rem;border:1px solid #ddd;border-radius:4px;font-family:inherit;resize:vertical}';
    html += '.compare-modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:none;align-items:center;justify-content:center;z-index:1001}.compare-modal.active{display:flex}.compare-content{background:white;border-radius:8px;max-width:95vw;width:1000px;max-height:95vh;overflow:auto;padding:2rem}.compare-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1.5rem}.compare-item{text-align:center}.compare-item img{max-width:100%;max-height:250px;object-fit:contain;margin-bottom:1rem}.compare-item h3{font-size:1rem;margin-bottom:0.5rem}.compare-colors{font-size:0.875rem;text-align:left}';
    html += '.compare-bar{position:fixed;bottom:60px;left:0;right:0;background:#1976d2;color:white;padding:0.75rem 2rem;display:flex;justify-content:space-between;align-items:center;z-index:99;transform:translateY(calc(100% + 60px));transition:transform 0.3s}.compare-bar.visible{transform:translateY(0)}.selection-bar.visible ~ .compare-bar.visible{transform:translateY(0)}';
    
    // Help modal styles
    html += '.help-modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:none;align-items:center;justify-content:center;z-index:1002;overflow-y:auto;padding:2rem}.help-modal.active{display:flex}.help-content{background:white;border-radius:12px;max-width:900px;width:95%;max-height:90vh;overflow-y:auto;padding:2rem;position:relative}';
    html += '.help-content h2{margin-bottom:1.5rem;color:#2c5545}.help-sections{display:flex;flex-direction:column;gap:2rem}';
    html += '.help-section{border-bottom:1px solid #eee;padding-bottom:1.5rem}.help-section:last-child{border-bottom:none}.help-section h3{color:#333;margin-bottom:1rem;font-size:1.1rem}';
    html += '.help-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem}.help-card{background:#f8f9fa;border-radius:8px;padding:1.25rem;text-align:center}.help-icon{font-size:2rem;margin-bottom:0.5rem}.help-card h4{margin-bottom:0.5rem;color:#2c5545}.help-card p{font-size:0.875rem;color:#666;margin:0}';
    html += '.help-table{width:100%;border-collapse:collapse}.help-table td{padding:0.75rem;border-bottom:1px solid #eee;vertical-align:top}.help-table tr:last-child td{border-bottom:none}.help-feature{width:180px;white-space:nowrap}';
    html += '.help-steps{display:flex;flex-direction:column;gap:1rem}.help-step{display:flex;align-items:flex-start;gap:1rem}.step-num{width:32px;height:32px;background:#2c5545;color:white;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:bold;flex-shrink:0}.step-content p{margin:0.25rem 0 0;color:#666;font-size:0.875rem}';
    html += '.help-section ul{margin:0.5rem 0 0 1.5rem;color:#666}.help-section ul li{margin-bottom:0.25rem}';
    html += '.faq-item{margin-bottom:1rem;padding:1rem;background:#f8f9fa;border-radius:8px}.faq-item strong{color:#333}.faq-item p{margin:0.5rem 0 0;color:#666;font-size:0.875rem}';
    html += 'kbd{background:#eee;border:1px solid #ccc;border-radius:4px;padding:0.2rem 0.5rem;font-family:monospace;font-size:0.875rem}';
    html += 'table{width:100%;border-collapse:collapse}th,td{padding:0.75rem;text-align:left;border-bottom:1px solid #eee}';
    html += '.add-form{display:flex;gap:0.5rem;margin-top:1rem;flex-wrap:wrap}.add-form input,.add-form select{padding:0.5rem;border:1px solid #ddd;border-radius:4px}';
    html += '.status-box{padding:1rem;background:#f9f9f9;border-radius:4px;margin-bottom:1rem}.status-item{margin-bottom:0.5rem}.status-label{font-weight:500}.status-value{color:#666}.status-value.connected{color:#2e7d32}.status-value.disconnected{color:#c4553d}';
    html += '.view-controls{display:flex;align-items:center;gap:1rem;margin-bottom:1rem;padding:0.75rem 1rem;background:white;border-radius:8px;flex-wrap:wrap}.view-controls label{font-weight:500;color:#333}';
    html += '.size-btn{padding:0.5rem 1rem;border:1px solid #ddd;background:white;cursor:pointer}.size-btn:first-of-type{border-radius:4px 0 0 4px}.size-btn:last-of-type{border-radius:0 4px 4px 0}.size-btn.active{background:#2c5545;color:white;border-color:#2c5545}';
    html += '.selection-bar{position:fixed;bottom:0;left:0;right:0;background:white;padding:1rem 2rem;box-shadow:0 -2px 10px rgba(0,0,0,0.1);display:flex;justify-content:space-between;align-items:center;z-index:100;transform:translateY(100%);transition:transform 0.3s}.selection-bar.visible{transform:translateY(0)}';
    html += '.selection-count{font-weight:600;font-size:1.1rem}.selection-actions{display:flex;gap:0.5rem}';
    html += '.share-modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:none;align-items:center;justify-content:center;z-index:1001}.share-modal.active{display:flex}.share-modal-content{background:white;border-radius:8px;padding:2rem;max-width:500px;width:90%}.share-modal h3{margin-bottom:1rem}.share-modal input{width:100%;padding:0.75rem;border:1px solid #ddd;border-radius:4px;margin-bottom:1rem}.share-modal-actions{display:flex;gap:0.5rem;justify-content:flex-end}';
    html += '.share-result{margin-top:1rem;padding:1rem;background:#f0f9f0;border-radius:4px}.share-result a{color:#2c5545;word-break:break-all}';
    html += '.share-buttons{display:flex;flex-direction:column;gap:0.75rem}.share-action-btn{display:block;width:100%;padding:1rem;border:1px solid #ddd;background:white;border-radius:8px;font-size:1rem;cursor:pointer;text-align:left;text-decoration:none;color:#333;transition:background 0.2s}.share-action-btn:hover{background:#f5f5f5}';
    html += '.select-mode-btn{padding:0.5rem 1rem;border:2px solid #2c5545;background:white;color:#2c5545;border-radius:4px;cursor:pointer;font-weight:500;transition:all 0.2s}.select-mode-btn.active{background:#2c5545;color:white}';
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
    html += '<div id="adminPanel" class="admin-panel hidden"><h2>Admin Settings</h2><div class="tabs"><button class="tab active" data-tab="zoho2">Zoho Sync</button><button class="tab" data-tab="import2">Import CSV</button><button class="tab" data-tab="ai2">AI Analysis</button><button class="tab" data-tab="users2">Users</button></div>';
    html += '<div id="zoho2Tab" class="tab-content active"><div class="status-box"><div class="status-item"><span class="status-label">Status: </span><span class="status-value" id="zohoStatusText">Checking...</span></div><div class="status-item"><span class="status-label">Workspace ID: </span><span class="status-value" id="zohoWorkspaceId">-</span></div><div class="status-item"><span class="status-label">View ID: </span><span class="status-value" id="zohoViewId">-</span></div></div><div style="display:flex;gap:1rem"><button class="btn btn-secondary" id="testZohoBtn">Test Connection</button><button class="btn btn-success" id="syncZohoBtn">Sync Now</button></div><div id="zohoMessage" style="margin-top:1rem"></div></div>';
    html += '<div id="import2Tab" class="tab-content"><div class="upload-area"><input type="file" id="csvFile" accept=".csv"><label for="csvFile">Click to upload CSV file</label></div><div id="importStatus"></div><button class="btn btn-danger" id="clearBtn" style="margin-top:1rem">Clear All Products</button></div>';
    html += '<div id="ai2Tab" class="tab-content"><div class="status-box"><div class="status-item"><span class="status-label">API Status: </span><span class="status-value" id="aiStatusText">Checking...</span></div><div class="status-item"><span class="status-label">Products Analyzed: </span><span class="status-value" id="aiAnalyzedCount">-</span></div><div class="status-item"><span class="status-label">Remaining: </span><span class="status-value" id="aiRemainingCount">-</span></div></div><p style="color:#666;font-size:0.875rem;margin-bottom:1rem">AI analysis uses Claude Vision to generate searchable tags from product images. This enables searching by garment type (cardigan, hoodie), style (casual, formal), pattern (striped, floral), and more.</p><button class="btn btn-primary" id="runAiBtn">Analyze Next 10 Products</button><div id="aiMessage" style="margin-top:1rem"></div></div>';
    html += '<div id="users2Tab" class="tab-content"><table><thead><tr><th>Username</th><th>Role</th><th>Actions</th></tr></thead><tbody id="usersTable"></tbody></table><div class="add-form"><input type="text" id="newUser" placeholder="Username"><input type="password" id="newPass" placeholder="Password"><select id="newRole"><option value="sales_rep">Sales Rep</option><option value="admin">Admin</option></select><button class="btn btn-primary" id="addUserBtn">Add</button></div></div></div>';
    
    html += '<div class="stats"><div><div class="stat-value" id="totalStyles">0</div><div class="stat-label">Styles</div></div><div><div class="stat-value" id="totalUnits">0</div><div class="stat-label" id="unitsLabel">Units Available</div></div><div class="qty-toggle"><button class="qty-toggle-btn active" id="toggleAvailableNow" data-mode="available_now">📦 Available Now</button><button class="qty-toggle-btn" id="toggleLeftToSell" data-mode="left_to_sell">📊 Left to Sell</button></div></div>';
    html += '<div class="view-controls"><label>View:</label><button class="size-btn" data-size="list">List</button><button class="size-btn" data-size="small">Small</button><button class="size-btn active" data-size="medium">Medium</button><button class="size-btn" data-size="large">Large</button><span style="margin-left:1rem"></span><label style="display:inline-flex;align-items:center;gap:0.35rem;cursor:pointer;font-size:0.875rem"><input type="checkbox" id="groupByStyleToggle" style="cursor:pointer"> Group by Style</label><span style="margin-left:1rem"></span><label>Sort:</label><select id="sortSelect" style="padding:0.4rem;border:1px solid #ddd;border-radius:4px"><option value="name-asc">Name A-Z</option><option value="name-desc">Name Z-A</option><option value="qty-high">Qty High→Low</option><option value="qty-low">Qty Low→High</option><option value="newest">Newest First</option></select><span style="margin-left:1rem"></span><label>Qty:</label><input type="number" id="minQty" placeholder="Min" style="width:70px;padding:0.4rem;border:1px solid #ddd;border-radius:4px"><span style="margin:0 0.25rem">-</span><input type="number" id="maxQty" placeholder="Max" style="width:70px;padding:0.4rem;border:1px solid #ddd;border-radius:4px"><button id="resetQtyBtn" style="margin-left:0.5rem;padding:0.4rem 0.75rem;border:1px solid #ddd;background:#f5f5f5;border-radius:4px;cursor:pointer;font-size:0.875rem">Reset</button><span style="margin-left:auto"></span><button class="btn btn-secondary btn-sm" id="compareBtn" disabled style="padding:0.4rem 0.75rem">Compare (0)</button><button class="select-mode-btn" id="selectModeBtn">Select for Sharing</button></div>';
    html += '<div class="filters"><button class="filter-btn" data-special="new">New Arrivals</button><button class="filter-btn" data-special="picks">My Picks</button><button class="filter-btn" data-special="notes">Has Notes</button><span style="margin:0 0.5rem;color:#ccc">|</span><div style="display:inline-block;position:relative"><button class="filter-btn" id="colorFilterBtn">Color: All ▼</button><button class="filter-btn hidden" id="clearColorBtn" style="margin-left:0.25rem;padding:0.5rem 0.75rem">✕</button><div id="colorDropdown" class="color-dropdown hidden"></div></div><span style="margin:0 0.5rem;color:#ccc">|</span><span id="categoryFilters"></span></div>';
    html += '<div class="product-grid size-medium" id="productGrid"></div><div class="empty hidden" id="emptyState">No products found.</div></main></div>';
    
    // Selection bar
    html += '<div class="selection-bar" id="selectionBar"><span class="selection-count"><span id="selectedCount">0</span> items selected</span><div class="selection-actions"><button class="btn btn-secondary" id="clearSelectionBtn">Clear</button><button class="btn btn-secondary" id="exitSelectionBtn">Exit Selection Mode</button><button class="btn btn-primary" id="shareSelectionBtn">Share / Download</button></div></div>';
    
    // Compare bar
    html += '<div class="compare-bar" id="compareBar"><span><span id="compareCount">0</span> items to compare</span><div><button class="btn btn-secondary btn-sm" id="clearCompareBtn" style="margin-right:0.5rem">Clear</button><button class="btn btn-primary btn-sm" id="showCompareBtn">Compare Now</button></div></div>';
    
    // Share modal
    html += '<div class="share-modal" id="shareModal"><div class="share-modal-content"><h3>Share Selection</h3><div id="shareForm"><input type="text" id="selectionName" placeholder="Name this selection (e.g. Spring Collection for Acme Co)"><div class="share-modal-actions"><button class="btn btn-secondary" id="cancelShareBtn">Cancel</button><button class="btn btn-primary" id="createShareBtn">Create Link</button></div></div><div class="share-result hidden" id="shareResult"><p style="margin-bottom:1rem;color:#666" id="shareNameDisplay"></p><div class="share-buttons"><button class="share-action-btn" id="emailLinkBtn">📧 Email Link</button><button class="share-action-btn" id="textLinkBtn">💬 Text Link</button><button class="share-action-btn" id="copyLinkBtn">🔗 Copy Link</button><a class="share-action-btn" id="pdfLink" href="" target="_blank">📄 Download PDF</a></div><div style="margin-top:1.5rem;text-align:center"><button class="btn btn-secondary" id="closeShareModalBtn">Done</button></div></div></div></div>';
    
    // Product modal
    html += '<div class="modal" id="modal"><div class="modal-content"><button class="modal-close" id="modalClose">&times;</button><div class="modal-body"><div class="modal-image"><img id="modalImage" src="" alt=""></div><div class="modal-details"><div class="product-style" id="modalStyle"></div><h2 id="modalName"></h2><p id="modalCategory" style="color:#666;margin-bottom:1rem"></p><div id="modalColors"></div><div class="total-row"><span>Total Available</span><span id="modalTotal"></span></div><div class="modal-actions"><button class="btn btn-secondary btn-sm" id="modalPickBtn">♡ Add to My Picks</button><button class="btn btn-secondary btn-sm" id="modalCompareBtn">+ Add to Compare</button></div><div class="sales-history-section"><h3 style="margin:1rem 0 0.75rem;font-size:1rem;display:flex;align-items:center;gap:0.5rem">📊 Sales History <span id="salesHistoryLoading" style="font-size:0.75rem;color:#666;font-weight:normal">(loading...)</span></h3><div id="salesHistorySummary" style="display:flex;gap:1.5rem;margin-bottom:0.75rem;font-size:0.875rem"></div><div id="salesHistoryList" style="max-height:200px;overflow-y:auto;font-size:0.875rem"></div></div><div class="note-section"><label><strong>My Notes:</strong></label><textarea id="modalNote" placeholder="Add private notes about this product..."></textarea><button class="btn btn-sm btn-primary" id="saveNoteBtn">Save Note</button></div></div></div></div></div>';
    
    // Compare modal
    html += '<div class="compare-modal" id="compareModal"><div class="compare-content"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem"><h2>Compare Products</h2><button class="btn btn-secondary" id="closeCompareBtn">Close</button></div><div class="compare-grid" id="compareGrid"></div></div></div>';
    
    // Help modal
    html += '<div class="help-modal" id="helpModal"><div class="help-content"><button class="modal-close" id="helpClose">&times;</button><h2>📖 Product Catalog Guide</h2><div class="help-sections">';
    
    // Quick Start
    html += '<div class="help-section"><h3>🚀 Quick Start</h3><div class="help-cards"><div class="help-card"><div class="help-icon">🔍</div><h4>Search</h4><p>Type in the search bar to find products by name, style ID, or visual features (if AI search is active)</p></div><div class="help-card"><div class="help-icon">🏷️</div><h4>Filter</h4><p>Use category buttons and color dropdown to narrow down products</p></div><div class="help-card"><div class="help-icon">📤</div><h4>Share</h4><p>Select products and share via email, text, or PDF with your customers</p></div></div></div>';
    
    // Features Guide
    html += '<div class="help-section"><h3>✨ Features Guide</h3><table class="help-table"><tr><td class="help-feature">🔍 <strong>Search Bar</strong></td><td>Search by style ID, product name, or descriptive terms like "striped hoodie" or "floral dress". Multi-word searches find products matching ALL terms.</td></tr><tr><td class="help-feature">📂 <strong>Category Filter</strong></td><td>Click category buttons (Sweater, Dress, etc.) to show only that category. Click "All" to reset.</td></tr><tr><td class="help-feature">🎨 <strong>Color Filter</strong></td><td>Click "Color: All ▼" dropdown to filter by specific colors. Click ✕ to clear.</td></tr><tr><td class="help-feature">📊 <strong>Sort Options</strong></td><td>Sort by Name (A-Z, Z-A), Quantity (High/Low), or Newest arrivals.</td></tr><tr><td class="help-feature">📏 <strong>View Options</strong></td><td>Switch between List, Small, Medium, and Large tile views.</td></tr><tr><td class="help-feature">🔢 <strong>Quantity Filter</strong></td><td>Set Min/Max quantity to find products within a specific inventory range.</td></tr></table></div>';
    
    // My Picks & Notes
    html += '<div class="help-section"><h3>💾 Save & Organize</h3><table class="help-table"><tr><td class="help-feature">♥ <strong>My Picks</strong></td><td>Click the heart icon on any product to save it to your personal favorites. Click "My Picks" filter to see only saved items. Your picks are saved to your account.</td></tr><tr><td class="help-feature">📝 <strong>Notes</strong></td><td>Click a product to open it, then add private notes in the "My Notes" section. Products with notes show a 📝 badge. Click "Has Notes" filter to find them.</td></tr><tr><td class="help-feature">⚖️ <strong>Compare</strong></td><td>Click "Add to Compare" in the product modal (up to 3 products). Then click "Compare" button to see them side-by-side.</td></tr></table></div>';
    
    // Sharing Guide
    html += '<div class="help-section"><h3>📤 Sharing Products</h3><div class="help-steps"><div class="help-step"><div class="step-num">1</div><div class="step-content"><strong>Enter Selection Mode</strong><p>Click "Select for Sharing" button</p></div></div><div class="help-step"><div class="step-num">2</div><div class="step-content"><strong>Select Products</strong><p>Click products to select them (green checkmark appears)</p></div></div><div class="help-step"><div class="step-num">3</div><div class="step-content"><strong>Share / Download</strong><p>Click "Share / Download" in the bottom bar</p></div></div><div class="help-step"><div class="step-num">4</div><div class="step-content"><strong>Choose Method</strong><p>📧 Email Link, 💬 Text Link, 🔗 Copy Link, or 📄 Download PDF</p></div></div></div></div>';
    
    // Keyboard Shortcuts
    html += '<div class="help-section"><h3>⌨️ Keyboard Shortcuts</h3><table class="help-table"><tr><td><kbd>←</kbd> <kbd>→</kbd> <kbd>↑</kbd> <kbd>↓</kbd></td><td>Navigate between products</td></tr><tr><td><kbd>Enter</kbd></td><td>Open selected product / Toggle selection in selection mode</td></tr><tr><td><kbd>Space</kbd></td><td>Toggle selection (in selection mode)</td></tr><tr><td><kbd>Esc</kbd></td><td>Close any open modal</td></tr></table></div>';
    
    // AI Search
    html += '<div class="help-section"><h3>🤖 AI-Enhanced Search</h3><p>When you see "🤖 AI-enhanced search active" below the search bar, the catalog has been analyzed by AI to understand what\'s in each product image.</p><p><strong>This means you can search by:</strong></p><ul><li>Garment type: "cardigan", "hoodie", "romper"</li><li>Style: "casual", "bohemian", "preppy"</li><li>Pattern: "striped", "floral", "graphic print", "heart print"</li><li>Features: "v-neck", "button-front", "cropped", "oversized"</li><li>Combinations: "striped cardigan buttons" or "oversized hoodie graphic"</li></ul></div>';
    
    // FAQ
    html += '<div class="help-section"><h3>❓ FAQ</h3><div class="faq-item"><strong>Q: Why can\'t I find a product I know exists?</strong><p>A: Try different search terms, check if filters are applied (look for active category/color filters), or try clearing the search and browsing.</p></div><div class="faq-item"><strong>Q: How do I share multiple products at once?</strong><p>A: Click "Select for Sharing", select all the products you want, then click "Share / Download" to send them all together.</p></div><div class="faq-item"><strong>Q: Are my picks and notes visible to others?</strong><p>A: No, your picks and notes are private to your account.</p></div><div class="faq-item"><strong>Q: How current is the inventory data?</strong><p>A: Check the "History" panel → "Data Freshness" tab to see when data was last updated.</p></div><div class="faq-item"><strong>Q: Can customers place orders through the shared link?</strong><p>A: No, shared links are view-only. Customers can see products and availability, then contact you to place orders.</p></div></div>';
    
    html += '</div></div></div>';
    
    html += '<script>';
    html += 'var products=[];var allProducts=[];var groupedProducts=[];var lastImportId=null;var currentFilter="all";var colorFilter=null;var specialFilter=null;var currentSort="name-asc";var currentSize="medium";var selectedProducts=[];var compareProducts=[];var selectionMode=false;var currentShareId=null;var userPicks=[];var userNotes={};var currentModalProductId=null;var focusedIndex=-1;var qtyMode="available_now";var groupByStyle=false;';
    
    html += 'function checkSession(){fetch("/api/session").then(function(r){return r.json()}).then(function(d){if(d.loggedIn){showApp(d.username,d.role);loadProducts();loadPicks();loadNotes();loadZohoStatus();loadDataFreshness();loadShares();loadHistory();if(d.role==="admin"){loadUsers();loadAiStatus()}}})}';
    html += 'function showApp(u,r){document.getElementById("loginPage").classList.add("hidden");document.getElementById("mainApp").classList.remove("hidden");document.getElementById("userInfo").textContent="Welcome, "+u;if(r==="admin")document.getElementById("adminBtn").style.display="block"}';
    
    html += 'document.getElementById("loginForm").addEventListener("submit",function(e){e.preventDefault();fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:document.getElementById("username").value,password:document.getElementById("password").value})}).then(function(r){return r.json()}).then(function(d){if(d.success){showApp(d.username,d.role);loadProducts();loadPicks();loadNotes();loadZohoStatus();loadDataFreshness();loadShares();loadHistory();if(d.role==="admin"){loadUsers();loadAiStatus()}}else{document.getElementById("loginError").textContent=d.error;document.getElementById("loginError").classList.remove("hidden")}})});';
    
    html += 'document.getElementById("logoutBtn").addEventListener("click",function(){fetch("/api/logout",{method:"POST"}).then(function(){location.reload()})});';
    html += 'document.getElementById("helpBtn").addEventListener("click",function(){document.getElementById("helpModal").classList.add("active")});';
    html += 'document.getElementById("helpClose").addEventListener("click",function(){document.getElementById("helpModal").classList.remove("active")});';
    html += 'document.getElementById("helpModal").addEventListener("click",function(e){if(e.target.id==="helpModal")document.getElementById("helpModal").classList.remove("active")});';
    html += 'document.getElementById("historyBtn").addEventListener("click",function(){document.getElementById("historyPanel").classList.toggle("hidden");document.getElementById("adminPanel").classList.add("hidden")});';
    html += 'document.getElementById("adminBtn").addEventListener("click",function(){document.getElementById("adminPanel").classList.toggle("hidden");document.getElementById("historyPanel").classList.add("hidden")});';
    
    html += 'var tabs=document.querySelectorAll(".tab");for(var i=0;i<tabs.length;i++){tabs[i].addEventListener("click",function(e){var panel=e.target.closest(".admin-panel");panel.querySelectorAll(".tab").forEach(function(t){t.classList.remove("active")});panel.querySelectorAll(".tab-content").forEach(function(c){c.classList.remove("active")});e.target.classList.add("active");document.getElementById(e.target.getAttribute("data-tab")+"Tab").classList.add("active")})}';
    
    html += 'var sizeBtns=document.querySelectorAll(".size-btn");sizeBtns.forEach(function(btn){btn.addEventListener("click",function(e){sizeBtns.forEach(function(b){b.classList.remove("active")});e.target.classList.add("active");currentSize=e.target.getAttribute("data-size");document.getElementById("productGrid").className="product-grid size-"+currentSize;renderProducts()})});';
    
    // Group by style toggle
    html += 'document.getElementById("groupByStyleToggle").addEventListener("change",function(){groupByStyle=this.checked;renderProducts()});';
    
    // Sort handler
    html += 'document.getElementById("sortSelect").addEventListener("change",function(e){currentSort=e.target.value;renderProducts()});';
    
    // Quantity mode toggle handlers
    html += 'document.getElementById("toggleAvailableNow").addEventListener("click",function(){qtyMode="available_now";document.getElementById("toggleAvailableNow").classList.add("active");document.getElementById("toggleLeftToSell").classList.remove("active");document.getElementById("unitsLabel").textContent="Available Now";renderProducts()});';
    html += 'document.getElementById("toggleLeftToSell").addEventListener("click",function(){qtyMode="left_to_sell";document.getElementById("toggleLeftToSell").classList.add("active");document.getElementById("toggleAvailableNow").classList.remove("active");document.getElementById("unitsLabel").textContent="Left to Sell";renderProducts()});';
    
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
    
    html += 'function toggleCompare(id){var idx=compareProducts.indexOf(id);if(idx===-1&&compareProducts.length<3){compareProducts.push(id)}else if(idx!==-1){compareProducts.splice(idx,1)}updateCompareUI()}';
    
    html += 'function updateCompareUI(){document.getElementById("compareCount").textContent=compareProducts.length;document.getElementById("compareBtn").disabled=compareProducts.length===0;document.getElementById("compareBtn").textContent="Compare ("+compareProducts.length+")";document.getElementById("compareBar").classList.toggle("visible",compareProducts.length>0)}';
    
    html += 'function showProductModal(id){currentModalProductId=id;var pr=products.find(function(p){return p.id===id});if(!pr)return;var imgUrl=getImageUrl(pr.image_url);document.getElementById("modalImage").src=imgUrl||"";document.getElementById("modalStyle").textContent=pr.style_id;document.getElementById("modalName").textContent=pr.name;document.getElementById("modalCategory").textContent=pr.category||"";var cols=pr.colors||[];var totNow=0,totLts=0;cols.forEach(function(c){var aNow=c.available_now||c.available_qty||0;var lts=c.left_to_sell||0;totNow+=aNow;totLts+=lts});var ch="";if(cols.length>1){ch="<table style=\\"width:100%;border-collapse:collapse;font-size:0.875rem\\"><thead><tr style=\\"border-bottom:1px solid #ddd\\"><th style=\\"text-align:left;padding:0.5rem 0;font-weight:600;color:#666\\">Color</th><th style=\\"text-align:right;padding:0.5rem 0;font-weight:600;color:#666;width:80px\\">Avail Now</th><th style=\\"text-align:right;padding:0.5rem 0;font-weight:600;color:#666;width:80px\\">Left to Sell</th></tr></thead><tbody>";cols.forEach(function(c){var aNow=c.available_now||c.available_qty||0;var lts=c.left_to_sell||0;ch+="<tr><td style=\\"padding:0.4rem 0\\">"+c.color_name+"</td><td style=\\"text-align:right;padding:0.4rem 0\\">"+aNow.toLocaleString()+"</td><td style=\\"text-align:right;padding:0.4rem 0;color:#666\\">"+lts.toLocaleString()+"</td></tr>"});ch+="</tbody></table>"}document.getElementById("modalColors").innerHTML=ch;document.getElementById("modalTotal").innerHTML="<span style=\\"margin-right:2rem\\">📦 Now: "+totNow.toLocaleString()+"</span><span>📊 LTS: "+totLts.toLocaleString()+"</span>";document.getElementById("modalNote").value=userNotes[id]||"";document.getElementById("modalPickBtn").style.display="";document.getElementById("modalCompareBtn").style.display="";var isPicked=userPicks.indexOf(id)!==-1;document.getElementById("modalPickBtn").textContent=isPicked?"♥ In My Picks":"♡ Add to My Picks";document.getElementById("modal").classList.add("active");loadSalesHistory(pr.style_id)}';
    
    html += 'function loadSalesHistory(styleId){document.getElementById("salesHistoryLoading").textContent="(loading...)";document.getElementById("salesHistorySummary").innerHTML="";document.getElementById("salesHistoryList").innerHTML="<div style=\\"color:#666;padding:0.5rem\\">Loading sales history...</div>";fetch("/api/sales-history/"+encodeURIComponent(styleId)).then(function(r){return r.json()}).then(function(d){document.getElementById("salesHistoryLoading").textContent="";if(!d.success){document.getElementById("salesHistoryList").innerHTML="<div style=\\"color:#999;padding:0.5rem\\">Unable to load sales history"+(d.error?": "+d.error:"")+"</div>";return}var sum=d.summary;var invDollars=sum.totalInvoicedDollars?"$"+sum.totalInvoicedDollars.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}):"";var openDollars=sum.totalOpenOrdersDollars?"$"+sum.totalOpenOrdersDollars.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}):"";document.getElementById("salesHistorySummary").innerHTML="<div style=\\"padding:0.5rem 0.75rem;background:#e8f5e9;border-radius:4px\\"><div style=\\"font-weight:bold;color:#2e7d32\\">"+sum.totalInvoiced.toLocaleString()+"</div><div style=\\"font-size:0.75rem;color:#666\\">Units Invoiced ("+sum.invoiceCount+" orders)</div>"+(invDollars?"<div style=\\"font-size:0.8rem;color:#2e7d32;margin-top:0.25rem\\">"+invDollars+"</div>":"")+"</div><div style=\\"padding:0.5rem 0.75rem;background:#fff3e0;border-radius:4px\\"><div style=\\"font-weight:bold;color:#ef6c00\\">"+sum.totalOpenOrders.toLocaleString()+"</div><div style=\\"font-size:0.75rem;color:#666\\">Open Orders ("+sum.openOrderCount+")</div>"+(openDollars?"<div style=\\"font-size:0.8rem;color:#ef6c00;margin-top:0.25rem\\">"+openDollars+"</div>":"")+"</div>";if(d.history.length===0){document.getElementById("salesHistoryList").innerHTML="<div style=\\"color:#999;padding:0.5rem\\">No sales history found for this style</div>";return}var h="<table style=\\"width:100%;border-collapse:collapse;font-size:0.8rem\\"><thead><tr style=\\"background:#f5f5f5\\"><th style=\\"text-align:left;padding:0.4rem\\">Date</th><th style=\\"text-align:left;padding:0.4rem\\">Customer</th><th style=\\"text-align:left;padding:0.4rem\\">Type</th><th style=\\"text-align:right;padding:0.4rem\\">Qty</th><th style=\\"text-align:right;padding:0.4rem\\">Amount</th></tr></thead><tbody>";d.history.forEach(function(rec){var typeLabel=rec.type==="invoice"?"<span style=\\"color:#2e7d32\\">INV "+rec.documentNumber+"</span>":"<span style=\\"color:#ef6c00\\">SO "+rec.documentNumber+(rec.isOpen?" (Open)":"")+"</span>";var dt=new Date(rec.date).toLocaleDateString();var amt=rec.amount?"$"+rec.amount.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}):"-";h+="<tr style=\\"border-bottom:1px solid #eee\\"><td style=\\"padding:0.4rem\\">"+dt+"</td><td style=\\"padding:0.4rem\\">"+rec.customerName+"</td><td style=\\"padding:0.4rem\\">"+typeLabel+"</td><td style=\\"padding:0.4rem;text-align:right\\">"+rec.quantity.toLocaleString()+"</td><td style=\\"padding:0.4rem;text-align:right\\">"+amt+"</td></tr>"});h+="</tbody></table>";document.getElementById("salesHistoryList").innerHTML=h}).catch(function(err){document.getElementById("salesHistoryLoading").textContent="";document.getElementById("salesHistoryList").innerHTML="<div style=\\"color:#999;padding:0.5rem\\">Error loading sales history: "+err.message+"</div>"})}';    
    html += 'function updateSelectionUI(){document.getElementById("selectedCount").textContent=selectedProducts.length;var bar=document.getElementById("selectionBar");if(selectedProducts.length>0&&selectionMode){bar.classList.add("visible")}else{bar.classList.remove("visible")}}';
    
    // Helper to group products by base style
    html += 'function groupProductsByStyle(prods){var groups={};prods.forEach(function(p){var base=p.style_id.split("-")[0];if(!groups[base]){groups[base]={baseStyle:base,name:p.name.replace(p.style_id,base),category:p.category,variants:[],firstSeenImport:p.first_seen_import}}groups[base].variants.push(p)});return Object.values(groups)}';
    
    html += 'function renderProducts(){var s=document.getElementById("searchInput").value.toLowerCase().trim();var searchWords=s?s.split(/\\s+/):[];var minQ=parseInt(document.getElementById("minQty").value)||0;var maxQ=parseInt(document.getElementById("maxQty").value)||999999999;var f=allProducts.filter(function(p){var searchText=p.style_id.toLowerCase()+" "+p.name.toLowerCase()+" "+(p.ai_tags||"").toLowerCase();var ms=searchWords.length===0||searchWords.every(function(word){return searchText.indexOf(word)!==-1});var mc=currentFilter==="all"||p.category===currentFilter;var colorNames=(p.colors||[]).map(function(c){return c.color_name});var mcolor=!colorFilter||colorNames.indexOf(colorFilter)!==-1;var tot=0;(p.colors||[]).forEach(function(c){tot+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))});var mq=tot>=minQ&&tot<=maxQ;var msp=true;if(specialFilter==="new"){msp=p.first_seen_import===lastImportId}else if(specialFilter==="picks"){msp=userPicks.indexOf(p.id)!==-1}else if(specialFilter==="notes"){msp=!!userNotes[p.id]}return ms&&mc&&mcolor&&mq&&msp});f.sort(function(a,b){var ta=0,tb=0;(a.colors||[]).forEach(function(c){ta+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))});(b.colors||[]).forEach(function(c){tb+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))});if(currentSort==="qty-high")return tb-ta;if(currentSort==="qty-low")return ta-tb;if(currentSort==="name-desc")return b.name.localeCompare(a.name);if(currentSort==="newest")return(b.first_seen_import||0)-(a.first_seen_import||0);return a.name.localeCompare(b.name)});products=f;if(f.length===0){document.getElementById("productGrid").innerHTML="";document.getElementById("emptyState").classList.remove("hidden")}else{document.getElementById("emptyState").classList.add("hidden");var h="";var isListView=currentSize==="list";if(groupByStyle){var grouped=groupProductsByStyle(f);grouped.sort(function(a,b){var ta=0,tb=0;a.variants.forEach(function(v){(v.colors||[]).forEach(function(c){ta+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))})});b.variants.forEach(function(v){(v.colors||[]).forEach(function(c){tb+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))})});if(currentSort==="qty-high")return tb-ta;if(currentSort==="qty-low")return ta-tb;if(currentSort==="name-desc")return b.name.localeCompare(a.name);return a.name.localeCompare(b.name)});grouped.forEach(function(grp,idx){var totNow=0,totLts=0;grp.variants.forEach(function(v){(v.colors||[]).forEach(function(c){totNow+=(c.available_now||c.available_qty||0);totLts+=(c.left_to_sell||0)})});var primaryQty=qtyMode==="left_to_sell"?totLts:totNow;var secondaryQty=qtyMode==="left_to_sell"?totNow:totLts;var secondaryLabel=qtyMode==="left_to_sell"?"Now":"LTS";var imgUrl=getImageUrl(grp.variants[0].image_url);var im=imgUrl?"<img src=\\""+imgUrl+"\\" onerror=\\"this.parentElement.innerHTML=\'No Image\'\\">":"No Image";var colorCount=grp.variants.length;var variantIds=grp.variants.map(function(v){return v.id}).join(",");var selModeClass=selectionMode?"selection-mode":"";h+="<div class=\\"product-card grouped "+selModeClass+"\\" data-idx=\\""+idx+"\\" data-variants=\\""+variantIds+"\\" onclick=\\"handleGroupClick(\'"+grp.baseStyle+"\',event)\\"><div class=\\"color-count-badge\\">"+colorCount+" colors</div><div class=\\"product-image\\">"+im+"</div><div class=\\"product-info\\"><div class=\\"product-style\\">"+grp.baseStyle+"</div><div class=\\"product-name\\">"+grp.name+"</div><div class=\\"total-row\\"><span>Total</span><span>"+primaryQty.toLocaleString()+"</span></div><div style=\\"font-size:0.75rem;color:#999;text-align:right\\">("+secondaryLabel+": "+secondaryQty.toLocaleString()+")</div></div></div>"});document.getElementById("totalStyles").textContent=grouped.length+" groups"}else{f.forEach(function(pr,idx){var cols=pr.colors||[];var totNow=0,totLts=0;cols.forEach(function(c){totNow+=(c.available_now||c.available_qty||0);totLts+=(c.left_to_sell||0)});var primaryQty=qtyMode==="left_to_sell"?totLts:totNow;var secondaryQty=qtyMode==="left_to_sell"?totNow:totLts;var secondaryLabel=qtyMode==="left_to_sell"?"Now":"LTS";var ch="";if(!isListView){var mx=Math.min(cols.length,3);for(var d=0;d<mx;d++){var cq=qtyMode==="left_to_sell"?(cols[d].left_to_sell||0):(cols[d].available_now||cols[d].available_qty||0);ch+="<div class=\\"color-row\\"><span>"+cols[d].color_name+"</span><span>"+cq.toLocaleString()+"</span></div>"}if(cols.length>3)ch+="<div class=\\"color-row\\" style=\\"color:#999\\">+"+(cols.length-3)+" more</div>"}var listCols="";if(isListView){cols.slice(0,5).forEach(function(c){var cq=qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0);listCols+=c.color_name+": "+cq.toLocaleString()+"; "});if(cols.length>5)listCols+="+"+(cols.length-5)+" more"}var imgUrl=getImageUrl(pr.image_url);var im=imgUrl?"<img src=\\""+imgUrl+"\\" onerror=\\"this.parentElement.innerHTML=\'No Image\'\\">":"No Image";var sel=selectedProducts.indexOf(pr.id)!==-1?"selected":"";var selModeClass=selectionMode?"selection-mode":"";var listClass=isListView?"list-view":"";var isPicked=userPicks.indexOf(pr.id)!==-1;var hasNote=!!userNotes[pr.id];h+="<div class=\\"product-card "+sel+" "+selModeClass+" "+listClass+"\\" data-idx=\\""+idx+"\\" onclick=\\"handleCardClick("+pr.id+",event)\\"><div class=\\"select-badge\\">✓</div><div class=\\"pick-badge "+(isPicked?"active":"")+"\\">"+(isPicked?"♥":"♡")+"</div><div class=\\"note-badge "+(hasNote?"has-note":"")+"\\">📝</div><div class=\\"product-image\\">"+im+"</div><div class=\\"product-info\\"><div class=\\"product-style\\">"+pr.style_id+"</div><div class=\\"product-name\\">"+pr.name+"</div>"+(isListView?"<div class=\\"list-colors\\">"+listCols+"</div>":"<div class=\\"color-list\\">"+ch+"</div>")+"<div class=\\"total-row\\"><span>Total</span><span>"+primaryQty.toLocaleString()+"</span></div><div style=\\"font-size:0.75rem;color:#999;text-align:right\\">("+secondaryLabel+": "+secondaryQty.toLocaleString()+")</div></div></div>"});document.getElementById("totalStyles").textContent=f.length}document.getElementById("productGrid").innerHTML=h}var tu=0;f.forEach(function(p){(p.colors||[]).forEach(function(c){tu+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))})});document.getElementById("totalUnits").textContent=tu.toLocaleString();focusedIndex=-1}';
    
    // Handle click on grouped card - show group modal
    html += 'function handleGroupClick(baseStyle,e){if(e.target.classList.contains("pick-badge"))return;var variants=allProducts.filter(function(p){return p.style_id.split("-")[0]===baseStyle});showGroupModal(baseStyle,variants)}';
    
    // Show group modal with all color variants
    html += 'function showGroupModal(baseStyle,variants){var totNow=0,totLts=0;variants.forEach(function(v){(v.colors||[]).forEach(function(c){totNow+=(c.available_now||c.available_qty||0);totLts+=(c.left_to_sell||0)})});document.getElementById("modalStyle").textContent=baseStyle;document.getElementById("modalName").textContent=variants[0].name.replace(variants[0].style_id,baseStyle);document.getElementById("modalCategory").textContent=variants[0].category||"";var imgUrl=getImageUrl(variants[0].image_url);document.getElementById("modalImage").src=imgUrl||"";var swatchHtml="<div style=\\"display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:1rem\\">";variants.forEach(function(v,i){var vImg=getImageUrl(v.image_url);var colorCode=v.style_id.split("-")[1]||"";var colorName=(v.colors&&v.colors[0])?v.colors[0].color_name:colorCode;swatchHtml+="<div class=\\"color-swatch"+(i===0?" active":"")+"\\" data-idx=\\""+i+"\\" style=\\"padding:0.5rem 0.75rem;border:2px solid "+(i===0?"#1a3b5d":"#ddd")+";border-radius:4px;cursor:pointer;font-size:0.75rem;background:"+(i===0?"#f0f4f8":"#fff")+"\\" onclick=\\"switchVariantImage("+i+",\'"+baseStyle+"\')\\">"+colorName+"</div>"});swatchHtml+="</div>";var ch="<table style=\\"width:100%;border-collapse:collapse;font-size:0.875rem\\"><thead><tr style=\\"border-bottom:1px solid #ddd\\"><th style=\\"text-align:left;padding:0.5rem 0;font-weight:600;color:#666\\">Color Variant</th><th style=\\"text-align:right;padding:0.5rem 0;font-weight:600;color:#666;width:80px\\">Avail Now</th><th style=\\"text-align:right;padding:0.5rem 0;font-weight:600;color:#666;width:80px\\">Left to Sell</th></tr></thead><tbody>";variants.forEach(function(v){var vNow=0,vLts=0;(v.colors||[]).forEach(function(c){vNow+=(c.available_now||c.available_qty||0);vLts+=(c.left_to_sell||0)});var colorName=(v.colors&&v.colors[0])?v.colors[0].color_name:v.style_id;ch+="<tr><td style=\\"padding:0.4rem 0\\">"+colorName+"</td><td style=\\"text-align:right;padding:0.4rem 0\\">"+vNow.toLocaleString()+"</td><td style=\\"text-align:right;padding:0.4rem 0;color:#666\\">"+vLts.toLocaleString()+"</td></tr>"});ch+="</tbody></table>";document.getElementById("modalColors").innerHTML=swatchHtml+ch;document.getElementById("modalTotal").innerHTML="<span style=\\"margin-right:2rem\\">📦 Now: "+totNow.toLocaleString()+"</span><span>📊 LTS: "+totLts.toLocaleString()+"</span>";document.getElementById("modalNote").value="";document.getElementById("modalPickBtn").style.display="none";document.getElementById("modalCompareBtn").style.display="none";currentModalProductId=null;window.currentGroupVariants=variants;document.getElementById("modal").classList.add("active");loadSalesHistory(baseStyle)}';
    
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
    html += 'document.getElementById("clearBtn").addEventListener("click",function(){if(!confirm("Delete all products?"))return;fetch("/api/products/clear",{method:"POST"}).then(function(){loadProducts()})});';
    
    html += 'function loadUsers(){fetch("/api/users").then(function(r){return r.json()}).then(function(u){var h="";u.forEach(function(x){h+="<tr><td>"+x.username+"</td><td>"+x.role+"</td><td><button class=\\"btn btn-danger\\" onclick=\\"deleteUser("+x.id+")\\">Delete</button></td></tr>"});document.getElementById("usersTable").innerHTML=h})}';
    html += 'document.getElementById("addUserBtn").addEventListener("click",function(){var u=document.getElementById("newUser").value;var p=document.getElementById("newPass").value;if(!u||!p){alert("Enter username and password");return}fetch("/api/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p,role:document.getElementById("newRole").value})}).then(function(){document.getElementById("newUser").value="";document.getElementById("newPass").value="";loadUsers()})});';
    html += 'function deleteUser(id){if(!confirm("Delete user?"))return;fetch("/api/users/"+id,{method:"DELETE"}).then(function(){loadUsers()})}';
    
    html += 'function loadHistory(){fetch("/api/zoho/sync-history").then(function(r){return r.json()}).then(function(h){var html="";h.forEach(function(x){html+="<tr><td>"+new Date(x.created_at).toLocaleString()+"</td><td>"+x.sync_type+"</td><td>"+x.status+"</td><td>"+(x.records_synced||"-")+"</td><td>"+(x.error_message||"-")+"</td></tr>"});document.getElementById("historyTable").innerHTML=html})}';
    
    // AI Analysis functions
    html += 'function loadAiStatus(){fetch("/api/ai-status").then(function(r){return r.json()}).then(function(d){var st=document.getElementById("aiStatusText");if(d.configured){st.textContent="Configured";st.className="status-value connected"}else{st.textContent="API Key Not Set";st.className="status-value disconnected"}document.getElementById("aiAnalyzedCount").textContent=d.analyzed+" / "+d.total;document.getElementById("aiRemainingCount").textContent=d.remaining})}';
    
    html += 'document.getElementById("runAiBtn").addEventListener("click",function(){var btn=this;btn.disabled=true;btn.textContent="Analyzing...";document.getElementById("aiMessage").innerHTML="<span style=\\"color:#666\\">Processing images with Claude Vision...</span>";fetch("/api/ai-analyze",{method:"POST"}).then(function(r){return r.json()}).then(function(d){btn.disabled=false;btn.textContent="Analyze Next 10 Products";if(d.success){document.getElementById("aiMessage").innerHTML="<span class=\\"success\\">"+d.message+". "+d.remaining+" remaining.</span>"}else{document.getElementById("aiMessage").innerHTML="<span class=\\"error\\">"+d.error+"</span>"}loadAiStatus()})});';
    
    html += 'document.getElementById("modalClose").addEventListener("click",function(){document.getElementById("modal").classList.remove("active")});';
    html += 'document.getElementById("modal").addEventListener("click",function(e){if(e.target.id==="modal")document.getElementById("modal").classList.remove("active")});';
    
    // Modal pick button
    html += 'document.getElementById("modalPickBtn").addEventListener("click",function(){if(currentModalProductId){togglePick(currentModalProductId,{stopPropagation:function(){}});var isPicked=userPicks.indexOf(currentModalProductId)!==-1;this.textContent=isPicked?"♥ In My Picks":"♡ Add to My Picks"}});';
    
    // Modal compare button
    html += 'document.getElementById("modalCompareBtn").addEventListener("click",function(){if(currentModalProductId){toggleCompare(currentModalProductId)}});';
    
    // Save note button
    html += 'document.getElementById("saveNoteBtn").addEventListener("click",function(){if(currentModalProductId){var note=document.getElementById("modalNote").value;fetch("/api/notes/"+currentModalProductId,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({note:note})}).then(function(){if(note.trim()){userNotes[currentModalProductId]=note}else{delete userNotes[currentModalProductId]}renderProducts()})}});';
    
    // Compare functionality
    html += 'document.getElementById("compareBtn").addEventListener("click",showCompare);';
    html += 'document.getElementById("showCompareBtn").addEventListener("click",showCompare);';
    html += 'document.getElementById("clearCompareBtn").addEventListener("click",function(){compareProducts=[];updateCompareUI();renderProducts()});';
    html += 'document.getElementById("closeCompareBtn").addEventListener("click",function(){document.getElementById("compareModal").classList.remove("active")});';
    
    html += 'function showCompare(){if(compareProducts.length===0)return;var h="";compareProducts.forEach(function(id){var pr=allProducts.find(function(p){return p.id===id});if(!pr)return;var imgUrl=getImageUrl(pr.image_url);var cols=pr.colors||[];var tot=0;var ch="";cols.forEach(function(c){tot+=c.available_qty||0;ch+="<div class=\\"color-row\\"><span>"+c.color_name+"</span><span>"+(c.available_qty||0).toLocaleString()+"</span></div>"});h+="<div class=\\"compare-item\\"><img src=\\""+imgUrl+"\\" onerror=\\"this.style.display=\'none\'\\"><h3>"+pr.name+"</h3><p style=\\"color:#666;font-size:0.875rem\\">"+pr.style_id+"</p><p style=\\"font-weight:bold;margin:0.5rem 0\\">Total: "+tot.toLocaleString()+"</p><div class=\\"compare-colors\\">"+ch+"</div></div>"});document.getElementById("compareGrid").innerHTML=h;document.getElementById("compareModal").classList.add("active")}';
    
    // Keyboard navigation
    html += 'document.addEventListener("keydown",function(e){if(document.getElementById("modal").classList.contains("active")){if(e.key==="Escape"){document.getElementById("modal").classList.remove("active")}return}if(document.getElementById("compareModal").classList.contains("active")){if(e.key==="Escape"){document.getElementById("compareModal").classList.remove("active")}return}if(document.getElementById("shareModal").classList.contains("active")){if(e.key==="Escape"){document.getElementById("shareModal").classList.remove("active")}return}if(document.activeElement.tagName==="INPUT"||document.activeElement.tagName==="TEXTAREA")return;var cards=document.querySelectorAll(".product-card");if(cards.length===0)return;if(e.key==="ArrowRight"||e.key==="ArrowDown"){e.preventDefault();focusedIndex=Math.min(focusedIndex+1,cards.length-1);updateFocus(cards)}else if(e.key==="ArrowLeft"||e.key==="ArrowUp"){e.preventDefault();focusedIndex=Math.max(focusedIndex-1,0);updateFocus(cards)}else if(e.key==="Enter"&&focusedIndex>=0){e.preventDefault();var id=parseInt(products[focusedIndex].id);if(selectionMode){var idx=selectedProducts.indexOf(id);if(idx===-1){selectedProducts.push(id)}else{selectedProducts.splice(idx,1)}updateSelectionUI();renderProducts()}else{showProductModal(id)}}else if(e.key===" "&&focusedIndex>=0&&selectionMode){e.preventDefault();var id=parseInt(products[focusedIndex].id);var idx=selectedProducts.indexOf(id);if(idx===-1){selectedProducts.push(id)}else{selectedProducts.splice(idx,1)}updateSelectionUI();renderProducts()}});';
    
    html += 'function updateFocus(cards){cards.forEach(function(c,i){c.classList.toggle("focused",i===focusedIndex)});if(focusedIndex>=0&&cards[focusedIndex]){cards[focusedIndex].scrollIntoView({block:"nearest",behavior:"smooth"})}}';
    
    html += 'checkSession();';
    html += '</script></body></html>';
    return html;
}

initDB().then(function() {
    app.listen(PORT, function() { console.log("Product Catalog running on port " + PORT); });
    setTimeout(function() { startTokenRefreshJob(); }, 5000);
});
