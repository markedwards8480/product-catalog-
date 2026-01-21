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

async function initDB() {
    try {
        await pool.query('CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL, role VARCHAR(50) DEFAULT \'sales_rep\', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, style_id VARCHAR(100) NOT NULL, base_style VARCHAR(100), name VARCHAR(255) NOT NULL, category VARCHAR(100), image_url TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS product_colors (id SERIAL PRIMARY KEY, product_id INTEGER REFERENCES products(id) ON DELETE CASCADE, color_name VARCHAR(100) NOT NULL, available_qty INTEGER DEFAULT 0, on_hand INTEGER DEFAULT 0, open_order INTEGER DEFAULT 0, to_come INTEGER DEFAULT 0, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS sync_history (id SERIAL PRIMARY KEY, sync_type VARCHAR(50), status VARCHAR(50), records_synced INTEGER DEFAULT 0, error_message TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS zoho_tokens (id SERIAL PRIMARY KEY, access_token TEXT, refresh_token TEXT, expires_at TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS selections (id SERIAL PRIMARY KEY, share_id VARCHAR(50) UNIQUE NOT NULL, name VARCHAR(255), product_ids INTEGER[], created_by VARCHAR(255), share_type VARCHAR(50) DEFAULT \'link\', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        
        // Add share_type column if it doesn't exist (for existing databases)
        try {
            await pool.query('ALTER TABLE selections ADD COLUMN IF NOT EXISTS share_type VARCHAR(50) DEFAULT \'link\'');
        } catch (e) { /* column may already exist */ }
        
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
    res.json({ loggedIn: true, username: req.session.username || 'admin', role: req.session.role || 'admin' });
});

app.get('/api/products', requireAuth, async function(req, res) {
    try {
        var result = await pool.query('SELECT p.id, p.style_id, p.base_style, p.name, p.category, p.image_url, json_agg(json_build_object(\'id\', pc.id, \'color_name\', pc.color_name, \'available_qty\', pc.available_qty, \'on_hand\', pc.on_hand)) FILTER (WHERE pc.id IS NOT NULL) as colors FROM products p LEFT JOIN product_colors pc ON p.id = pc.product_id GROUP BY p.id ORDER BY p.category, p.name');
        res.json(result.rows);
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

function parseCSVLine(line) { var result = []; var current = ''; var inQuotes = false; for (var i = 0; i < line.length; i++) { var char = line[i]; if (char === '"') { inQuotes = !inQuotes; } else if (char === ',' && !inQuotes) { result.push(current.trim()); current = ''; } else { current += char; } } result.push(current.trim()); return result; }
function parseNumber(val) { if (!val) return 0; return parseInt(val.toString().replace(/,/g, '').replace(/"/g, '').trim()) || 0; }

app.post('/api/import', requireAuth, requireAdmin, upload.single('file'), async function(req, res) {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        var content = req.file.buffer.toString('utf-8'); var allLines = content.split('\n'); var lines = []; for (var i = 0; i < allLines.length; i++) { if (allLines[i].trim()) lines.push(allLines[i]); } if (lines.length < 2) return res.status(400).json({ error: 'File appears empty' });
        var headerLine = lines[0]; if (headerLine.charCodeAt(0) === 0xFEFF) headerLine = headerLine.slice(1); var headersRaw = parseCSVLine(headerLine); var headers = []; for (var h = 0; h < headersRaw.length; h++) { headers.push(headersRaw[h].toLowerCase().replace(/[^\w\s]/g, '').trim()); }
        var headerMap = {}; for (var hi = 0; hi < headers.length; hi++) { headerMap[headers[hi]] = hi; }
        var imported = 0, skipped = 0; var lastStyleId = null, lastImageUrl = null, lastCategory = null;
        for (var li = 1; li < lines.length; li++) { try { var values = parseCSVLine(lines[li]); if (values[0] && values[0].indexOf('Grand Summary') !== -1) { skipped++; continue; } var styleId = values[headerMap['style name']] || values[0]; var imageUrl = values[headerMap['style image']] || values[1]; var color = values[headerMap['color']] || values[2]; var category = values[headerMap['commodity']] || values[3]; var onHand = parseNumber(values[headerMap['on hand']] || values[4]); var available = parseNumber(values[headerMap['available now']] || values[headerMap['left to sell']] || values[7]); if (!styleId && color) { styleId = lastStyleId; if (!imageUrl || imageUrl === '-No Value-') imageUrl = lastImageUrl; if (!category || category === '-No Value-') category = lastCategory; } if (!styleId) { skipped++; continue; } lastStyleId = styleId; if (imageUrl && imageUrl !== '-No Value-' && imageUrl.indexOf('http') === 0) lastImageUrl = imageUrl; if (category && category !== '-No Value-') lastCategory = category; var baseStyle = styleId.split('-')[0]; var validCategory = (category && category !== '-No Value-') ? category : 'Uncategorized'; var name = validCategory + ' - ' + baseStyle; var validImageUrl = (imageUrl && imageUrl !== '-No Value-' && imageUrl.indexOf('http') === 0) ? imageUrl : lastImageUrl; var productResult = await pool.query('SELECT id, image_url FROM products WHERE style_id = $1', [styleId]); var productId; if (productResult.rows.length > 0) { productId = productResult.rows[0].id; var finalImage = validImageUrl || productResult.rows[0].image_url; await pool.query('UPDATE products SET name=$1, category=$2, base_style=$3, image_url=$4, updated_at=CURRENT_TIMESTAMP WHERE id=$5', [name, validCategory, baseStyle, finalImage, productId]); } else { var ins = await pool.query('INSERT INTO products (style_id, base_style, name, category, image_url) VALUES ($1,$2,$3,$4,$5) RETURNING id', [styleId, baseStyle, name, validCategory, validImageUrl]); productId = ins.rows[0].id; } if (color && color !== '-No Value-') { var colorResult = await pool.query('SELECT id FROM product_colors WHERE product_id=$1 AND color_name=$2', [productId, color]); if (colorResult.rows.length > 0) { await pool.query('UPDATE product_colors SET available_qty=$1, on_hand=$2, updated_at=CURRENT_TIMESTAMP WHERE id=$3', [available, onHand, colorResult.rows[0].id]); } else { await pool.query('INSERT INTO product_colors (product_id, color_name, available_qty, on_hand) VALUES ($1,$2,$3,$4)', [productId, color, available, onHand]); } } imported++; } catch (rowErr) { skipped++; } }
        await pool.query('INSERT INTO sync_history (sync_type, status, records_synced) VALUES ($1,$2,$3)', ['csv_import', 'success', imported]);
        res.json({ success: true, imported: imported, skipped: skipped });
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
    var html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>' + (selection.name || 'Product Selection') + ' - Mark Edwards Apparel</title><style>@media print{@page{margin:0.5in}body{-webkit-print-color-adjust:exact;print-color-adjust:exact}}*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial,sans-serif;padding:20px;background:white}.header{text-align:center;margin-bottom:30px;padding-bottom:20px;border-bottom:2px solid #333}.header h1{font-size:24px;margin-bottom:5px}.header p{color:#666}.product-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:20px}.product-card{border:1px solid #ddd;border-radius:8px;overflow:hidden;page-break-inside:avoid}.product-image{height:180px;background:#f5f5f5;display:flex;align-items:center;justify-content:center}.product-image img{max-width:100%;max-height:100%;object-fit:contain}.product-info{padding:12px}.product-name{font-size:14px;font-weight:bold;margin-bottom:4px}.product-style{font-size:11px;color:#666;margin-bottom:8px}.color-row{display:flex;justify-content:space-between;font-size:11px;padding:2px 0}.total-row{margin-top:8px;padding-top:8px;border-top:1px solid #eee;font-weight:bold;display:flex;justify-content:space-between;font-size:12px}.footer{margin-top:30px;text-align:center;color:#666;font-size:12px}.print-btn{position:fixed;top:20px;right:20px;padding:10px 20px;background:#2c5545;color:white;border:none;border-radius:4px;cursor:pointer;font-size:14px}@media print{.print-btn{display:none}}</style></head><body>';
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
    html += '.search-box input{padding:0.5rem 1rem;border:1px solid #ddd;border-radius:4px;width:250px}';
    html += '.main{max-width:1400px;margin:0 auto;padding:2rem}';
    html += '.admin-panel{background:white;padding:1.5rem;border-radius:8px;margin-bottom:2rem}.admin-panel h2{margin-bottom:1rem}';
    html += '.tabs{display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap}.tab{padding:0.5rem 1rem;border:none;background:#eee;cursor:pointer;border-radius:4px}.tab.active{background:#2c5545;color:white}.tab-content{display:none}.tab-content.active{display:block}';
    html += '.upload-area{border:2px dashed #ddd;padding:2rem;text-align:center;border-radius:4px;margin-bottom:1rem}.upload-area input{display:none}.upload-area label{color:#2c5545;cursor:pointer}';
    html += '.stats{display:flex;gap:2rem;margin-bottom:1rem;padding:1rem;background:white;border-radius:8px}.stat-value{font-size:1.5rem;font-weight:bold}.stat-label{color:#666;font-size:0.875rem}';
    html += '.filters{display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap}.filter-btn{padding:0.5rem 1rem;border:1px solid #ddd;background:white;border-radius:20px;cursor:pointer}.filter-btn.active{background:#2c5545;color:white;border-color:#2c5545}';
    html += '.product-grid{display:grid;gap:1.5rem}.product-grid.size-small{grid-template-columns:repeat(auto-fill,minmax(200px,1fr))}.product-grid.size-medium{grid-template-columns:repeat(auto-fill,minmax(300px,1fr))}.product-grid.size-large{grid-template-columns:repeat(auto-fill,minmax(400px,1fr))}';
    html += '.product-card{background:white;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);cursor:pointer;transition:transform 0.2s;position:relative}.product-card:hover{transform:translateY(-2px);box-shadow:0 4px 16px rgba(0,0,0,0.15)}';
    html += '.product-card.selected{outline:3px solid #2c5545;outline-offset:-3px}';
    html += '.product-card.selection-mode:hover{outline:2px dashed #2c5545;outline-offset:-2px}';
    html += '.select-badge{position:absolute;top:10px;right:10px;width:28px;height:28px;background:#2c5545;color:white;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px;opacity:0;transition:opacity 0.2s}.product-card.selection-mode:hover .select-badge{opacity:0.7}.product-card.selected .select-badge{opacity:1}';
    html += '.product-image{height:220px;background:#f8f8f8;display:flex;align-items:center;justify-content:center;overflow:hidden}.product-image img{max-width:100%;max-height:100%;object-fit:contain}';
    html += '.product-info{padding:1rem}.product-style{font-size:0.75rem;color:#666;text-transform:uppercase}.product-name{font-size:1.1rem;font-weight:600;margin:0.25rem 0}.color-list{margin-top:0.75rem}.color-row{display:flex;justify-content:space-between;padding:0.25rem 0;font-size:0.875rem}.total-row{margin-top:0.5rem;padding-top:0.5rem;border-top:1px solid #eee;font-weight:bold;display:flex;justify-content:space-between}';
    html += '.empty{text-align:center;padding:3rem;color:#666}';
    html += '.modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:none;align-items:center;justify-content:center;z-index:1000}.modal.active{display:flex}.modal-content{background:white;border-radius:8px;max-width:95vw;width:1200px;max-height:95vh;overflow:auto;position:relative}.modal-body{display:flex;min-height:600px}.modal-image{width:60%;background:#f0f0f0;min-height:600px;display:flex;align-items:center;justify-content:center;padding:1rem}.modal-image img{max-width:100%;max-height:700px;object-fit:contain}.modal-details{width:40%;padding:2rem}.modal-close{position:absolute;top:1rem;right:1rem;background:white;border:none;font-size:1.5rem;cursor:pointer;border-radius:50%;width:36px;height:36px}';
    html += 'table{width:100%;border-collapse:collapse}th,td{padding:0.75rem;text-align:left;border-bottom:1px solid #eee}';
    html += '.add-form{display:flex;gap:0.5rem;margin-top:1rem;flex-wrap:wrap}.add-form input,.add-form select{padding:0.5rem;border:1px solid #ddd;border-radius:4px}';
    html += '.status-box{padding:1rem;background:#f9f9f9;border-radius:4px;margin-bottom:1rem}.status-item{margin-bottom:0.5rem}.status-label{font-weight:500}.status-value{color:#666}.status-value.connected{color:#2e7d32}.status-value.disconnected{color:#c4553d}';
    html += '.view-controls{display:flex;align-items:center;gap:1rem;margin-bottom:1rem;padding:0.75rem 1rem;background:white;border-radius:8px;flex-wrap:wrap}.view-controls label{font-weight:500;color:#333}';
    html += '.size-btn{padding:0.5rem 1rem;border:1px solid #ddd;background:white;cursor:pointer}.size-btn:first-of-type{border-radius:4px 0 0 4px}.size-btn:last-of-type{border-radius:0 4px 4px 0}.size-btn.active{background:#2c5545;color:white;border-color:#2c5545}';
    html += '.selection-bar{position:fixed;bottom:0;left:0;right:0;background:white;padding:1rem 2rem;box-shadow:0 -2px 10px rgba(0,0,0,0.1);display:flex;justify-content:space-between;align-items:center;z-index:100;transform:translateY(100%);transition:transform 0.3s}.selection-bar.visible{transform:translateY(0)}';
    html += '.selection-count{font-weight:600;font-size:1.1rem}.selection-actions{display:flex;gap:0.5rem}';
    html += '.share-modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:none;align-items:center;justify-content:center;z-index:1001}.share-modal.active{display:flex}.share-modal-content{background:white;border-radius:8px;padding:2rem;max-width:500px;width:90%}.share-modal h3{margin-bottom:1rem}.share-modal input{width:100%;padding:0.75rem;border:1px solid #ddd;border-radius:4px;margin-bottom:1rem}.share-modal-actions{display:flex;gap:0.5rem;justify-content:flex-end}';
    html += '.share-result{margin-top:1rem;padding:1rem;background:#f0f9f0;border-radius:4px}.share-result a{color:#2c5545;word-break:break-all}';
    html += '.select-mode-btn{padding:0.5rem 1rem;border:2px solid #2c5545;background:white;color:#2c5545;border-radius:4px;cursor:pointer;font-weight:500;transition:all 0.2s}.select-mode-btn.active{background:#2c5545;color:white}';
    html += '.freshness-info{padding:1rem;background:#f0f9f0;border-radius:4px;margin-bottom:1rem}.freshness-info.stale{background:#fff3e0}';
    html += '.share-history-table{font-size:0.875rem}.share-history-table td{padding:0.5rem 0.75rem}.share-type-badge{display:inline-block;padding:0.125rem 0.5rem;border-radius:4px;font-size:0.75rem;font-weight:500}.share-type-badge.link{background:#e3f2fd;color:#1565c0}.share-type-badge.pdf{background:#fce4ec;color:#c62828}';
    html += '</style></head><body>';
    
    html += '<div id="loginPage" class="login-page"><div class="login-box"><h1>Mark Edwards Apparel<br><span style="font-size:0.8em;font-weight:normal">Product Catalog</span></h1><form id="loginForm"><div class="form-group"><label>Username</label><input type="text" id="username" required></div><div class="form-group"><label>Password</label><input type="password" id="password" required></div><button type="submit" class="btn btn-primary" style="width:100%">Sign In</button><div id="loginError" class="error hidden"></div></form></div></div>';
    
    html += '<div id="mainApp" class="hidden"><header class="header"><h1>Mark Edwards Apparel Product Catalog</h1><div class="search-box"><input type="text" id="searchInput" placeholder="Search products..."></div><div class="header-right"><span id="userInfo"></span><button class="btn btn-secondary" id="adminBtn" style="display:none">Admin</button><button class="btn btn-secondary" id="logoutBtn">Sign Out</button></div></header>';
    
    html += '<main class="main"><div id="adminPanel" class="admin-panel hidden"><h2>Admin Panel</h2><div class="tabs"><button class="tab active" data-tab="zoho">Zoho Sync</button><button class="tab" data-tab="import">Import CSV</button><button class="tab" data-tab="users">Users</button><button class="tab" data-tab="history">Sync History</button><button class="tab" data-tab="freshness">Data Freshness</button><button class="tab" data-tab="shares">Sharing History</button></div>';
    html += '<div id="zohoTab" class="tab-content active"><div class="status-box"><div class="status-item"><span class="status-label">Status: </span><span class="status-value" id="zohoStatusText">Checking...</span></div><div class="status-item"><span class="status-label">Workspace ID: </span><span class="status-value" id="zohoWorkspaceId">-</span></div><div class="status-item"><span class="status-label">View ID: </span><span class="status-value" id="zohoViewId">-</span></div></div><div style="display:flex;gap:1rem"><button class="btn btn-secondary" id="testZohoBtn">Test Connection</button><button class="btn btn-success" id="syncZohoBtn">Sync Now</button></div><div id="zohoMessage" style="margin-top:1rem"></div></div>';
    html += '<div id="importTab" class="tab-content"><div class="upload-area"><input type="file" id="csvFile" accept=".csv"><label for="csvFile">Click to upload CSV file</label></div><div id="importStatus"></div><button class="btn btn-danger" id="clearBtn" style="margin-top:1rem">Clear All Products</button></div>';
    html += '<div id="usersTab" class="tab-content"><table><thead><tr><th>Username</th><th>Role</th><th>Actions</th></tr></thead><tbody id="usersTable"></tbody></table><div class="add-form"><input type="text" id="newUser" placeholder="Username"><input type="password" id="newPass" placeholder="Password"><select id="newRole"><option value="sales_rep">Sales Rep</option><option value="admin">Admin</option></select><button class="btn btn-primary" id="addUserBtn">Add</button></div></div>';
    html += '<div id="historyTab" class="tab-content"><table><thead><tr><th>Date</th><th>Type</th><th>Status</th><th>Records</th><th>Error</th></tr></thead><tbody id="historyTable"></tbody></table></div>';
    html += '<div id="freshnessTab" class="tab-content"><div class="freshness-info" id="freshnessInfo"><p><strong>Last Data Update:</strong> <span id="lastUpdateTime">Loading...</span></p><p><strong>Records Imported:</strong> <span id="lastUpdateRecords">-</span></p></div><p style="color:#666;font-size:0.875rem;margin-top:1rem">This shows when the product catalog data was last updated via CSV import.</p></div>';
    html += '<div id="sharesTab" class="tab-content"><table class="share-history-table"><thead><tr><th>Date</th><th>Name</th><th>Sales Rep</th><th>Type</th><th>Items</th><th>Actions</th></tr></thead><tbody id="sharesTable"></tbody></table></div></div>';
    
    html += '<div class="stats"><div><div class="stat-value" id="totalStyles">0</div><div class="stat-label">Styles</div></div><div><div class="stat-value" id="totalUnits">0</div><div class="stat-label">Units Available</div></div></div>';
    html += '<div class="view-controls"><label>Tile Size:</label><button class="size-btn" data-size="small">Small</button><button class="size-btn active" data-size="medium">Medium</button><button class="size-btn" data-size="large">Large</button><span style="margin-left:1rem"></span><label>Qty:</label><input type="number" id="minQty" placeholder="Min" style="width:70px;padding:0.4rem;border:1px solid #ddd;border-radius:4px"><span style="margin:0 0.25rem">-</span><input type="number" id="maxQty" placeholder="Max" style="width:70px;padding:0.4rem;border:1px solid #ddd;border-radius:4px"><button id="resetQtyBtn" style="margin-left:0.5rem;padding:0.4rem 0.75rem;border:1px solid #ddd;background:#f5f5f5;border-radius:4px;cursor:pointer;font-size:0.875rem">Reset</button><span style="margin-left:auto"></span><button class="select-mode-btn" id="selectModeBtn">Select for Sharing</button></div>';
    html += '<div class="filters" id="filters"></div><div class="product-grid size-medium" id="productGrid"></div><div class="empty hidden" id="emptyState">No products found.</div></main></div>';
    
    // Selection bar
    html += '<div class="selection-bar" id="selectionBar"><span class="selection-count"><span id="selectedCount">0</span> items selected</span><div class="selection-actions"><button class="btn btn-secondary" id="clearSelectionBtn">Clear</button><button class="btn btn-secondary" id="exitSelectionBtn">Exit Selection Mode</button><button class="btn btn-primary" id="shareSelectionBtn">Share / Download</button></div></div>';
    
    // Share modal
    html += '<div class="share-modal" id="shareModal"><div class="share-modal-content"><h3>Share Selection</h3><input type="text" id="selectionName" placeholder="Name this selection (e.g. Spring Collection for Acme Co)"><div class="share-modal-actions"><button class="btn btn-secondary" id="cancelShareBtn">Cancel</button><button class="btn btn-primary" id="createShareBtn">Create Link</button></div><div class="share-result hidden" id="shareResult"><p><strong>Share Link:</strong></p><p><a id="shareLink" href="" target="_blank"></a></p><p style="margin-top:0.5rem"><a id="pdfLink" href="" target="_blank" id="pdfDownloadLink">Download PDF</a></p></div></div></div>';
    
    // Product modal
    html += '<div class="modal" id="modal"><div class="modal-content"><button class="modal-close" id="modalClose">&times;</button><div class="modal-body"><div class="modal-image"><img id="modalImage" src="" alt=""></div><div class="modal-details"><div class="product-style" id="modalStyle"></div><h2 id="modalName"></h2><p id="modalCategory" style="color:#666;margin-bottom:1rem"></p><div id="modalColors"></div><div class="total-row"><span>Total Available</span><span id="modalTotal"></span></div></div></div></div></div>';
    
    html += '<script>';
    html += 'var products=[];var currentFilter="all";var currentSize="medium";var selectedProducts=[];var selectionMode=false;var currentShareId=null;';
    
    html += 'function checkSession(){fetch("/api/session").then(function(r){return r.json()}).then(function(d){if(d.loggedIn){showApp(d.username,d.role);loadProducts();loadZohoStatus();loadDataFreshness();if(d.role==="admin"){loadUsers();loadHistory();loadShares()}}})}';
    html += 'function showApp(u,r){document.getElementById("loginPage").classList.add("hidden");document.getElementById("mainApp").classList.remove("hidden");document.getElementById("userInfo").textContent="Welcome, "+u;if(r==="admin")document.getElementById("adminBtn").style.display="block"}';
    
    html += 'document.getElementById("loginForm").addEventListener("submit",function(e){e.preventDefault();fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:document.getElementById("username").value,password:document.getElementById("password").value})}).then(function(r){return r.json()}).then(function(d){if(d.success){showApp(d.username,d.role);loadProducts();loadZohoStatus();loadDataFreshness();if(d.role==="admin"){loadUsers();loadHistory();loadShares()}}else{document.getElementById("loginError").textContent=d.error;document.getElementById("loginError").classList.remove("hidden")}})});';
    
    html += 'document.getElementById("logoutBtn").addEventListener("click",function(){fetch("/api/logout",{method:"POST"}).then(function(){location.reload()})});';
    html += 'document.getElementById("adminBtn").addEventListener("click",function(){document.getElementById("adminPanel").classList.toggle("hidden")});';
    
    html += 'var tabs=document.querySelectorAll(".tab");for(var i=0;i<tabs.length;i++){tabs[i].addEventListener("click",function(e){document.querySelectorAll(".tab").forEach(function(t){t.classList.remove("active")});document.querySelectorAll(".tab-content").forEach(function(c){c.classList.remove("active")});e.target.classList.add("active");document.getElementById(e.target.getAttribute("data-tab")+"Tab").classList.add("active")})}';
    
    html += 'var sizeBtns=document.querySelectorAll(".size-btn");sizeBtns.forEach(function(btn){btn.addEventListener("click",function(e){sizeBtns.forEach(function(b){b.classList.remove("active")});e.target.classList.add("active");currentSize=e.target.getAttribute("data-size");document.getElementById("productGrid").className="product-grid size-"+currentSize})});';
    
    html += 'function loadZohoStatus(){fetch("/api/zoho/status").then(function(r){return r.json()}).then(function(d){var st=document.getElementById("zohoStatusText");if(d.connected){st.textContent="Connected";st.className="status-value connected"}else{st.textContent="Not connected";st.className="status-value disconnected"}document.getElementById("zohoWorkspaceId").textContent=d.workspaceId||"Not set";document.getElementById("zohoViewId").textContent=d.viewId||"Not set"})}';
    
    html += 'function loadDataFreshness(){fetch("/api/data-freshness").then(function(r){return r.json()}).then(function(d){if(d.lastUpdate){var dt=new Date(d.lastUpdate);document.getElementById("lastUpdateTime").textContent=dt.toLocaleString();document.getElementById("lastUpdateRecords").textContent=d.recordCount.toLocaleString()+" records";var hoursSince=(Date.now()-dt.getTime())/(1000*60*60);if(hoursSince>24){document.getElementById("freshnessInfo").classList.add("stale")}}else{document.getElementById("lastUpdateTime").textContent="No data imported yet";document.getElementById("lastUpdateRecords").textContent="-"}})}';
    
    html += 'function loadShares(){fetch("/api/selections").then(function(r){return r.json()}).then(function(shares){var h="";shares.forEach(function(s){var dt=new Date(s.created_at).toLocaleString();var type=s.share_type||"link";var badge=type==="pdf"?"<span class=\\"share-type-badge pdf\\">PDF</span>":"<span class=\\"share-type-badge link\\">Link</span>";var itemCount=(s.product_ids||[]).length;h+="<tr><td>"+dt+"</td><td>"+s.name+"</td><td>"+s.created_by+"</td><td>"+badge+"</td><td>"+itemCount+"</td><td><a href=\\"/share/"+s.share_id+"\\" target=\\"_blank\\">View</a></td></tr>"});document.getElementById("sharesTable").innerHTML=h||"<tr><td colspan=6 style=\\"text-align:center;color:#666\\">No shares yet</td></tr>"})}';
    
    html += 'document.getElementById("testZohoBtn").addEventListener("click",function(){document.getElementById("zohoMessage").innerHTML="Testing...";fetch("/api/zoho/test",{method:"POST"}).then(function(r){return r.json()}).then(function(d){document.getElementById("zohoMessage").innerHTML=d.success?"<span class=success>"+d.message+"</span>":"<span class=error>"+d.error+"</span>";loadZohoStatus()})});';
    html += 'document.getElementById("syncZohoBtn").addEventListener("click",function(){document.getElementById("zohoMessage").innerHTML="Syncing...";fetch("/api/zoho/sync",{method:"POST"}).then(function(r){return r.json()}).then(function(d){document.getElementById("zohoMessage").innerHTML=d.success?"<span class=success>"+d.message+"</span>":"<span class=error>"+d.error+"</span>";loadProducts();loadHistory();loadDataFreshness()})});';
    
    html += 'function getImageUrl(url){if(!url)return null;if(url.indexOf("download-accl.zoho.com")!==-1){return"/api/image/"+url.split("/").pop()}return url}';
    html += 'function loadProducts(){fetch("/api/products").then(function(r){return r.json()}).then(function(d){products=d;renderFilters();renderProducts()})}';
    
    html += 'function renderFilters(){var cats=[];products.forEach(function(p){if(p.category&&cats.indexOf(p.category)===-1)cats.push(p.category)});cats.sort();var h="<button class=\\"filter-btn active\\" data-cat=\\"all\\">All</button>";cats.forEach(function(c){h+="<button class=\\"filter-btn\\" data-cat=\\""+c+"\\">"+c+"</button>"});document.getElementById("filters").innerHTML=h;document.querySelectorAll(".filter-btn").forEach(function(btn){btn.addEventListener("click",function(e){document.querySelectorAll(".filter-btn").forEach(function(b){b.classList.remove("active")});e.target.classList.add("active");currentFilter=e.target.getAttribute("data-cat");renderProducts()})})}';
    
    // Selection mode toggle
    html += 'document.getElementById("selectModeBtn").addEventListener("click",function(){selectionMode=!selectionMode;this.classList.toggle("active",selectionMode);if(!selectionMode){selectedProducts=[];updateSelectionUI()}renderProducts()});';
    
    html += 'document.getElementById("exitSelectionBtn").addEventListener("click",function(){selectionMode=false;selectedProducts=[];document.getElementById("selectModeBtn").classList.remove("active");updateSelectionUI();renderProducts()});';
    
    html += 'function handleCardClick(id,e){if(selectionMode){e.stopPropagation();var idx=selectedProducts.indexOf(id);if(idx===-1){selectedProducts.push(id)}else{selectedProducts.splice(idx,1)}updateSelectionUI();renderProducts()}else{showProductModal(id)}}';
    
    html += 'function showProductModal(id){var pr=products.find(function(p){return p.id===id});if(!pr)return;var imgUrl=getImageUrl(pr.image_url);document.getElementById("modalImage").src=imgUrl||"";document.getElementById("modalStyle").textContent=pr.style_id;document.getElementById("modalName").textContent=pr.name;document.getElementById("modalCategory").textContent=pr.category||"";var cols=pr.colors||[];var tot=0;var ch="";cols.forEach(function(c){tot+=c.available_qty||0;ch+="<div class=\\"color-row\\"><span>"+c.color_name+"</span><span>"+(c.available_qty||0).toLocaleString()+"</span></div>"});document.getElementById("modalColors").innerHTML=ch;document.getElementById("modalTotal").textContent=tot.toLocaleString();document.getElementById("modal").classList.add("active")}';
    
    html += 'function updateSelectionUI(){document.getElementById("selectedCount").textContent=selectedProducts.length;var bar=document.getElementById("selectionBar");if(selectedProducts.length>0&&selectionMode){bar.classList.add("visible")}else{bar.classList.remove("visible")}}';
    
    html += 'function renderProducts(){var s=document.getElementById("searchInput").value.toLowerCase();var minQ=parseInt(document.getElementById("minQty").value)||0;var maxQ=parseInt(document.getElementById("maxQty").value)||999999999;var f=products.filter(function(p){var ms=!s||p.style_id.toLowerCase().indexOf(s)!==-1||p.name.toLowerCase().indexOf(s)!==-1;var mc=currentFilter==="all"||p.category===currentFilter;var tot=0;(p.colors||[]).forEach(function(c){tot+=c.available_qty||0});var mq=tot>=minQ&&tot<=maxQ;return ms&&mc&&mq});if(f.length===0){document.getElementById("productGrid").innerHTML="";document.getElementById("emptyState").classList.remove("hidden")}else{document.getElementById("emptyState").classList.add("hidden");var h="";f.forEach(function(pr){var cols=pr.colors||[];var tot=0;cols.forEach(function(c){tot+=c.available_qty||0});var ch="";var mx=Math.min(cols.length,3);for(var d=0;d<mx;d++){ch+="<div class=\\"color-row\\"><span>"+cols[d].color_name+"</span><span>"+(cols[d].available_qty||0).toLocaleString()+"</span></div>"}if(cols.length>3)ch+="<div class=\\"color-row\\" style=\\"color:#999\\">+"+(cols.length-3)+" more</div>";var imgUrl=getImageUrl(pr.image_url);var im=imgUrl?"<img src=\\""+imgUrl+"\\" onerror=\\"this.parentElement.innerHTML=\'No Image\'\\">":"No Image";var sel=selectedProducts.indexOf(pr.id)!==-1?"selected":"";var selModeClass=selectionMode?"selection-mode":"";h+="<div class=\\"product-card "+sel+" "+selModeClass+"\\" onclick=\\"handleCardClick("+pr.id+",event)\\"><div class=\\"select-badge\\">✓</div><div class=\\"product-image\\">"+im+"</div><div class=\\"product-info\\"><div class=\\"product-style\\">"+pr.style_id+"</div><div class=\\"product-name\\">"+pr.name+"</div><div class=\\"color-list\\">"+ch+"</div><div class=\\"total-row\\"><span>Total</span><span>"+tot.toLocaleString()+"</span></div></div></div>"});document.getElementById("productGrid").innerHTML=h}document.getElementById("totalStyles").textContent=f.length;var tu=0;f.forEach(function(p){(p.colors||[]).forEach(function(c){tu+=c.available_qty||0})});document.getElementById("totalUnits").textContent=tu.toLocaleString()}';
    
    html += 'document.getElementById("searchInput").addEventListener("input",renderProducts);';
    html += 'document.getElementById("minQty").addEventListener("input",renderProducts);';
    html += 'document.getElementById("maxQty").addEventListener("input",renderProducts);';
    html += 'document.getElementById("resetQtyBtn").addEventListener("click",function(){document.getElementById("minQty").value="";document.getElementById("maxQty").value="";renderProducts()});';
    
    html += 'document.getElementById("clearSelectionBtn").addEventListener("click",function(){selectedProducts=[];updateSelectionUI();renderProducts()});';
    
    html += 'document.getElementById("shareSelectionBtn").addEventListener("click",function(){document.getElementById("shareModal").classList.add("active");document.getElementById("shareResult").classList.add("hidden");document.getElementById("selectionName").value=""});';
    html += 'document.getElementById("cancelShareBtn").addEventListener("click",function(){document.getElementById("shareModal").classList.remove("active")});';
    
    html += 'document.getElementById("createShareBtn").addEventListener("click",function(){var name=document.getElementById("selectionName").value||"Product Selection";fetch("/api/selections",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({productIds:selectedProducts,name:name,shareType:"link"})}).then(function(r){return r.json()}).then(function(d){if(d.success){currentShareId=d.shareId;var url=window.location.origin+"/share/"+d.shareId;document.getElementById("shareLink").href=url;document.getElementById("shareLink").textContent=url;document.getElementById("pdfLink").href="/api/selections/"+d.shareId+"/pdf";document.getElementById("shareResult").classList.remove("hidden");loadShares()}else{alert(d.error)}})});';
    
    // Record PDF download
    html += 'document.getElementById("pdfLink").addEventListener("click",function(){if(currentShareId){fetch("/api/selections/"+currentShareId+"/record-pdf",{method:"POST"}).then(function(){loadShares()})}});';
    
    html += 'document.getElementById("csvFile").addEventListener("change",function(e){var f=e.target.files[0];if(!f)return;var fd=new FormData();fd.append("file",f);document.getElementById("importStatus").innerHTML="Importing...";fetch("/api/import",{method:"POST",body:fd}).then(function(r){return r.json()}).then(function(d){document.getElementById("importStatus").innerHTML=d.success?"<span class=success>Imported "+d.imported+" products</span>":"<span class=error>"+d.error+"</span>";loadProducts();loadHistory();loadDataFreshness()})});';
    html += 'document.getElementById("clearBtn").addEventListener("click",function(){if(!confirm("Delete all products?"))return;fetch("/api/products/clear",{method:"POST"}).then(function(){loadProducts()})});';
    
    html += 'function loadUsers(){fetch("/api/users").then(function(r){return r.json()}).then(function(u){var h="";u.forEach(function(x){h+="<tr><td>"+x.username+"</td><td>"+x.role+"</td><td><button class=\\"btn btn-danger\\" onclick=\\"deleteUser("+x.id+")\\">Delete</button></td></tr>"});document.getElementById("usersTable").innerHTML=h})}';
    html += 'document.getElementById("addUserBtn").addEventListener("click",function(){var u=document.getElementById("newUser").value;var p=document.getElementById("newPass").value;if(!u||!p){alert("Enter username and password");return}fetch("/api/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p,role:document.getElementById("newRole").value})}).then(function(){document.getElementById("newUser").value="";document.getElementById("newPass").value="";loadUsers()})});';
    html += 'function deleteUser(id){if(!confirm("Delete user?"))return;fetch("/api/users/"+id,{method:"DELETE"}).then(function(){loadUsers()})}';
    
    html += 'function loadHistory(){fetch("/api/zoho/sync-history").then(function(r){return r.json()}).then(function(h){var html="";h.forEach(function(x){html+="<tr><td>"+new Date(x.created_at).toLocaleString()+"</td><td>"+x.sync_type+"</td><td>"+x.status+"</td><td>"+(x.records_synced||"-")+"</td><td>"+(x.error_message||"-")+"</td></tr>"});document.getElementById("historyTable").innerHTML=html})}';
    
    html += 'document.getElementById("modalClose").addEventListener("click",function(){document.getElementById("modal").classList.remove("active")});';
    html += 'document.getElementById("modal").addEventListener("click",function(e){if(e.target.id==="modal")document.getElementById("modal").classList.remove("active")});';
    
    html += 'checkSession();';
    html += '</script></body></html>';
    return html;
}

initDB().then(function() {
    app.listen(PORT, function() { console.log("Product Catalog running on port " + PORT); });
    setTimeout(function() { startTokenRefreshJob(); }, 5000);
});
