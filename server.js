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
    res.json({ loggedIn: true, username: 'admin', role: 'admin' });
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
        
        if (!clientId || !clientSecret || !refreshToken) {
            console.log('Missing Zoho credentials in environment');
            return { success: false, error: 'Missing Zoho credentials' };
        }
        
        var params = new URLSearchParams();
        params.append('refresh_token', refreshToken);
        params.append('client_id', clientId);
        params.append('client_secret', clientSecret);
        params.append('grant_type', 'refresh_token');
        
        var response = await fetch('https://accounts.zoho.com/oauth/v2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params.toString()
        });
        
        var data = await response.json();
        
        if (data.access_token) {
            zohoAccessToken = data.access_token;
            var expiresAt = new Date(Date.now() + (data.expires_in || 3600) * 1000);
            await pool.query('INSERT INTO zoho_tokens (access_token, refresh_token, expires_at, updated_at) VALUES ($1, $2, $3, NOW())', [zohoAccessToken, refreshToken, expiresAt]);
            console.log('Zoho token refreshed successfully');
            return { success: true };
        } else {
            console.error('Failed to refresh Zoho token:', data);
            return { success: false, error: data.error || 'Token refresh failed' };
        }
    } catch (err) {
        console.error('Error refreshing Zoho token:', err);
        return { success: false, error: err.message };
    }
}

function startTokenRefreshJob() {
    console.log('Starting background token refresh job (every 30 minutes)');
    refreshZohoToken();
    setInterval(function() { refreshZohoToken(); }, 30 * 60 * 1000);
}

app.get('/api/zoho/status', requireAuth, function(req, res) {
    var hasCredentials = !!(process.env.ZOHO_CLIENT_ID && process.env.ZOHO_CLIENT_SECRET && process.env.ZOHO_REFRESH_TOKEN);
    var hasToken = !!zohoAccessToken;
    var hasViewId = !!process.env.ZOHO_VIEW_ID;
    var hasWorkspaceId = !!process.env.ZOHO_WORKSPACE_ID;
    res.json({ configured: hasCredentials, connected: hasToken, viewConfigured: hasViewId && hasWorkspaceId, viewId: process.env.ZOHO_VIEW_ID || null, workspaceId: process.env.ZOHO_WORKSPACE_ID || null });
});

app.post('/api/zoho/test', requireAuth, requireAdmin, async function(req, res) {
    try {
        if (!zohoAccessToken) {
            var tokenResult = await refreshZohoToken();
            if (!tokenResult.success) return res.json({ success: false, error: tokenResult.error });
        }
        res.json({ success: true, message: 'Connection successful' });
    } catch (err) { res.json({ success: false, error: err.message }); }
});

app.post('/api/zoho/sync', requireAuth, requireAdmin, async function(req, res) {
    try {
        var workspaceId = process.env.ZOHO_WORKSPACE_ID;
        var viewId = process.env.ZOHO_VIEW_ID;
        if (!workspaceId) { await pool.query('INSERT INTO sync_history (sync_type, status, error_message) VALUES ($1, $2, $3)', ['zoho', 'failed', 'ZOHO_WORKSPACE_ID not configured']); return res.json({ success: false, error: 'ZOHO_WORKSPACE_ID not configured in Railway variables' }); }
        if (!viewId) { await pool.query('INSERT INTO sync_history (sync_type, status, error_message) VALUES ($1, $2, $3)', ['zoho', 'failed', 'ZOHO_VIEW_ID not configured']); return res.json({ success: false, error: 'ZOHO_VIEW_ID not configured in Railway variables' }); }
        if (!zohoAccessToken) { var tokenResult = await refreshZohoToken(); if (!tokenResult.success) { await pool.query('INSERT INTO sync_history (sync_type, status, error_message) VALUES ($1, $2, $3)', ['zoho', 'failed', tokenResult.error]); return res.json({ success: false, error: tokenResult.error }); } }
        var apiUrl = 'https://analyticsapi.zoho.com/restapi/v2/workspaces/' + workspaceId + '/views/' + viewId + '/data?CONFIG={"responseFormat":"json"}';
        console.log('Fetching from Zoho:', apiUrl);
        var response = await fetch(apiUrl, { headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken } });
        if (response.status === 401) { console.log('Got 401, refreshing token...'); var tokenResult = await refreshZohoToken(); if (!tokenResult.success) { await pool.query('INSERT INTO sync_history (sync_type, status, error_message) VALUES ($1, $2, $3)', ['zoho', 'failed', tokenResult.error]); return res.json({ success: false, error: tokenResult.error }); } response = await fetch(apiUrl, { headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken } }); }
        if (!response.ok) { var errorText = await response.text(); console.error('Zoho API error:', response.status, errorText); await pool.query('INSERT INTO sync_history (sync_type, status, error_message) VALUES ($1, $2, $3)', ['zoho', 'failed', 'API error: ' + response.status]); return res.json({ success: false, error: 'API error: ' + response.status + ' - ' + errorText }); }
        var data = await response.json(); console.log('Zoho response keys:', Object.keys(data));
        var rows = data.data || data.rows || []; var columns = data.column_order || data.columns || [];
        if (rows.length === 0) { await pool.query('INSERT INTO sync_history (sync_type, status, error_message) VALUES ($1, $2, $3)', ['zoho', 'failed', 'No data returned']); return res.json({ success: false, error: 'No data returned from Zoho Analytics' }); }
        var colMap = {}; for (var ci = 0; ci < columns.length; ci++) { colMap[columns[ci].toLowerCase().replace(/\s+/g, '_')] = ci; } console.log('Column map:', colMap);
        await pool.query('DELETE FROM product_colors'); await pool.query('DELETE FROM products');
        var productMap = {}; var recordCount = 0;
        for (var ri = 0; ri < rows.length; ri++) { var row = rows[ri]; var styleIdx = colMap['style_name'] !== undefined ? colMap['style_name'] : (colMap['style'] !== undefined ? colMap['style'] : 0); var colorIdx = colMap['color'] !== undefined ? colMap['color'] : (colMap['color_name'] !== undefined ? colMap['color_name'] : 1); var categoryIdx = colMap['commodity'] !== undefined ? colMap['commodity'] : (colMap['category'] !== undefined ? colMap['category'] : 2); var qtyIdx = colMap['left_to_sell'] !== undefined ? colMap['left_to_sell'] : (colMap['available'] !== undefined ? colMap['available'] : 3); var styleName = row[styleIdx] || 'Unknown Style'; var color = row[colorIdx] || 'Default'; var category = row[categoryIdx] || 'Uncategorized'; var qty = parseInt(row[qtyIdx]) || 0; var baseStyle = styleName.replace(/\s*-\s*\d+$/, '').trim(); if (!productMap[baseStyle]) { var insertResult = await pool.query('INSERT INTO products (style_id, base_style, name, category) VALUES ($1, $2, $3, $4) RETURNING id', [styleName, baseStyle, baseStyle, category]); productMap[baseStyle] = insertResult.rows[0].id; } var productId = productMap[baseStyle]; await pool.query('INSERT INTO product_colors (product_id, color_name, available_qty) VALUES ($1, $2, $3)', [productId, color, qty]); recordCount++; }
        await pool.query('INSERT INTO sync_history (sync_type, status, records_synced) VALUES ($1, $2, $3)', ['zoho', 'success', recordCount]);
        res.json({ success: true, message: 'Synced ' + recordCount + ' records from ' + Object.keys(productMap).length + ' products' });
    } catch (err) { console.error('Sync error:', err); await pool.query('INSERT INTO sync_history (sync_type, status, error_message) VALUES ($1, $2, $3)', ['zoho', 'failed', err.message]); res.json({ success: false, error: err.message }); }
});

app.get('/api/zoho/sync-history', requireAuth, async function(req, res) { try { var result = await pool.query('SELECT * FROM sync_history ORDER BY created_at DESC LIMIT 20'); res.json(result.rows); } catch (err) { res.status(500).json({ error: err.message }); } });

function parseCSVLine(line) { var result = []; var current = ''; var inQuotes = false; for (var i = 0; i < line.length; i++) { var char = line[i]; if (char === '"') { inQuotes = !inQuotes; } else if (char === ',' && !inQuotes) { result.push(current.trim()); current = ''; } else { current += char; } } result.push(current.trim()); return result; }
function parseNumber(val) { if (!val) return 0; return parseInt(val.toString().replace(/,/g, '').replace(/"/g, '').trim()) || 0; }

app.post('/api/import', requireAuth, requireAdmin, upload.single('file'), async function(req, res) {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        var content = req.file.buffer.toString('utf-8'); var allLines = content.split('\n'); var lines = []; for (var i = 0; i < allLines.length; i++) { if (allLines[i].trim()) lines.push(allLines[i]); } if (lines.length < 2) return res.status(400).json({ error: 'File appears empty' });
        var headerLine = lines[0]; if (headerLine.charCodeAt(0) === 0xFEFF) headerLine = headerLine.slice(1); var headersRaw = parseCSVLine(headerLine); var headers = []; for (var h = 0; h < headersRaw.length; h++) { headers.push(headersRaw[h].toLowerCase().replace(/[^\w\s]/g, '').trim()); } console.log('CSV Headers:', headers);
        var headerMap = {}; for (var hi = 0; hi < headers.length; hi++) { headerMap[headers[hi]] = hi; }
        var imported = 0, skipped = 0; var lastStyleId = null, lastImageUrl = null, lastCategory = null;
        for (var li = 1; li < lines.length; li++) { try { var values = parseCSVLine(lines[li]); if (values[0] && values[0].indexOf('Grand Summary') !== -1) { skipped++; continue; } var styleId = values[headerMap['style name']] || values[0]; var imageUrl = values[headerMap['style image']] || values[1]; var color = values[headerMap['color']] || values[2]; var category = values[headerMap['commodity']] || values[3]; var onHand = parseNumber(values[headerMap['on hand']] || values[4]); var available = parseNumber(values[headerMap['available now']] || values[headerMap['left to sell']] || values[7]); if (!styleId && color) { styleId = lastStyleId; if (!imageUrl || imageUrl === '-No Value-') imageUrl = lastImageUrl; if (!category || category === '-No Value-') category = lastCategory; } if (!styleId) { skipped++; continue; } lastStyleId = styleId; if (imageUrl && imageUrl !== '-No Value-' && imageUrl.indexOf('http') === 0) lastImageUrl = imageUrl; if (category && category !== '-No Value-') lastCategory = category; var baseStyle = styleId.split('-')[0]; var validCategory = (category && category !== '-No Value-') ? category : 'Uncategorized'; var name = validCategory + ' - ' + baseStyle; var validImageUrl = (imageUrl && imageUrl !== '-No Value-' && imageUrl.indexOf('http') === 0) ? imageUrl : lastImageUrl; var productResult = await pool.query('SELECT id, image_url FROM products WHERE style_id = $1', [styleId]); var productId; if (productResult.rows.length > 0) { productId = productResult.rows[0].id; var finalImage = validImageUrl || productResult.rows[0].image_url; await pool.query('UPDATE products SET name=$1, category=$2, base_style=$3, image_url=$4, updated_at=CURRENT_TIMESTAMP WHERE id=$5', [name, validCategory, baseStyle, finalImage, productId]); } else { var ins = await pool.query('INSERT INTO products (style_id, base_style, name, category, image_url) VALUES ($1,$2,$3,$4,$5) RETURNING id', [styleId, baseStyle, name, validCategory, validImageUrl]); productId = ins.rows[0].id; } if (color && color !== '-No Value-') { var colorResult = await pool.query('SELECT id FROM product_colors WHERE product_id=$1 AND color_name=$2', [productId, color]); if (colorResult.rows.length > 0) { await pool.query('UPDATE product_colors SET available_qty=$1, on_hand=$2, updated_at=CURRENT_TIMESTAMP WHERE id=$3', [available, onHand, colorResult.rows[0].id]); } else { await pool.query('INSERT INTO product_colors (product_id, color_name, available_qty, on_hand) VALUES ($1,$2,$3,$4)', [productId, color, available, onHand]); } } imported++; } catch (rowErr) { console.error('Row error:', rowErr.message); skipped++; } }
        await pool.query('INSERT INTO sync_history (sync_type, status, records_synced) VALUES ($1,$2,$3)', ['csv_import', 'success', imported]);
        res.json({ success: true, imported: imported, skipped: skipped });
    } catch (err) { console.error('Import error:', err); res.status(500).json({ error: err.message }); }
});

app.post('/api/products/clear', requireAuth, requireAdmin, async function(req, res) { try { await pool.query('DELETE FROM product_colors'); await pool.query('DELETE FROM products'); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/users', requireAuth, requireAdmin, async function(req, res) { try { var result = await pool.query('SELECT id, username, role, created_at FROM users ORDER BY created_at'); res.json(result.rows); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/users', requireAuth, requireAdmin, async function(req, res) { try { var username = req.body.username; var password = req.body.password; var role = req.body.role; var hash = await bcrypt.hash(password, 10); await pool.query('INSERT INTO users (username, password, role) VALUES ($1,$2,$3)', [username, hash, role || 'sales_rep']); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete('/api/users/:id', requireAuth, requireAdmin, async function(req, res) { try { await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); } });

// Image proxy for WorkDrive images - FIXED VERSION
app.get('/api/image/:fileId', async function(req, res) {
    var retryCount = 0;
    async function fetchImage() {
        try {
            var fileId = req.params.fileId;
            if (!zohoAccessToken) { var tokenResult = await refreshZohoToken(); if (!tokenResult.success) { return res.status(401).send('No valid token'); } }
            var imageUrl = 'https://workdrive.zoho.com/api/v1/download/' + fileId;
            console.log('Fetching image:', imageUrl);
            var response = await fetch(imageUrl, { headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken, 'Accept': 'application/vnd.api+json' } });
            console.log('WorkDrive response status:', response.status);
            if (response.status === 401) { if (retryCount === 0) { retryCount++; console.log('Got 401, refreshing token and retrying...'); await refreshZohoToken(); return fetchImage(); } return res.status(401).send('Authentication failed'); }
            if (!response.ok) { var errorText = await response.text(); console.error('WorkDrive image fetch failed:', response.status, errorText); return res.status(response.status).send('Image not found'); }
            var contentType = response.headers.get('content-type') || 'image/jpeg';
            res.setHeader('Content-Type', contentType);
            res.setHeader('Cache-Control', 'public, max-age=86400');
            var buffer = await response.arrayBuffer();
            res.send(Buffer.from(buffer));
        } catch (err) { console.error('Image proxy error:', err); res.status(500).send('Error fetching image'); }
    }
    fetchImage();
});

app.get('*', function(req, res) { res.send(getHTML()); });

function getHTML() {
    var html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Product Catalog</title><style>';
    html += '* { margin: 0; padding: 0; box-sizing: border-box; }';
    html += 'body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #f5f5f5; }';
    html += '.login-page { min-height: 100vh; display: flex; align-items: center; justify-content: center; }';
    html += '.login-box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 100%; max-width: 360px; }';
    html += '.login-box h1 { margin-bottom: 1.5rem; font-size: 1.5rem; text-align: center; }';
    html += '.form-group { margin-bottom: 1rem; }';
    html += '.form-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }';
    html += '.form-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; }';
    html += '.btn { padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }';
    html += '.btn-primary { background: #2c5545; color: white; }';
    html += '.btn-secondary { background: #eee; color: #333; }';
    html += '.btn-danger { background: #c4553d; color: white; }';
    html += '.btn-success { background: #2e7d32; color: white; }';
    html += '.error { color: #c4553d; margin-top: 1rem; text-align: center; }';
    html += '.success { color: #2e7d32; }';
    html += '.hidden { display: none !important; }';
    html += '.header { background: white; padding: 1rem 2rem; border-bottom: 1px solid #ddd; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }';
    html += '.header h1 { font-size: 1.25rem; }';
    html += '.header-right { display: flex; gap: 1rem; align-items: center; }';
    html += '.search-box input { padding: 0.5rem 1rem; border: 1px solid #ddd; border-radius: 4px; width: 250px; }';
    html += '.main { max-width: 1400px; margin: 0 auto; padding: 2rem; }';
    html += '.admin-panel { background: white; padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem; }';
    html += '.admin-panel h2 { margin-bottom: 1rem; }';
    html += '.tabs { display: flex; gap: 0.5rem; margin-bottom: 1rem; }';
    html += '.tab { padding: 0.5rem 1rem; border: none; background: #eee; cursor: pointer; border-radius: 4px; }';
    html += '.tab.active { background: #2c5545; color: white; }';
    html += '.tab-content { display: none; }';
    html += '.tab-content.active { display: block; }';
    html += '.upload-area { border: 2px dashed #ddd; padding: 2rem; text-align: center; border-radius: 4px; margin-bottom: 1rem; }';
    html += '.upload-area input { display: none; }';
    html += '.upload-area label { color: #2c5545; cursor: pointer; }';
    html += '.stats { display: flex; gap: 2rem; margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 8px; }';
    html += '.stat-value { font-size: 1.5rem; font-weight: bold; }';
    html += '.stat-label { color: #666; font-size: 0.875rem; }';
    html += '.filters { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }';
    html += '.filter-btn { padding: 0.5rem 1rem; border: 1px solid #ddd; background: white; border-radius: 20px; cursor: pointer; }';
    html += '.filter-btn.active { background: #2c5545; color: white; border-color: #2c5545; }';
    html += '.product-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1.5rem; }';
    html += '.product-card { background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); cursor: pointer; transition: transform 0.2s; }';
    html += '.product-card:hover { transform: translateY(-2px); box-shadow: 0 4px 16px rgba(0,0,0,0.15); }';
    html += '.product-image { height: 200px; background: #f0f0f0; display: flex; align-items: center; justify-content: center; overflow: hidden; }';
    html += '.product-image img { width: 100%; height: 100%; object-fit: cover; }';
    html += '.product-info { padding: 1rem; }';
    html += '.product-style { font-size: 0.75rem; color: #666; text-transform: uppercase; }';
    html += '.product-name { font-size: 1.1rem; font-weight: 600; margin: 0.25rem 0; }';
    html += '.color-list { margin-top: 0.75rem; }';
    html += '.color-row { display: flex; justify-content: space-between; padding: 0.25rem 0; font-size: 0.875rem; }';
    html += '.total-row { margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid #eee; font-weight: bold; display: flex; justify-content: space-between; }';
    html += '.empty { text-align: center; padding: 3rem; color: #666; }';
    html += '.modal { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: none; align-items: center; justify-content: center; z-index: 1000; }';
    html += '.modal.active { display: flex; }';
    html += '.modal-content { background: white; border-radius: 8px; max-width: 800px; width: 90%; max-height: 90vh; overflow: auto; position: relative; }';
    html += '.modal-body { display: flex; }';
    html += '.modal-image { width: 50%; background: #f0f0f0; min-height: 300px; }';
    html += '.modal-image img { width: 100%; height: 100%; object-fit: cover; }';
    html += '.modal-details { width: 50%; padding: 2rem; }';
    html += '.modal-close { position: absolute; top: 1rem; right: 1rem; background: white; border: none; font-size: 1.5rem; cursor: pointer; border-radius: 50%; width: 36px; height: 36px; }';
    html += 'table { width: 100%; border-collapse: collapse; }';
    html += 'th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #eee; }';
    html += '.add-form { display: flex; gap: 0.5rem; margin-top: 1rem; flex-wrap: wrap; }';
    html += '.add-form input, .add-form select { padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; }';
    html += '.status-box { padding: 1rem; background: #f9f9f9; border-radius: 4px; margin-bottom: 1rem; }';
    html += '.status-item { margin-bottom: 0.5rem; }';
    html += '.status-label { font-weight: 500; }';
    html += '.status-value { color: #666; }';
    html += '.status-value.connected { color: #2e7d32; }';
    html += '.status-value.disconnected { color: #c4553d; }';
    html += '</style></head><body>';
    
    html += '<div id="loginPage" class="login-page"><div class="login-box"><h1>Product Catalog</h1>';
    html += '<form id="loginForm"><div class="form-group"><label>Username</label><input type="text" id="username" required></div>';
    html += '<div class="form-group"><label>Password</label><input type="password" id="password" required></div>';
    html += '<button type="submit" class="btn btn-primary" style="width:100%">Sign In</button>';
    html += '<div id="loginError" class="error hidden"></div></form></div></div>';
    
    html += '<div id="mainApp" class="hidden"><header class="header"><h1>Product Catalog</h1>';
    html += '<div class="search-box"><input type="text" id="searchInput" placeholder="Search products..."></div>';
    html += '<div class="header-right"><span id="userInfo"></span>';
    html += '<button class="btn btn-secondary" id="adminBtn" style="display:none">Admin</button>';
    html += '<button class="btn btn-secondary" id="logoutBtn">Sign Out</button></div></header>';
    
    html += '<main class="main"><div id="adminPanel" class="admin-panel hidden"><h2>Admin Panel</h2>';
    html += '<div class="tabs"><button class="tab active" data-tab="zoho">Zoho Sync</button>';
    html += '<button class="tab" data-tab="import">Import CSV</button>';
    html += '<button class="tab" data-tab="users">Users</button>';
    html += '<button class="tab" data-tab="history">History</button></div>';
    
    html += '<div id="zohoTab" class="tab-content active">';
    html += '<div class="status-box" id="zohoStatusBox"><div class="status-item"><span class="status-label">Status: </span><span class="status-value" id="zohoStatusText">Checking...</span></div>';
    html += '<div class="status-item"><span class="status-label">Workspace ID: </span><span class="status-value" id="zohoWorkspaceId">-</span></div>';
    html += '<div class="status-item"><span class="status-label">View ID: </span><span class="status-value" id="zohoViewId">-</span></div></div>';
    html += '<p style="margin-bottom:1rem;color:#666">Configure ZOHO_CLIENT_ID, ZOHO_CLIENT_SECRET, ZOHO_REFRESH_TOKEN, ZOHO_WORKSPACE_ID, and ZOHO_VIEW_ID in Railway environment variables.</p>';
    html += '<div style="display:flex;gap:1rem"><button class="btn btn-secondary" id="testZohoBtn">Test Connection</button>';
    html += '<button class="btn btn-success" id="syncZohoBtn">Sync Now</button></div>';
    html += '<div id="zohoMessage" style="margin-top:1rem"></div></div>';
    
    html += '<div id="importTab" class="tab-content"><div class="upload-area"><input type="file" id="csvFile" accept=".csv">';
    html += '<label for="csvFile">Click to upload CSV file</label></div><div id="importStatus"></div>';
    html += '<button class="btn btn-danger" id="clearBtn" style="margin-top:1rem">Clear All Products</button></div>';
    
    html += '<div id="usersTab" class="tab-content"><table><thead><tr><th>Username</th><th>Role</th><th>Actions</th></tr></thead>';
    html += '<tbody id="usersTable"></tbody></table><div class="add-form"><input type="text" id="newUser" placeholder="Username">';
    html += '<input type="password" id="newPass" placeholder="Password">';
    html += '<select id="newRole"><option value="sales_rep">Sales Rep</option><option value="admin">Admin</option></select>';
    html += '<button class="btn btn-primary" id="addUserBtn">Add</button></div></div>';
    
    html += '<div id="historyTab" class="tab-content"><table><thead><tr><th>Date</th><th>Type</th><th>Status</th><th>Records</th><th>Error</th></tr></thead>';
    html += '<tbody id="historyTable"></tbody></table></div></div>';
    
    html += '<div class="stats"><div><div class="stat-value" id="totalStyles">0</div><div class="stat-label">Styles</div></div>';
    html += '<div><div class="stat-value" id="totalUnits">0</div><div class="stat-label">Units Available</div></div></div>';
    html += '<div class="filters" id="filters"></div><div class="product-grid" id="productGrid"></div>';
    html += '<div class="empty hidden" id="emptyState">No products found. Import a CSV or sync from Zoho to get started.</div></main></div>';
    
    html += '<div class="modal" id="modal"><div class="modal-content"><button class="modal-close" id="modalClose">&times;</button>';
    html += '<div class="modal-body"><div class="modal-image"><img id="modalImage" src="" alt=""></div>';
    html += '<div class="modal-details"><div class="product-style" id="modalStyle"></div><h2 id="modalName"></h2>';
    html += '<p id="modalCategory" style="color:#666;margin-bottom:1rem"></p><div id="modalColors"></div>';
    html += '<div class="total-row"><span>Total Available</span><span id="modalTotal"></span></div></div></div></div></div>';
    
    html += '<script>';
    html += 'var products=[];var currentFilter="all";';
    html += 'function checkSession(){fetch("/api/session").then(function(r){return r.json()}).then(function(d){if(d.loggedIn){showApp(d.username,d.role);loadProducts();loadZohoStatus();if(d.role==="admin"){loadUsers();loadHistory()}}else{document.getElementById("loginPage").classList.remove("hidden");document.getElementById("mainApp").classList.add("hidden")}})}';
    html += 'function showApp(u,r){document.getElementById("loginPage").classList.add("hidden");document.getElementById("mainApp").classList.remove("hidden");document.getElementById("userInfo").textContent="Welcome, "+u;if(r==="admin")document.getElementById("adminBtn").style.display="block"}';
    html += 'document.getElementById("loginForm").addEventListener("submit",function(e){e.preventDefault();var u=document.getElementById("username").value;var p=document.getElementById("password").value;fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})}).then(function(r){return r.json()}).then(function(d){if(d.success){showApp(d.username,d.role);loadProducts();loadZohoStatus();if(d.role==="admin"){loadUsers();loadHistory()}}else{document.getElementById("loginError").textContent=d.error;document.getElementById("loginError").classList.remove("hidden")}})});';
    html += 'document.getElementById("logoutBtn").addEventListener("click",function(){fetch("/api/logout",{method:"POST"}).then(function(){location.reload()})});';
    html += 'document.getElementById("adminBtn").addEventListener("click",function(){document.getElementById("adminPanel").classList.toggle("hidden")});';
    html += 'var tabs=document.querySelectorAll(".tab");for(var i=0;i<tabs.length;i++){tabs[i].addEventListener("click",function(e){var all=document.querySelectorAll(".tab");var cons=document.querySelectorAll(".tab-content");for(var j=0;j<all.length;j++)all[j].classList.remove("active");for(var k=0;k<cons.length;k++)cons[k].classList.remove("active");e.target.classList.add("active");document.getElementById(e.target.getAttribute("data-tab")+"Tab").classList.add("active")})}';
    html += 'function loadZohoStatus(){fetch("/api/zoho/status").then(function(r){return r.json()}).then(function(d){var st=document.getElementById("zohoStatusText");if(d.connected){st.textContent="Connected";st.className="status-value connected"}else if(d.configured){st.textContent="Configured (not connected)";st.className="status-value"}else{st.textContent="Not configured";st.className="status-value disconnected"}document.getElementById("zohoWorkspaceId").textContent=d.workspaceId||"Not set";document.getElementById("zohoViewId").textContent=d.viewId||"Not set"})}';
    html += 'document.getElementById("testZohoBtn").addEventListener("click",function(){document.getElementById("zohoMessage").innerHTML="Testing...";fetch("/api/zoho/test",{method:"POST"}).then(function(r){return r.json()}).then(function(d){if(d.success){document.getElementById("zohoMessage").innerHTML="<span class=\\"success\\">"+d.message+"</span>";loadZohoStatus()}else{document.getElementById("zohoMessage").innerHTML="<span class=\\"error\\">"+d.error+"</span>"}})});';
    html += 'document.getElementById("syncZohoBtn").addEventListener("click",function(){document.getElementById("zohoMessage").innerHTML="Syncing...";fetch("/api/zoho/sync",{method:"POST"}).then(function(r){return r.json()}).then(function(d){if(d.success){document.getElementById("zohoMessage").innerHTML="<span class=\\"success\\">"+d.message+"</span>";loadProducts();loadHistory()}else{document.getElementById("zohoMessage").innerHTML="<span class=\\"error\\">"+d.error+"</span>";loadHistory()}})});';
    html += 'function getImageUrl(url){if(!url)return null;if(url.indexOf("download-accl.zoho.com/v1/workdrive/download/")!==-1){var parts=url.split("/");var fileId=parts[parts.length-1];return"/api/image/"+fileId}return url}';
    html += 'function loadProducts(){fetch("/api/products").then(function(r){return r.json()}).then(function(d){products=d;renderFilters();renderProducts()})}';
    html += 'function renderFilters(){var cats=[];for(var i=0;i<products.length;i++){if(products[i].category&&cats.indexOf(products[i].category)===-1)cats.push(products[i].category)}cats.sort();var h="<button class=\\"filter-btn active\\" data-cat=\\"all\\">All</button>";for(var j=0;j<cats.length;j++){h+="<button class=\\"filter-btn\\" data-cat=\\""+cats[j]+"\\">"+cats[j]+"</button>"}document.getElementById("filters").innerHTML=h;var btns=document.querySelectorAll(".filter-btn");for(var k=0;k<btns.length;k++){btns[k].addEventListener("click",function(e){var all=document.querySelectorAll(".filter-btn");for(var m=0;m<all.length;m++)all[m].classList.remove("active");e.target.classList.add("active");currentFilter=e.target.getAttribute("data-cat");renderProducts()})}}';
    html += 'function renderProducts(){var s=document.getElementById("searchInput").value.toLowerCase();var f=[];for(var i=0;i<products.length;i++){var p=products[i];var ms=!s||p.style_id.toLowerCase().indexOf(s)!==-1||p.name.toLowerCase().indexOf(s)!==-1;var mc=currentFilter==="all"||p.category===currentFilter;if(ms&&mc)f.push(p)}if(f.length===0){document.getElementById("productGrid").innerHTML="";document.getElementById("emptyState").classList.remove("hidden")}else{document.getElementById("emptyState").classList.add("hidden");var h="";for(var j=0;j<f.length;j++){var pr=f[j];var cols=pr.colors||[];var tot=0;for(var c=0;c<cols.length;c++)tot+=cols[c].available_qty||0;var ch="";var mx=Math.min(cols.length,3);for(var d=0;d<mx;d++){ch+="<div class=\\"color-row\\"><span>"+cols[d].color_name+"</span><span>"+(cols[d].available_qty||0).toLocaleString()+"</span></div>"}if(cols.length>3)ch+="<div class=\\"color-row\\" style=\\"color:#999\\">+"+(cols.length-3)+" more</div>";var imgUrl=getImageUrl(pr.image_url);var im=imgUrl?"<img src=\\""+imgUrl+"\\" onerror=\\"this.parentElement.innerHTML=\'No Image\'\\">" :"No Image";h+="<div class=\\"product-card\\" onclick=\\"openModal("+pr.id+")\\"><div class=\\"product-image\\">"+im+"</div><div class=\\"product-info\\"><div class=\\"product-style\\">"+pr.style_id+"</div><div class=\\"product-name\\">"+pr.name+"</div><div class=\\"color-list\\">"+ch+"</div><div class=\\"total-row\\"><span>Total</span><span>"+tot.toLocaleString()+"</span></div></div></div>"}document.getElementById("productGrid").innerHTML=h}document.getElementById("totalStyles").textContent=f.length;var tu=0;for(var t=0;t<f.length;t++){var cs=f[t].colors||[];for(var u=0;u<cs.length;u++)tu+=cs[u].available_qty||0}document.getElementById("totalUnits").textContent=tu.toLocaleString()}';
    html += 'document.getElementById("searchInput").addEventListener("input",renderProducts);';
    html += 'function openModal(id){var p=null;for(var i=0;i<products.length;i++){if(products[i].id===id){p=products[i];break}}if(!p)return;var cols=p.colors||[];var tot=0;for(var c=0;c<cols.length;c++)tot+=cols[c].available_qty||0;var im=document.getElementById("modalImage");var imgUrl=getImageUrl(p.image_url);if(imgUrl){im.src=imgUrl;im.style.display="block"}else{im.style.display="none"}document.getElementById("modalStyle").textContent=p.style_id;document.getElementById("modalName").textContent=p.name;document.getElementById("modalCategory").textContent=p.category||"";var ch="";for(var d=0;d<cols.length;d++){ch+="<div class=\\"color-row\\"><span>"+cols[d].color_name+"</span><span>"+(cols[d].available_qty||0).toLocaleString()+"</span></div>"}document.getElementById("modalColors").innerHTML=ch;document.getElementById("modalTotal").textContent=tot.toLocaleString();document.getElementById("modal").classList.add("active")}';
    html += 'document.getElementById("modalClose").addEventListener("click",function(){document.getElementById("modal").classList.remove("active")});';
    html += 'document.getElementById("modal").addEventListener("click",function(e){if(e.target.id==="modal")document.getElementById("modal").classList.remove("active")});';
    html += 'document.getElementById("csvFile").addEventListener("change",function(e){var f=e.target.files[0];if(!f)return;var fd=new FormData();fd.append("file",f);document.getElementById("importStatus").innerHTML="Importing...";fetch("/api/import",{method:"POST",body:fd}).then(function(r){return r.json()}).then(function(d){if(d.success){document.getElementById("importStatus").innerHTML="<span class=\\"success\\">Imported "+d.imported+" products</span>";loadProducts();loadHistory()}else{document.getElementById("importStatus").innerHTML="<span class=\\"error\\">"+d.error+"</span>"}})});';
    html += 'document.getElementById("clearBtn").addEventListener("click",function(){if(!confirm("Delete all products?"))return;fetch("/api/products/clear",{method:"POST"}).then(function(){loadProducts()})});';
    html += 'function loadUsers(){fetch("/api/users").then(function(r){return r.json()}).then(function(u){var h="";for(var i=0;i<u.length;i++){h+="<tr><td>"+u[i].username+"</td><td>"+u[i].role+"</td><td><button class=\\"btn btn-danger\\" onclick=\\"deleteUser("+u[i].id+")\\">Delete</button></td></tr>"}document.getElementById("usersTable").innerHTML=h})}';
    html += 'document.getElementById("addUserBtn").addEventListener("click",function(){var u=document.getElementById("newUser").value;var p=document.getElementById("newPass").value;var r=document.getElementById("newRole").value;if(!u||!p){alert("Enter username and password");return}fetch("/api/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p,role:r})}).then(function(){document.getElementById("newUser").value="";document.getElementById("newPass").value="";loadUsers()})});';
    html += 'function deleteUser(id){if(!confirm("Delete this user?"))return;fetch("/api/users/"+id,{method:"DELETE"}).then(function(){loadUsers()})}';
    html += 'function loadHistory(){fetch("/api/zoho/sync-history").then(function(r){return r.json()}).then(function(h){var html="";for(var i=0;i<h.length;i++){html+="<tr><td>"+new Date(h[i].created_at).toLocaleString()+"</td><td>"+h[i].sync_type+"</td><td>"+h[i].status+"</td><td>"+(h[i].records_synced||"-")+"</td><td>"+(h[i].error_message||"-")+"</td></tr>"}document.getElementById("historyTable").innerHTML=html})}';
    html += 'checkSession();';
    html += '</script></body></html>';
    return html;
}

initDB().then(function() {
    app.listen(PORT, function() {
        console.log("Product Catalog running on port " + PORT);
    });
    setTimeout(function() {
        startTokenRefreshJob();
    }, 5000);
});
