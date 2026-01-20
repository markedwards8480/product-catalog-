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
    secret: process.env.SESSION_SECRET || 'catalog-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

let zohoAccessToken = null;

async function initDB() {
    try {
        await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL, role VARCHAR(50) DEFAULT 'sales_rep', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, style_id VARCHAR(100) NOT NULL, base_style VARCHAR(100), name VARCHAR(255) NOT NULL, category VARCHAR(100), image_url TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS product_colors (id SERIAL PRIMARY KEY, product_id INTEGER REFERENCES products(id) ON DELETE CASCADE, color_name VARCHAR(100) NOT NULL, available_qty INTEGER DEFAULT 0, on_hand INTEGER DEFAULT 0, open_order INTEGER DEFAULT 0, to_come INTEGER DEFAULT 0, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS sync_history (id SERIAL PRIMARY KEY, sync_type VARCHAR(50), status VARCHAR(50), records_synced INTEGER DEFAULT 0, error_message TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);

        const userCheck = await pool.query('SELECT COUNT(*) FROM users');
        if (parseInt(userCheck.rows[0].count) === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await pool.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', ['admin', hashedPassword, 'admin']);
            console.log('Default admin user created (admin/admin123)');
        }
        console.log('Database initialized successfully');
    } catch (err) {
        console.error('Database initialization error:', err);
    }
}

async function refreshZohoToken() {
    try {
        const clientId = process.env.ZOHO_CLIENT_ID;
        const clientSecret = process.env.ZOHO_CLIENT_SECRET;
        const refreshToken = process.env.ZOHO_REFRESH_TOKEN;
        
        if (!clientId || !clientSecret || !refreshToken) {
            console.log('Zoho credentials not configured');
            return null;
        }

        console.log('Refreshing Zoho access token...');
        const response = await fetch('https://accounts.zoho.com/oauth/v2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ 
                refresh_token: refreshToken, 
                client_id: clientId, 
                client_secret: clientSecret, 
                grant_type: 'refresh_token' 
            })
        });

        const data = await response.json();
        if (data.access_token) {
            zohoAccessToken = data.access_token;
            console.log('Zoho access token refreshed successfully');
            return data.access_token;
        } else {
            console.error('Failed to refresh Zoho token:', data);
            return null;
        }
    } catch (err) {
        console.error('Error refreshing Zoho token:', err);
        return null;
    }
}

let tokenRefreshInterval = null;
function startTokenRefreshJob() {
    if (tokenRefreshInterval) clearInterval(tokenRefreshInterval);
    refreshZohoToken();
    tokenRefreshInterval = setInterval(async () => { await refreshZohoToken(); }, 30 * 60 * 1000);
    console.log('Background token refresh started (every 30 minutes)');
}

async function zohoApiCall(url, options = {}) {
    if (!zohoAccessToken) {
        await refreshZohoToken();
        if (!zohoAccessToken) throw new Error('No valid Zoho access token');
    }
    
    const headers = { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken, ...options.headers };
    let response = await fetch(url, { ...options, headers });
    
    if (response.status === 401) {
        console.log('Zoho API returned 401 - refreshing token...');
        await refreshZohoToken();
        if (zohoAccessToken) {
            headers['Authorization'] = 'Zoho-oauthtoken ' + zohoAccessToken;
            response = await fetch(url, { ...options, headers });
        }
    }
    return response;
}

async function syncFromZohoAnalytics() {
    try {
        const viewId = process.env.ZOHO_VIEW_ID;
        const orgId = process.env.ZOHO_ORG_ID;
        
        if (!viewId) {
            return { success: false, error: 'ZOHO_VIEW_ID not configured in Railway variables' };
        }

        console.log('Syncing from Zoho Analytics, View ID:', viewId);
        
        // Use the export API with view ID
        let url = 'https://analyticsapi.zoho.com/restapi/v2/views/' + viewId + '/data?CONFIG={"responseFormat":"json"}';
        if (orgId) {
            url += '&ZOHO_ORG_ID=' + orgId;
        }

        console.log('API URL:', url);
        const response = await zohoApiCall(url);
        const responseText = await response.text();
        
        console.log('Response status:', response.status);
        console.log('Response preview:', responseText.substring(0, 500));

        if (!response.ok) {
            console.error('Zoho Analytics API error:', responseText);
            await pool.query('INSERT INTO sync_history (sync_type, status, error_message) VALUES ($1, $2, $3)', ['zoho_analytics', 'failed', responseText.substring(0, 500)]);
            return { success: false, error: 'Zoho API error: ' + response.status + ' - ' + responseText.substring(0, 200) };
        }

        let data;
        try {
            data = JSON.parse(responseText);
        } catch (e) {
            return { success: false, error: 'Invalid JSON response from Zoho' };
        }

        console.log('Response keys:', Object.keys(data));
        
        // Handle different response structures
        let rows = [];
        let columns = [];
        
        if (data.data && data.data.rows) {
            rows = data.data.rows;
            columns = data.data.columns || [];
        } else if (data.rows) {
            rows = data.rows;
            columns = data.columns || [];
        } else if (Array.isArray(data.data)) {
            rows = data.data;
        } else if (Array.isArray(data)) {
            rows = data;
        }

        console.log('Columns found:', columns);
        console.log('Number of rows:', rows.length);
        if (rows.length > 0) {
            console.log('First row sample:', JSON.stringify(rows[0]).substring(0, 300));
        }

        // Build column map
        const colMap = {};
        if (Array.isArray(columns) && columns.length > 0) {
            columns.forEach((col, idx) => {
                const colName = (typeof col === 'string' ? col : col.columnName || col.name || col.COLUMN_NAME || '').toLowerCase().replace(/\s+/g, '_');
                colMap[colName] = idx;
                console.log('Column', idx, ':', colName);
            });
        }

        let imported = 0;
        
        for (const row of rows) {
            try {
                let styleId, color, category, onHand, openOrder, toCome, available;
                
                // If row is an array, use column indices
                if (Array.isArray(row)) {
                    styleId = row[colMap['style_name']] || row[colMap['stylename']] || row[0];
                    color = row[colMap['color']] || row[1] || '';
                    category = row[colMap['commodity']] || row[2] || 'Uncategorized';
                    onHand = parseInt(row[colMap['on_hand']] || row[3] || 0) || 0;
                    openOrder = parseInt(row[colMap['open_order']] || row[4] || 0) || 0;
                    toCome = parseInt(row[colMap['to_come']] || row[5] || 0) || 0;
                    available = parseInt(row[colMap['left_to_sell']] || row[6] || 0) || 0;
                } else {
                    // If row is an object, access by property name
                    styleId = row['Style Name'] || row['style_name'] || row['StyleName'] || row['STYLE_NAME'];
                    color = row['Color'] || row['color'] || row['COLOR'] || '';
                    category = row['Commodity'] || row['commodity'] || row['COMMODITY'] || row['Category'] || 'Uncategorized';
                    onHand = parseInt(row['On Hand'] || row['on_hand'] || row['ON_HAND'] || 0) || 0;
                    openOrder = parseInt(row['Open Order'] || row['open_order'] || row['OPEN_ORDER'] || 0) || 0;
                    toCome = parseInt(row['To Come'] || row['to_come'] || row['TO_COME'] || 0) || 0;
                    available = parseInt(row['Left to Sell'] || row['left_to_sell'] || row['LEFT_TO_SELL'] || row['Available'] || 0) || 0;
                }
                
                if (!styleId) continue;

                const baseStyle = styleId.toString().split('-')[0];
                const name = category + ' - ' + baseStyle;

                let productResult = await pool.query('SELECT id FROM products WHERE style_id = $1', [styleId]);
                let productId;
                if (productResult.rows.length > 0) {
                    productId = productResult.rows[0].id;
                    await pool.query('UPDATE products SET name = $1, category = $2, base_style = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4', [name, category, baseStyle, productId]);
                } else {
                    const insertResult = await pool.query('INSERT INTO products (style_id, base_style, name, category) VALUES ($1, $2, $3, $4) RETURNING id', [styleId, baseStyle, name, category]);
                    productId = insertResult.rows[0].id;
                }

                if (color) {
                    const colorResult = await pool.query('SELECT id FROM product_colors WHERE product_id = $1 AND color_name = $2', [productId, color]);
                    if (colorResult.rows.length > 0) {
                        await pool.query('UPDATE product_colors SET available_qty = $1, on_hand = $2, open_order = $3, to_come = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5', [available, onHand, openOrder, toCome, colorResult.rows[0].id]);
                    } else {
                        await pool.query('INSERT INTO product_colors (product_id, color_name, available_qty, on_hand, open_order, to_come) VALUES ($1, $2, $3, $4, $5, $6)', [productId, color, available, onHand, openOrder, toCome]);
                    }
                }
                imported++;
            } catch (rowErr) {
                console.error('Error importing row:', rowErr);
            }
        }

        await pool.query('INSERT INTO sync_history (sync_type, status, records_synced) VALUES ($1, $2, $3)', ['zoho_analytics', 'success', imported]);
        console.log('Zoho Analytics sync complete:', imported, 'records');
        return { success: true, imported };
    } catch (err) {
        console.error('Zoho Analytics sync error:', err);
        await pool.query('INSERT INTO sync_history (sync_type, status, error_message) VALUES ($1, $2, $3)', ['zoho_analytics', 'failed', err.message]);
        return { success: false, error: err.message };
    }
}

function requireAuth(req, res, next) { if (req.session && req.session.userId) next(); else res.status(401).json({ error: 'Unauthorized' }); }
function requireAdmin(req, res, next) { if (req.session && req.session.role === 'admin') next(); else res.status(403).json({ error: 'Admin access required' }); }

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        res.json({ success: true, username: user.username, role: user.role });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/session', (req, res) => { if (req.session && req.session.userId) res.json({ loggedIn: true, username: req.session.username, role: req.session.role }); else res.json({ loggedIn: false }); });

app.get('/api/zoho/status', requireAuth, requireAdmin, async (req, res) => {
    const configured = !!(process.env.ZOHO_CLIENT_ID && process.env.ZOHO_CLIENT_SECRET && process.env.ZOHO_REFRESH_TOKEN);
    const hasToken = !!zohoAccessToken;
    const lastSync = await pool.query('SELECT created_at FROM sync_history WHERE status = $1 ORDER BY created_at DESC LIMIT 1', ['success']);
    res.json({
        configured,
        connected: hasToken,
        viewId: process.env.ZOHO_VIEW_ID || null,
        workspace: process.env.ZOHO_WORKSPACE_NAME || null,
        view: process.env.ZOHO_VIEW_NAME || null,
        lastSync: lastSync.rows.length > 0 ? lastSync.rows[0].created_at : null
    });
});

app.post('/api/zoho/test', requireAuth, requireAdmin, async (req, res) => {
    try {
        const token = await refreshZohoToken();
        if (token) res.json({ success: true, message: 'Token refresh successful' });
        else res.status(400).json({ success: false, error: 'Failed to refresh token' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/zoho/sync', requireAuth, requireAdmin, async (req, res) => {
    try { const result = await syncFromZohoAnalytics(); res.json(result); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/zoho/sync-history', requireAuth, requireAdmin, async (req, res) => {
    try { const result = await pool.query('SELECT * FROM sync_history ORDER BY created_at DESC LIMIT 20'); res.json(result.rows); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/products', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(`SELECT p.id, p.style_id, p.base_style, p.name, p.category, p.image_url, json_agg(json_build_object('id', pc.id, 'color_name', pc.color_name, 'available_qty', pc.available_qty, 'on_hand', pc.on_hand, 'open_order', pc.open_order, 'to_come', pc.to_come)) FILTER (WHERE pc.id IS NOT NULL) as colors FROM products p LEFT JOIN product_colors pc ON p.id = pc.product_id GROUP BY p.id ORDER BY p.category, p.name, p.style_id`);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/import', requireAuth, requireAdmin, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        const content = req.file.buffer.toString('utf-8');
        const lines = content.split('\n').filter(line => line.trim());
        if (lines.length < 2) return res.status(400).json({ error: 'File appears empty' });

        const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/"/g, ''));
        let imported = 0;

        for (let i = 1; i < lines.length; i++) {
            try {
                const values = lines[i].match(/("([^"]*)"|[^,]*)/g).map(v => v.replace(/^"|"$/g, '').trim());
                const row = {};
                headers.forEach((h, idx) => { row[h] = values[idx] || ''; });

                const styleId = row['style name'] || row['style_id'] || row['style'];
                const name = row['name'] || row['product name'] || styleId;
                const category = row['commodity'] || row['category'] || 'Uncategorized';
                const color = row['color'] || row['colour'] || '';
                const available = parseInt(row['left to sell'] || row['available'] || 0) || 0;
                const onHand = parseInt(row['on hand'] || 0) || 0;
                const openOrder = parseInt(row['open order'] || 0) || 0;
                const toCome = parseInt(row['to come'] || 0) || 0;
                if (!styleId) continue;

                const baseStyle = styleId.split('-')[0];
                let productResult = await pool.query('SELECT id FROM products WHERE style_id = $1', [styleId]);
                let productId;
                if (productResult.rows.length > 0) {
                    productId = productResult.rows[0].id;
                    await pool.query('UPDATE products SET name = $1, category = $2, base_style = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4', [name, category, baseStyle, productId]);
                } else {
                    const insertResult = await pool.query('INSERT INTO products (style_id, base_style, name, category) VALUES ($1, $2, $3, $4) RETURNING id', [styleId, baseStyle, name, category]);
                    productId = insertResult.rows[0].id;
                }

                if (color) {
                    const colorResult = await pool.query('SELECT id FROM product_colors WHERE product_id = $1 AND color_name = $2', [productId, color]);
                    if (colorResult.rows.length > 0) {
                        await pool.query('UPDATE product_colors SET available_qty = $1, on_hand = $2, open_order = $3, to_come = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5', [available, onHand, openOrder, toCome, colorResult.rows[0].id]);
                    } else {
                        await pool.query('INSERT INTO product_colors (product_id, color_name, available_qty, on_hand, open_order, to_come) VALUES ($1, $2, $3, $4, $5, $6)', [productId, color, available, onHand, openOrder, toCome]);
                    }
                }
                imported++;
            } catch (rowErr) { /* skip */ }
        }
        res.json({ success: true, imported });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try { const result = await pool.query('SELECT id, username, role, created_at FROM users ORDER BY created_at'); res.json(result.rows); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', [username, hashedPassword, role || 'sales_rep']);
        res.json({ success: true });
    } catch (err) { if (err.code === '23505') res.status(400).json({ error: 'Username exists' }); else res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        if (req.params.id == req.session.userId) return res.status(400).json({ error: 'Cannot delete yourself' });
        await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('*', (req, res) => { res.send(getHTML()); });

function getHTML() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Product Catalog</title>
    <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=Playfair+Display:wght@500;600&display=swap" rel="stylesheet">
    <style>
        *{margin:0;padding:0;box-sizing:border-box}:root{--bg:#FAFAF8;--card:#FFF;--text:#1A1A1A;--muted:#999;--border:#E8E8E6;--accent:#2C5545;--accent-light:#E8F0EC;--danger:#C4553D;--success:#2E7D32}body{font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}.login-container{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem;background:linear-gradient(135deg,#f5f5f3,#e8e8e6)}.login-box{background:var(--card);padding:3rem;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.06);width:100%;max-width:400px}.login-logo{font-family:'Playfair Display',serif;font-size:1.75rem;font-weight:600;text-align:center;margin-bottom:2rem}.login-logo span{color:var(--accent)}.form-group{margin-bottom:1.25rem}.form-group label{display:block;font-size:.875rem;font-weight:500;margin-bottom:.5rem;color:#666}.form-group input,.form-group select{width:100%;padding:.875rem 1rem;border:1px solid var(--border);border-radius:8px;font-family:inherit;font-size:1rem}.form-group input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-light)}.btn{padding:.875rem 1.5rem;border:none;border-radius:8px;font-family:inherit;font-size:.9375rem;font-weight:500;cursor:pointer}.btn-primary{background:var(--accent);color:#fff;width:100%}.btn-primary:hover{background:#234536}.btn-secondary{background:var(--bg);color:var(--text);border:1px solid var(--border)}.btn-secondary:hover{border-color:var(--accent);color:var(--accent)}.btn-danger{background:var(--danger);color:#fff}.btn-success{background:var(--success);color:#fff}.error-message{color:var(--danger);font-size:.875rem;margin-top:1rem;text-align:center}.success-message{color:var(--success);font-size:.875rem;margin-top:1rem;text-align:center}.header{background:var(--card);border-bottom:1px solid var(--border);padding:1.25rem 2rem;position:sticky;top:0;z-index:100}.header-inner{max-width:1600px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;gap:2rem;flex-wrap:wrap}.logo{font-family:'Playfair Display',serif;font-size:1.5rem;font-weight:600}.logo span{color:var(--accent)}.header-right{display:flex;align-items:center;gap:1rem}.user-info{font-size:.875rem;color:#666}.controls{display:flex;align-items:center;gap:1rem;flex:1;max-width:600px}.search-box{flex:1;position:relative}.search-box input{width:100%;padding:.75rem 1rem .75rem 2.75rem;border:1px solid var(--border);border-radius:8px;font-family:inherit;font-size:.9375rem;background:var(--bg)}.search-box input:focus{outline:none;border-color:var(--accent);background:var(--card)}.search-box::before{content:'';position:absolute;left:1rem;top:50%;transform:translateY(-50%);width:18px;height:18px;background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%23999'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z'/%3E%3C/svg%3E") center/contain no-repeat}.filter-pills{display:flex;gap:.5rem;flex-wrap:wrap}.filter-pill{padding:.5rem 1rem;border:1px solid var(--border);border-radius:20px;background:var(--card);font-family:inherit;font-size:.8125rem;font-weight:500;color:#666;cursor:pointer}.filter-pill:hover{border-color:var(--accent);color:var(--accent)}.filter-pill.active{background:var(--accent);border-color:var(--accent);color:#fff}.stats-bar{background:var(--card);padding:1rem 2rem;border-bottom:1px solid var(--border)}.stats-inner{max-width:1600px;margin:0 auto;display:flex;align-items:center;gap:2rem;flex-wrap:wrap}.stat{display:flex;align-items:baseline;gap:.5rem}.stat-value{font-size:1.5rem;font-weight:600}.stat-label{font-size:.875rem;color:var(--muted)}.sync-info{margin-left:auto;font-size:.8125rem;color:var(--muted)}.main{max-width:1600px;margin:0 auto;padding:2rem}.admin-panel{background:var(--card);border-radius:12px;padding:2rem;margin-bottom:2rem;box-shadow:0 4px 24px rgba(0,0,0,.06)}.admin-panel h2{font-family:'Playfair Display',serif;font-size:1.5rem;margin-bottom:1.5rem}.admin-tabs{display:flex;gap:.5rem;margin-bottom:1.5rem;border-bottom:1px solid var(--border);padding-bottom:1rem;flex-wrap:wrap}.admin-tab{padding:.625rem 1.25rem;border:none;background:none;font-family:inherit;font-size:.9375rem;font-weight:500;color:#666;cursor:pointer;border-radius:6px}.admin-tab:hover{background:var(--bg);color:var(--text)}.admin-tab.active{background:var(--accent);color:#fff}.admin-section{display:none}.admin-section.active{display:block}.zoho-status{padding:1rem;background:var(--bg);border-radius:8px;margin-bottom:1.5rem;border-left:4px solid var(--danger)}.zoho-status.connected{border-left-color:var(--success)}.file-upload-area{border:2px dashed var(--border);border-radius:8px;padding:2rem;text-align:center}.file-upload-area:hover{border-color:var(--accent)}.file-upload-area input[type="file"]{display:none}.file-upload-area label{cursor:pointer;color:var(--accent);font-weight:500}.user-table,.sync-table{width:100%;border-collapse:collapse}.user-table th,.user-table td,.sync-table th,.sync-table td{padding:.875rem;text-align:left;border-bottom:1px solid var(--border)}.user-table th,.sync-table th{font-weight:600;color:#666;font-size:.8125rem;text-transform:uppercase}.add-user-form{display:flex;gap:1rem;margin-top:1.5rem;flex-wrap:wrap}.add-user-form input,.add-user-form select{padding:.75rem 1rem;border:1px solid var(--border);border-radius:6px;font-family:inherit}.category-section{margin-bottom:3rem}.category-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;padding-bottom:.75rem;border-bottom:2px solid var(--text)}.category-title{font-family:'Playfair Display',serif;font-size:1.75rem;font-weight:500}.category-count{font-size:.875rem;color:var(--muted)}.product-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:1.5rem}.product-card{background:var(--card);border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.06);transition:all .3s ease;cursor:pointer;animation:fadeInUp .4s ease forwards;opacity:0}.product-card:hover{transform:translateY(-4px);box-shadow:0 16px 48px rgba(0,0,0,.08)}.product-image-container{position:relative;aspect-ratio:4/3;background:linear-gradient(145deg,#f5f5f5,#ebebeb);display:flex;align-items:center;justify-content:center}.product-image{width:100%;height:100%;object-fit:cover;transition:transform .4s ease}.product-card:hover .product-image{transform:scale(1.05)}.no-image{color:var(--muted);font-size:.875rem}.product-badge{position:absolute;top:1rem;left:1rem;padding:.375rem .75rem;background:var(--accent);color:#fff;font-size:.75rem;font-weight:600;border-radius:4px;text-transform:uppercase}.product-badge.low-stock{background:var(--danger)}.product-info{padding:1.25rem}.product-style{font-size:.8125rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:.25rem}.product-name{font-family:'Playfair Display',serif;font-size:1.25rem;font-weight:500;margin-bottom:1rem}.color-availability{display:flex;flex-direction:column;gap:.625rem}.color-row{display:flex;align-items:center;justify-content:space-between;padding:.5rem .75rem;background:var(--bg);border-radius:6px}.color-info{display:flex;align-items:center;gap:.625rem}.color-swatch{width:20px;height:20px;border-radius:50%;border:2px solid rgba(0,0,0,.08)}.color-name{font-size:.875rem;font-weight:500}.color-qty{font-size:.9375rem;font-weight:600;color:var(--accent)}.color-qty.low{color:var(--danger)}.color-qty.out{color:var(--muted);text-decoration:line-through}.total-row{display:flex;align-items:center;justify-content:space-between;padding-top:.75rem;margin-top:.5rem;border-top:1px solid var(--border)}.total-label{font-size:.8125rem;font-weight:500;color:#666;text-transform:uppercase}.total-value{font-size:1.125rem;font-weight:600}.empty-state{text-align:center;padding:4rem 2rem}.empty-state h3{font-family:'Playfair Display',serif;font-size:1.5rem;margin-bottom:.5rem}.empty-state p{color:var(--muted)}.modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);z-index:1000;display:none;align-items:center;justify-content:center;padding:2rem}.modal-overlay.active{display:flex}.modal-content{background:var(--card);border-radius:16px;max-width:900px;width:100%;max-height:90vh;overflow:hidden;display:grid;grid-template-columns:1fr 1fr;box-shadow:0 25px 50px -12px rgba(0,0,0,.25);position:relative}.modal-close{position:absolute;top:1rem;right:1rem;width:40px;height:40px;border-radius:50%;background:var(--card);border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:1.5rem;color:#666;z-index:10}.modal-close:hover{background:var(--text);color:#fff}.modal-image{aspect-ratio:1;background:#f5f5f5;display:flex;align-items:center;justify-content:center}.modal-image img{width:100%;height:100%;object-fit:cover}.modal-details{padding:2rem;display:flex;flex-direction:column}.modal-style{font-size:.875rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:.5rem}.modal-name{font-family:'Playfair Display',serif;font-size:2rem;font-weight:500;margin-bottom:.5rem}.modal-category{font-size:1rem;color:#666;margin-bottom:2rem}.modal-availability-title{font-size:.8125rem;font-weight:600;color:#666;text-transform:uppercase;margin-bottom:1rem}.modal-colors{display:flex;flex-direction:column;gap:.75rem;flex:1}.modal-color-row{display:flex;align-items:center;justify-content:space-between;padding:.875rem 1rem;background:var(--bg);border-radius:8px}.modal-color-info{display:flex;align-items:center;gap:.875rem}.modal-color-swatch{width:28px;height:28px;border-radius:50%;border:2px solid rgba(0,0,0,.1)}.modal-color-name{font-size:1rem;font-weight:500}.modal-color-qty{font-size:1.25rem;font-weight:600;color:var(--accent)}.modal-total{display:flex;align-items:center;justify-content:space-between;padding-top:1.5rem;margin-top:1rem;border-top:2px solid var(--border)}.modal-total-label{font-size:1rem;font-weight:500;color:#666}.modal-total-value{font-size:1.75rem;font-weight:600}@media(max-width:768px){.header{padding:1rem}.header-inner{flex-direction:column;align-items:stretch;gap:1rem}.controls{max-width:none}.main{padding:1rem}.product-grid{grid-template-columns:1fr}.modal-content{grid-template-columns:1fr;max-height:85vh;overflow-y:auto}.admin-panel{padding:1rem}.add-user-form{flex-direction:column}}@keyframes fadeInUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}.product-card:nth-child(1){animation-delay:.05s}.product-card:nth-child(2){animation-delay:.1s}.product-card:nth-child(3){animation-delay:.15s}.product-card:nth-child(4){animation-delay:.2s}.product-card:nth-child(5){animation-delay:.25s}.product-card:nth-child(6){animation-delay:.3s}.hidden{display:none!important}.loading{display:inline-block;width:20px;height:20px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
    </style>
</head>
<body>
<div id="loginPage" class="login-container"><div class="login-box"><div class="login-logo">Product <span>Catalog</span></div><form id="loginForm"><div class="form-group"><label>Username</label><input type="text" id="loginUsername" required></div><div class="form-group"><label>Password</label><input type="password" id="loginPassword" required></div><button type="submit" class="btn btn-primary">Sign In</button><div id="loginError" class="error-message hidden"></div></form></div></div>
<div id="mainApp" class="hidden">
<header class="header"><div class="header-inner"><div class="logo">Product <span>Catalog</span></div><div class="controls"><div class="search-box"><input type="text" id="searchInput" placeholder="Search by style, color, or category..."></div></div><div class="filter-pills" id="categoryFilters"><button class="filter-pill active" data-category="all">All</button></div><div class="header-right"><span class="user-info">Signed in as <strong id="currentUser"></strong></span><button class="btn btn-secondary" id="adminBtn" style="display:none;">Admin</button><button class="btn btn-secondary" id="logoutBtn">Sign Out</button></div></div></header>
<div class="stats-bar"><div class="stats-inner"><div class="stat"><span class="stat-value" id="totalStyles">0</span><span class="stat-label">Styles</span></div><div class="stat"><span class="stat-value" id="totalUnits">0</span><span class="stat-label">Units Available</span></div><div class="stat"><span class="stat-value" id="inStockCount">0</span><span class="stat-label">In Stock</span></div><div class="sync-info" id="syncInfo"></div></div></div>
<main class="main">
<div id="adminPanel" class="admin-panel hidden"><h2>Admin Panel</h2><div class="admin-tabs"><button class="admin-tab active" data-tab="zoho">Zoho Analytics</button><button class="admin-tab" data-tab="import">CSV Import</button><button class="admin-tab" data-tab="users">Manage Users</button><button class="admin-tab" data-tab="history">Sync History</button></div>
<div id="zohoSection" class="admin-section active"><div id="zohoStatus" class="zoho-status"><strong>Status:</strong> <span id="zohoStatusText">Checking...</span></div><p style="margin-bottom:1rem;color:#666"><strong>View ID:</strong> <span id="zohoViewId">-</span></p><div style="display:flex;gap:1rem;flex-wrap:wrap"><button class="btn btn-secondary" id="testZohoBtn">Test Connection</button><button class="btn btn-success" id="syncZohoBtn">Sync Now</button></div><div id="zohoMessage" style="margin-top:1rem"></div></div>
<div id="importSection" class="admin-section"><p style="margin-bottom:1rem;color:#666">Upload a CSV export from Zoho Analytics.</p><div class="file-upload-area"><input type="file" id="csvUpload" accept=".csv"><label for="csvUpload">Click to upload CSV file</label></div><div id="importStatus" style="margin-top:1rem"></div></div>
<div id="usersSection" class="admin-section"><table class="user-table"><thead><tr><th>Username</th><th>Role</th><th>Created</th><th>Actions</th></tr></thead><tbody id="userTableBody"></tbody></table><div class="add-user-form"><input type="text" id="newUsername" placeholder="Username"><input type="password" id="newPassword" placeholder="Password"><select id="newRole"><option value="sales_rep">Sales Rep</option><option value="admin">Admin</option></select><button class="btn btn-primary" id="addUserBtn">Add User</button></div></div>
<div id="historySection" class="admin-section"><table class="sync-table"><thead><tr><th>Date</th><th>Type</th><th>Status</th><th>Records</th><th>Error</th></tr></thead><tbody id="syncHistoryBody"></tbody></table></div>
</div>
<div id="productContainer"></div>
</main>
</div>
<div class="modal-overlay" id="modal"><div class="modal-content"><button class="modal-close" onclick="closeModal()">&times;</button><div class="modal-image"><img id="modalImage" src="" alt=""></div><div class="modal-details"><div class="modal-style" id="modalStyle"></div><h2 class="modal-name" id="modalName"></h2><div class="modal-category" id="modalCategory"></div><div class="modal-availability-title">Availability by Color</div><div class="modal-colors" id="modalColors"></div><div class="modal-total"><span class="modal-total-label">Total Available</span><span class="modal-total-value" id="modalTotal"></span></div></div></div></div>
<script>
let products=[],currentCategory='all',isAdmin=false;
async function checkSession(){try{const r=await fetch('/api/session');const d=await r.json();if(d.loggedIn){showApp(d.username,d.role);loadProducts();if(d.role==='admin'){loadZohoStatus();loadUsers();loadSyncHistory()}}else{showLogin()}}catch(e){showLogin()}}
function showLogin(){document.getElementById('loginPage').classList.remove('hidden');document.getElementById('mainApp').classList.add('hidden')}
function showApp(u,r){document.getElementById('loginPage').classList.add('hidden');document.getElementById('mainApp').classList.remove('hidden');document.getElementById('currentUser').textContent=u;isAdmin=r==='admin';document.getElementById('adminBtn').style.display=isAdmin?'block':'none'}
document.getElementById('loginForm').addEventListener('submit',async e=>{e.preventDefault();const u=document.getElementById('loginUsername').value;const p=document.getElementById('loginPassword').value;try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});const d=await r.json();if(d.success){showApp(d.username,d.role);loadProducts();if(d.role==='admin'){loadZohoStatus();loadUsers();loadSyncHistory()}}else{document.getElementById('loginError').textContent=d.error||'Login failed';document.getElementById('loginError').classList.remove('hidden')}}catch(e){document.getElementById('loginError').textContent='Connection error';document.getElementById('loginError').classList.remove('hidden')}});
document.getElementById('logoutBtn').addEventListener('click',async()=>{await fetch('/api/logout',{method:'POST'});showLogin()});
document.getElementById('adminBtn').addEventListener('click',()=>{document.getElementById('adminPanel').classList.toggle('hidden')});
document.querySelectorAll('.admin-tab').forEach(t=>{t.addEventListener('click',e=>{document.querySelectorAll('.admin-tab').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.admin-section').forEach(x=>x.classList.remove('active'));e.target.classList.add('active');document.getElementById(e.target.dataset.tab+'Section').classList.add('active')})});
async function loadZohoStatus(){try{const r=await fetch('/api/zoho/status');const d=await r.json();document.getElementById('zohoViewId').textContent=d.viewId||'Not configured';if(d.connected){document.getElementById('zohoStatus').classList.add('connected');document.getElementById('zohoStatusText').textContent='Connected'}else if(d.configured){document.getElementById('zohoStatusText').textContent='Configured (not yet connected)'}else{document.getElementById('zohoStatusText').textContent='Not configured'}if(d.lastSync){document.getElementById('syncInfo').textContent='Last sync: '+new Date(d.lastSync).toLocaleString()}}catch(e){}}
document.getElementById('testZohoBtn').addEventListener('click',async()=>{const b=document.getElementById('testZohoBtn');b.disabled=true;b.innerHTML='<span class="loading"></span> Testing...';try{const r=await fetch('/api/zoho/test',{method:'POST'});const d=await r.json();if(d.success){document.getElementById('zohoMessage').innerHTML='<p class="success-message">Connection successful!</p>';document.getElementById('zohoStatus').classList.add('connected');document.getElementById('zohoStatusText').textContent='Connected'}else{document.getElementById('zohoMessage').innerHTML='<p class="error-message">'+(d.error||'Failed')+'</p>'}}catch(e){document.getElementById('zohoMessage').innerHTML='<p class="error-message">'+e.message+'</p>'}b.disabled=false;b.textContent='Test Connection'});
document.getElementById('syncZohoBtn').addEventListener('click',async()=>{const b=document.getElementById('syncZohoBtn');b.disabled=true;b.innerHTML='<span class="loading"></span> Syncing...';try{const r=await fetch('/api/zoho/sync',{method:'POST'});const d=await r.json();if(d.success){document.getElementById('zohoMessage').innerHTML='<p class="success-message">Synced '+d.imported+' products!</p>';loadProducts();loadSyncHistory();loadZohoStatus()}else{document.getElementById('zohoMessage').innerHTML='<p class="error-message">'+(d.error||'Failed')+'</p>'}}catch(e){document.getElementById('zohoMessage').innerHTML='<p class="error-message">'+e.message+'</p>'}b.disabled=false;b.textContent='Sync Now'});
async function loadSyncHistory(){try{const r=await fetch('/api/zoho/sync-history');const h=await r.json();document.getElementById('syncHistoryBody').innerHTML=h.map(x=>'<tr><td>'+new Date(x.created_at).toLocaleString()+'</td><td>'+x.sync_type+'</td><td style="color:'+(x.status==='success'?'var(--success)':'var(--danger)')+'">'+x.status+'</td><td>'+(x.records_synced||'-')+'</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+(x.error_message||'-')+'</td></tr>').join('')}catch(e){}}
async function loadProducts(){try{const r=await fetch('/api/products');products=await r.json();updateCategoryFilters();renderProducts()}catch(e){}}
function updateCategoryFilters(){const cats=[...new Set(products.map(p=>p.category).filter(Boolean))];const c=document.getElementById('categoryFilters');c.innerHTML='<button class="filter-pill active" data-category="all">All</button>';cats.sort().forEach(cat=>{c.innerHTML+='<button class="filter-pill" data-category="'+cat+'">'+cat+'s</button>'});document.querySelectorAll('.filter-pill').forEach(p=>{p.addEventListener('click',e=>{document.querySelectorAll('.filter-pill').forEach(x=>x.classList.remove('active'));e.target.classList.add('active');currentCategory=e.target.dataset.category;renderProducts()})})}
function formatNumber(n){return(n||0).toLocaleString()}
function getSwatchStyle(c){const colors={black:'#1A1A1A',ivory:'linear-gradient(145deg,#FFFFF0,#F5F5DC)','heather grey':'linear-gradient(145deg,#9CA3AF,#6B7280)',pink:'linear-gradient(145deg,#F9A8D4,#EC4899)',brown:'linear-gradient(145deg,#A78B71,#78583A)',navy:'#1E3A5F',burgundy:'#722F37',olive:'#556B2F',cream:'linear-gradient(145deg,#FFFDD0,#F5E6C8)',charcoal:'#36454F',white:'#FFFFFF',grey:'#808080',red:'#DC2626',blue:'#2563EB',green:'#16A34A'};return colors[(c||'').toLowerCase()]||'#CCCCCC'}
function renderProducts(){const s=document.getElementById('searchInput').value.toLowerCase();let f=products.filter(p=>{const ms=!s||(p.style_id||'').toLowerCase().includes(s)||(p.name||'').toLowerCase().includes(s)||(p.category||'').toLowerCase().includes(s)||(p.colors||[]).some(c=>(c.color_name||'').toLowerCase().includes(s));const mc=currentCategory==='all'||p.category===currentCategory;return ms&&mc});const bc={};f.forEach(p=>{const cat=p.category||'Uncategorized';if(!bc[cat])bc[cat]=[];bc[cat].push(p)});let h='';Object.keys(bc).sort().forEach(cat=>{const cp=bc[cat];h+='<section class="category-section"><div class="category-header"><h2 class="category-title">'+cat+'s</h2><span class="category-count">'+cp.length+' style'+(cp.length!==1?'s':'')+'</span></div><div class="product-grid">';cp.forEach(p=>{const colors=p.colors||[];const total=colors.reduce((s,c)=>s+(c.available_qty||0),0);const low=total<5000&&total>0;let ch=colors.map(c=>'<div class="color-row"><div class="color-info"><div class="color-swatch" style="background:'+getSwatchStyle(c.color_name)+'"></div><span class="color-name">'+(c.color_name||'Unknown')+'</span></div><span class="color-qty'+(c.available_qty===0?' out':c.available_qty<1000?' low':'')+'">'+formatNumber(c.available_qty)+'</span></div>').join('');h+='<div class="product-card" onclick="openModal('+p.id+')"><div class="product-image-container">';if(p.image_url)h+='<img class="product-image" src="'+p.image_url+'" alt="'+p.name+'" loading="lazy">';else h+='<span class="no-image">No Image</span>';if(low)h+='<span class="product-badge low-stock">Low Stock</span>';h+='</div><div class="product-info"><div class="product-style">'+(p.style_id||p.base_style)+'</div><h3 class="product-name">'+(p.name||'Unnamed')+'</h3><div class="color-availability">'+ch+'</div><div class="total-row"><span class="total-label">Total Available</span><span class="total-value">'+formatNumber(total)+'</span></div></div></div>'});h+='</div></section>'});if(h==='')h='<div class="empty-state"><h3>No products found</h3><p>Click "Sync Now" in Admin panel to import from Zoho Analytics.</p></div>';document.getElementById('productContainer').innerHTML=h;updateStats(f)}
function updateStats(f){document.getElementById('totalStyles').textContent=f.length;document.getElementById('totalUnits').textContent=formatNumber(f.reduce((s,p)=>s+(p.colors||[]).reduce((x,c)=>x+(c.available_qty||0),0),0));document.getElementById('inStockCount').textContent=f.filter(p=>(p.colors||[]).some(c=>c.available_qty>0)).length}
document.getElementById('searchInput').addEventListener('input',renderProducts);
function openModal(id){const p=products.find(x=>x.id===id);if(!p)return;const colors=p.colors||[];const total=colors.reduce((s,c)=>s+(c.available_qty||0),0);if(p.image_url){document.getElementById('modalImage').src=p.image_url;document.getElementById('modalImage').style.display='block'}else{document.getElementById('modalImage').style.display='none'}document.getElementById('modalStyle').textContent=p.style_id||p.base_style;document.getElementById('modalName').textContent=p.name||'Unnamed';document.getElementById('modalCategory').textContent=p.category||'';document.getElementById('modalTotal').textContent=formatNumber(total);document.getElementById('modalColors').innerHTML=colors.map(c=>'<div class="modal-color-row"><div class="modal-color-info"><div class="modal-color-swatch" style="background:'+getSwatchStyle(c.color_name)+'"></div><span class="modal-color-name">'+(c.color_name||'Unknown')+'</span></div><span class="modal-color-qty">'+formatNumber(c.available_qty)+'</span></div>').join('');document.getElementById('modal').classList.add('active');document.body.style.overflow='hidden'}
function closeModal(){document.getElementById('modal').classList.remove('active');document.body.style.overflow=''}
document.getElementById('modal').addEventListener('click',e=>{if(e.target.id==='modal')closeModal()});
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal()});
document.getElementById('csvUpload').addEventListener('change',async e=>{const f=e.target.files[0];if(!f)return;const fd=new FormData();fd.append('file',f);document.getElementById('importStatus').innerHTML='<p>Importing...</p>';try{const r=await fetch('/api/import',{method:'POST',body:fd});const d=await r.json();if(d.success){document.getElementById('importStatus').innerHTML='<p class="success-message">Imported '+d.imported+' products</p>';loadProducts()}else{document.getElementById('importStatus').innerHTML='<p class="error-message">'+d.error+'</p>'}}catch(e){document.getElementById('importStatus').innerHTML='<p class="error-message">Upload failed</p>'}});
async function loadUsers(){try{const r=await fetch('/api/users');const u=await r.json();document.getElementById('userTableBody').innerHTML=u.map(x=>'<tr><td>'+x.username+'</td><td>'+x.role+'</td><td>'+new Date(x.created_at).toLocaleDateString()+'</td><td><button class="btn btn-danger" onclick="deleteUser('+x.id+')" style="padding:.5rem 1rem;font-size:.8125rem">Delete</button></td></tr>').join('')}catch(e){}}
document.getElementById('addUserBtn').addEventListener('click',async()=>{const u=document.getElementById('newUsername').value;const p=document.getElementById('newPassword').value;const r=document.getElementById('newRole').value;if(!u||!p){alert('Enter username and password');return}try{const res=await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p,role:r})});const d=await res.json();if(d.success){document.getElementById('newUsername').value='';document.getElementById('newPassword').value='';loadUsers()}else{alert(d.error||'Failed')}}catch(e){alert(e.message)}});
async function deleteUser(id){if(!confirm('Delete user?'))return;try{const r=await fetch('/api/users/'+id,{method:'DELETE'});const d=await r.json();if(d.success)loadUsers();else alert(d.error)}catch(e){alert(e.message)}}
checkSession();
</script>
</body>
</html>`;
}

initDB().then(() => {
    app.listen(PORT, () => { console.log('Product Catalog running on port ' + PORT); });
    setTimeout(() => { startTokenRefreshJob(); }, 5000);
});
