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

// Zoho credentials
let zohoAccessToken = null;

async function initDB() {
    try {
        await pool.query(`CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'sales_rep',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        
        await pool.query(`CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            style_id VARCHAR(100) NOT NULL,
            base_style VARCHAR(100),
            name VARCHAR(255) NOT NULL,
            category VARCHAR(100),
            image_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        
        await pool.query(`CREATE TABLE IF NOT EXISTS product_colors (
            id SERIAL PRIMARY KEY,
            product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
            color_name VARCHAR(100) NOT NULL,
            available_qty INTEGER DEFAULT 0,
            on_hand INTEGER DEFAULT 0,
            open_order INTEGER DEFAULT 0,
            to_come INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        
        await pool.query(`CREATE TABLE IF NOT EXISTS sync_history (
            id SERIAL PRIMARY KEY,
            sync_type VARCHAR(50),
            status VARCHAR(50),
            records_synced INTEGER DEFAULT 0,
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        
        await pool.query(`CREATE TABLE IF NOT EXISTS zoho_tokens (
            id SERIAL PRIMARY KEY,
            access_token TEXT,
            refresh_token TEXT,
            expires_at TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);

        // Create default admin user
        const adminExists = await pool.query("SELECT id FROM users WHERE username = 'admin'");
        if (adminExists.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await pool.query("INSERT INTO users (username, password, role) VALUES ('admin', $1, 'admin')", [hashedPassword]);
        }

        // Load stored token
        const tokenResult = await pool.query("SELECT * FROM zoho_tokens ORDER BY id DESC LIMIT 1");
        if (tokenResult.rows.length > 0) {
            zohoAccessToken = tokenResult.rows[0].access_token;
        }

        console.log('Database initialized successfully');
    } catch (err) {
        console.error('Database initialization error:', err.message);
    }
}

// Auth middleware
function requireAuth(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
}

function requireAdmin(req, res, next) {
    if (req.session && req.session.role === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Admin access required' });
    }
}

// Auth routes
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        
        if (result.rows.length === 0) {
            return res.json({ success: false, error: 'Invalid credentials' });
        }
        
        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.json({ success: false, error: 'Invalid credentials' });
        }
        
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        
        res.json({ success: true, user: { username: user.username, role: user.role } });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/session', (req, res) => {
    if (req.session && req.session.userId) {
        res.json({ 
            authenticated: true, 
            user: { username: req.session.username, role: req.session.role } 
        });
    } else {
        res.json({ authenticated: false });
    }
});

// User management
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, role, created_at FROM users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', [username, hashedPassword, role || 'sales_rep']);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM users WHERE id = $1 AND username != $2', [req.params.id, 'admin']);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// Products
app.get('/api/products', requireAuth, async (req, res) => {
    try {
        const productsResult = await pool.query('SELECT * FROM products ORDER BY category, name');
        const products = productsResult.rows;
        
        for (let product of products) {
            const colorsResult = await pool.query('SELECT * FROM product_colors WHERE product_id = $1 ORDER BY color_name', [product.id]);
            product.colors = colorsResult.rows;
        }
        
        res.json(products);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Zoho OAuth
app.post('/api/zoho/save-credentials', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { clientId, clientSecret, refreshToken } = req.body;
        
        // Store in environment (in production, these would be in Railway variables)
        process.env.ZOHO_CLIENT_ID = clientId;
        process.env.ZOHO_CLIENT_SECRET = clientSecret;
        process.env.ZOHO_REFRESH_TOKEN = refreshToken;
        
        // Try to get access token
        const tokenResult = await refreshZohoToken();
        if (tokenResult.success) {
            res.json({ success: true, message: 'Credentials saved and verified' });
        } else {
            res.json({ success: false, error: tokenResult.error });
        }
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

async function refreshZohoToken() {
    try {
        const clientId = process.env.ZOHO_CLIENT_ID;
        const clientSecret = process.env.ZOHO_CLIENT_SECRET;
        const refreshToken = process.env.ZOHO_REFRESH_TOKEN;
        
        if (!clientId || !clientSecret || !refreshToken) {
            return { success: false, error: 'Missing Zoho credentials' };
        }
        
        const params = new URLSearchParams({
            refresh_token: refreshToken,
            client_id: clientId,
            client_secret: clientSecret,
            grant_type: 'refresh_token'
        });
        
        const response = await fetch('https://accounts.zoho.com/oauth/v2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params.toString()
        });
        
        const data = await response.json();
        
        if (data.access_token) {
            zohoAccessToken = data.access_token;
            const expiresAt = new Date(Date.now() + (data.expires_in || 3600) * 1000);
            
            await pool.query(`
                INSERT INTO zoho_tokens (access_token, refresh_token, expires_at, updated_at)
                VALUES ($1, $2, $3, NOW())
            `, [zohoAccessToken, refreshToken, expiresAt]);
            
            return { success: true };
        } else {
            return { success: false, error: data.error || 'Failed to refresh token' };
        }
    } catch (err) {
        return { success: false, error: err.message };
    }
}

app.get('/api/zoho/status', requireAuth, async (req, res) => {
    const hasCredentials = !!(process.env.ZOHO_CLIENT_ID && process.env.ZOHO_CLIENT_SECRET && process.env.ZOHO_REFRESH_TOKEN);
    const hasToken = !!zohoAccessToken;
    const hasViewId = !!process.env.ZOHO_VIEW_ID;
    const hasWorkspaceId = !!process.env.ZOHO_WORKSPACE_ID;
    
    res.json({
        configured: hasCredentials,
        connected: hasToken,
        viewConfigured: hasViewId && hasWorkspaceId,
        viewId: process.env.ZOHO_VIEW_ID || null,
        workspaceId: process.env.ZOHO_WORKSPACE_ID || null
    });
});

app.post('/api/zoho/test-connection', requireAuth, requireAdmin, async (req, res) => {
    try {
        if (!zohoAccessToken) {
            const tokenResult = await refreshZohoToken();
            if (!tokenResult.success) {
                return res.json({ success: false, error: tokenResult.error });
            }
        }
        
        res.json({ success: true, message: 'Connection successful' });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.post('/api/zoho/sync', requireAuth, requireAdmin, async (req, res) => {
    try {
        const workspaceId = process.env.ZOHO_WORKSPACE_ID;
        const viewId = process.env.ZOHO_VIEW_ID;
        
        if (!workspaceId) {
            await pool.query("INSERT INTO sync_history (sync_type, status, error_message) VALUES ('zoho', 'failed', 'ZOHO_WORKSPACE_ID not configured')");
            return res.json({ success: false, error: 'ZOHO_WORKSPACE_ID not configured in Railway variables' });
        }
        
        if (!viewId) {
            await pool.query("INSERT INTO sync_history (sync_type, status, error_message) VALUES ('zoho', 'failed', 'ZOHO_VIEW_ID not configured')");
            return res.json({ success: false, error: 'ZOHO_VIEW_ID not configured in Railway variables' });
        }
        
        if (!zohoAccessToken) {
            const tokenResult = await refreshZohoToken();
            if (!tokenResult.success) {
                await pool.query("INSERT INTO sync_history (sync_type, status, error_message) VALUES ('zoho', 'failed', $1)", [tokenResult.error]);
                return res.json({ success: false, error: tokenResult.error });
            }
        }
        
        // Use the correct Zoho Analytics API endpoint
        const apiUrl = `https://analyticsapi.zoho.com/restapi/v2/workspaces/${workspaceId}/views/${viewId}/data?CONFIG={"responseFormat":"json"}`;
        
        console.log('Fetching from Zoho:', apiUrl);
        
        let response = await fetch(apiUrl, {
            headers: { 'Authorization': `Zoho-oauthtoken ${zohoAccessToken}` }
        });
        
        // If 401, try refreshing token
        if (response.status === 401) {
            const tokenResult = await refreshZohoToken();
            if (!tokenResult.success) {
                await pool.query("INSERT INTO sync_history (sync_type, status, error_message) VALUES ('zoho', 'failed', $1)", [tokenResult.error]);
                return res.json({ success: false, error: tokenResult.error });
            }
            
            response = await fetch(apiUrl, {
                headers: { 'Authorization': `Zoho-oauthtoken ${zohoAccessToken}` }
            });
        }
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Zoho API error:', response.status, errorText);
            await pool.query("INSERT INTO sync_history (sync_type, status, error_message) VALUES ('zoho', 'failed', $1)", [`API error: ${response.status} - ${errorText}`]);
            return res.json({ success: false, error: `API error: ${response.status} - ${errorText}` });
        }
        
        const data = await response.json();
        console.log('Zoho response keys:', Object.keys(data));
        
        // Parse the Zoho Analytics response
        const rows = data.data || data.rows || [];
        const columns = data.column_order || data.columns || [];
        
        if (rows.length === 0) {
            await pool.query("INSERT INTO sync_history (sync_type, status, error_message) VALUES ('zoho', 'failed', 'No data returned from Zoho')");
            return res.json({ success: false, error: 'No data returned from Zoho Analytics' });
        }
        
        // Process the data - find column indices
        const colMap = {};
        columns.forEach((col, idx) => {
            colMap[col.toLowerCase().replace(/\s+/g, '_')] = idx;
        });
        
        console.log('Column map:', colMap);
        console.log('Sample row:', rows[0]);
        
        // Clear existing data and insert new
        await pool.query('DELETE FROM product_colors');
        await pool.query('DELETE FROM products');
        
        const productMap = new Map();
        let recordCount = 0;
        
        for (const row of rows) {
            // Try to find the style name column
            const styleIdx = colMap['style_name'] ?? colMap['style'] ?? colMap['name'] ?? 0;
            const colorIdx = colMap['color'] ?? colMap['color_name'] ?? 1;
            const categoryIdx = colMap['commodity'] ?? colMap['category'] ?? colMap['type'] ?? 2;
            const qtyIdx = colMap['left_to_sell'] ?? colMap['available'] ?? colMap['qty'] ?? colMap['quantity'] ?? 3;
            
            const styleName = row[styleIdx] || 'Unknown Style';
            const color = row[colorIdx] || 'Default';
            const category = row[categoryIdx] || 'Uncategorized';
            const qty = parseInt(row[qtyIdx]) || 0;
            
            // Create base style key
            const baseStyle = styleName.replace(/\s*-\s*\d+$/, '').trim();
            
            if (!productMap.has(baseStyle)) {
                const result = await pool.query(
                    'INSERT INTO products (style_id, base_style, name, category) VALUES ($1, $2, $3, $4) RETURNING id',
                    [styleName, baseStyle, baseStyle, category]
                );
                productMap.set(baseStyle, result.rows[0].id);
            }
            
            const productId = productMap.get(baseStyle);
            
            await pool.query(
                'INSERT INTO product_colors (product_id, color_name, available_qty) VALUES ($1, $2, $3)',
                [productId, color, qty]
            );
            
            recordCount++;
        }
        
        await pool.query("INSERT INTO sync_history (sync_type, status, records_synced) VALUES ('zoho', 'success', $1)", [recordCount]);
        
        res.json({ success: true, message: `Synced ${recordCount} records from ${productMap.size} products` });
    } catch (err) {
        console.error('Sync error:', err);
        await pool.query("INSERT INTO sync_history (sync_type, status, error_message) VALUES ('zoho', 'failed', $1)", [err.message]);
        res.json({ success: false, error: err.message });
    }
});

app.get('/api/sync-history', requireAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM sync_history ORDER BY created_at DESC LIMIT 20');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// CSV Import
app.post('/api/import', requireAuth, requireAdmin, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.json({ success: false, error: 'No file uploaded' });
        }
        
        const content = req.file.buffer.toString('utf-8');
        const lines = content.split('\n').filter(line => line.trim());
        
        if (lines.length < 2) {
            return res.json({ success: false, error: 'File appears empty' });
        }
        
        // Parse header
        const header = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/"/g, ''));
        
        // Find column indices
        const styleIdx = header.findIndex(h => h.includes('style'));
        const colorIdx = header.findIndex(h => h.includes('color'));
        const categoryIdx = header.findIndex(h => h.includes('commodity') || h.includes('category'));
        const qtyIdx = header.findIndex(h => h.includes('left') || h.includes('sell') || h.includes('available'));
        
        if (styleIdx === -1) {
            return res.json({ success: false, error: 'Could not find Style column' });
        }
        
        // Clear existing data
        await pool.query('DELETE FROM product_colors');
        await pool.query('DELETE FROM products');
        
        const productMap = new Map();
        let imported = 0;
        
        for (let i = 1; i < lines.length; i++) {
            const values = lines[i].split(',').map(v => v.trim().replace(/"/g, ''));
            
            const styleName = values[styleIdx] || '';
            if (!styleName) continue;
            
            const color = colorIdx >= 0 ? values[colorIdx] : 'Default';
            const category = categoryIdx >= 0 ? values[categoryIdx] : 'Uncategorized';
            const qty = qtyIdx >= 0 ? parseInt(values[qtyIdx]) || 0 : 0;
            
            const baseStyle = styleName.replace(/\s*-\s*\d+$/, '').trim();
            
            if (!productMap.has(baseStyle)) {
                const result = await pool.query(
                    'INSERT INTO products (style_id, base_style, name, category) VALUES ($1, $2, $3, $4) RETURNING id',
                    [styleName, baseStyle, baseStyle, category]
                );
                productMap.set(baseStyle, result.rows[0].id);
            }
            
            const productId = productMap.get(baseStyle);
            
            await pool.query(
                'INSERT INTO product_colors (product_id, color_name, available_qty) VALUES ($1, $2, $3)',
                [productId, color, qty]
            );
            
            imported++;
        }
        
        await pool.query("INSERT INTO sync_history (sync_type, status, records_synced) VALUES ('csv', 'success', $1)", [imported]);
        
        res.json({ success: true, imported });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// Token refresh job
function startTokenRefreshJob() {
    setInterval(async () => {
        if (process.env.ZOHO_REFRESH_TOKEN) {
            console.log('Running scheduled token refresh...');
            await refreshZohoToken();
        }
    }, 30 * 60 * 1000); // Every 30 minutes
}

// Serve frontend
app.get('/', (req, res) => {
    res.send(getHTML());
});

function getHTML() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Product Catalog</title>
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --success: #16a34a;
            --danger: #dc2626;
            --warning: #f59e0b;
            --gray-50: #f9fafb;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-300: #d1d5db;
            --gray-500: #6b7280;
            --gray-700: #374151;
            --gray-900: #111827;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--gray-50);
            color: var(--gray-900);
            line-height: 1.5;
        }
        
        .container { max-width: 1400px; margin: 0 auto; padding: 1rem; }
        
        /* Login */
        .login-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
        }
        
        .login-box {
            background: white;
            padding: 2.5rem;
            border-radius: 12px;
            box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25);
            width: 100%;
            max-width: 400px;
        }
        
        .login-box h1 {
            text-align: center;
            margin-bottom: 1.5rem;
            color: var(--gray-900);
        }
        
        .form-group { margin-bottom: 1rem; }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--gray-700);
        }
        
        .form-group input {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--gray-300);
            border-radius: 6px;
            font-size: 1rem;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }
        
        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .btn-primary {
            background: var(--primary);
            color: white;
        }
        
        .btn-primary:hover { background: var(--primary-dark); }
        
        .btn-success {
            background: var(--success);
            color: white;
        }
        
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        
        .btn-block { width: 100%; }
        
        /* Header */
        .header {
            background: white;
            border-bottom: 1px solid var(--gray-200);
            padding: 1rem 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 1rem;
        }
        
        .header h1 {
            font-size: 1.5rem;
            color: var(--primary);
        }
        
        .header-actions {
            display: flex;
            gap: 1rem;
            align-items: center;
        }
        
        /* Tabs */
        .tabs {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
            border-bottom: 1px solid var(--gray-200);
            padding-bottom: 0.5rem;
        }
        
        .tab {
            padding: 0.5rem 1rem;
            border: none;
            background: none;
            cursor: pointer;
            font-size: 1rem;
            color: var(--gray-500);
            border-radius: 6px;
        }
        
        .tab.active {
            background: var(--primary);
            color: white;
        }
        
        /* Search */
        .search-bar {
            margin-bottom: 1.5rem;
        }
        
        .search-bar input {
            width: 100%;
            max-width: 400px;
            padding: 0.75rem 1rem;
            border: 1px solid var(--gray-300);
            border-radius: 6px;
            font-size: 1rem;
        }
        
        /* Category Filters */
        .category-filters {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
        }
        
        .filter-pill {
            padding: 0.5rem 1rem;
            border: 1px solid var(--gray-300);
            border-radius: 9999px;
            background: white;
            cursor: pointer;
            font-size: 0.875rem;
            transition: all 0.2s;
        }
        
        .filter-pill:hover {
            border-color: var(--primary);
        }
        
        .filter-pill.active {
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }
        
        /* Products Grid */
        .product-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 1.5rem;
        }
        
        .product-card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .product-header {
            padding: 1rem;
            border-bottom: 1px solid var(--gray-100);
        }
        
        .product-name {
            font-weight: 600;
            font-size: 1.125rem;
            color: var(--gray-900);
        }
        
        .product-style {
            font-size: 0.875rem;
            color: var(--gray-500);
        }
        
        .product-colors {
            padding: 1rem;
        }
        
        .color-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--gray-100);
        }
        
        .color-row:last-child {
            border-bottom: none;
        }
        
        .color-info {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .color-swatch {
            width: 24px;
            height: 24px;
            border-radius: 50%;
            border: 1px solid var(--gray-300);
        }
        
        .color-name {
            font-size: 0.875rem;
        }
        
        .color-qty {
            font-weight: 600;
            font-size: 0.875rem;
        }
        
        .color-qty.low {
            color: var(--warning);
        }
        
        .color-qty.out {
            color: var(--danger);
        }
        
        .total-row {
            display: flex;
            justify-content: space-between;
            padding: 0.75rem 1rem;
            background: var(--gray-50);
            font-weight: 600;
        }
        
        /* Category Section */
        .category-section {
            margin-bottom: 2rem;
        }
        
        .category-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .category-title {
            font-size: 1.25rem;
            color: var(--gray-900);
        }
        
        .category-count {
            color: var(--gray-500);
            font-size: 0.875rem;
        }
        
        /* Admin Panel */
        .admin-section {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .admin-section h2 {
            margin-bottom: 1rem;
            font-size: 1.125rem;
        }
        
        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        
        .status-badge.success {
            background: #dcfce7;
            color: #166534;
        }
        
        .status-badge.error {
            background: #fef2f2;
            color: #dc2626;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--gray-200);
        }
        
        th {
            font-weight: 600;
            color: var(--gray-700);
        }
        
        .hidden { display: none !important; }
        
        .error-message { color: var(--danger); margin-top: 0.5rem; }
        .success-message { color: var(--success); margin-top: 0.5rem; }
        
        @media (max-width: 768px) {
            .product-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <!-- Login Screen -->
    <div id="loginScreen" class="login-container">
        <div class="login-box">
            <h1>Product Catalog</h1>
            <form id="loginForm">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="loginUsername" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="loginPassword" required>
                </div>
                <button type="submit" class="btn btn-primary btn-block">Login</button>
                <p id="loginError" class="error-message hidden"></p>
            </form>
        </div>
    </div>
    
    <!-- Main App -->
    <div id="appScreen" class="hidden">
        <header class="header">
            <div class="header-content">
                <h1>Product Catalog</h1>
                <div class="header-actions">
                    <span id="userDisplay"></span>
                    <button id="logoutBtn" class="btn">Logout</button>
                </div>
            </div>
        </header>
        
        <div class="container">
            <div class="tabs">
                <button class="tab active" data-tab="catalog">Catalog</button>
                <button class="tab" data-tab="admin" id="adminTab">Admin</button>
            </div>
            
            <!-- Catalog Tab -->
            <div id="catalogTab">
                <div class="search-bar">
                    <input type="text" id="searchInput" placeholder="Search by style, color, or category...">
                </div>
                
                <div class="category-filters" id="categoryFilters"></div>
                
                <div id="productsContainer"></div>
            </div>
            
            <!-- Admin Tab -->
            <div id="adminTabContent" class="hidden">
                <!-- Zoho Integration -->
                <div class="admin-section">
                    <h2>Zoho Analytics Integration</h2>
                    <div id="zohoStatus" style="margin-bottom: 1rem;"></div>
                    
                    <div style="display: grid; gap: 1rem; max-width: 500px;">
                        <div class="form-group">
                            <label>Client ID</label>
                            <input type="text" id="zohoClientId" placeholder="From Zoho API Console">
                        </div>
                        <div class="form-group">
                            <label>Client Secret</label>
                            <input type="password" id="zohoClientSecret" placeholder="From Zoho API Console">
                        </div>
                        <div class="form-group">
                            <label>Refresh Token</label>
                            <input type="text" id="zohoRefreshToken" placeholder="From OAuth flow">
                        </div>
                        <div style="display: flex; gap: 1rem;">
                            <button id="saveZohoBtn" class="btn btn-primary">Save Credentials</button>
                            <button id="testZohoBtn" class="btn">Test Connection</button>
                            <button id="syncZohoBtn" class="btn btn-success">Sync Now</button>
                        </div>
                        <p id="zohoMessage"></p>
                    </div>
                </div>
                
                <!-- CSV Import -->
                <div class="admin-section">
                    <h2>CSV Import</h2>
                    <p style="margin-bottom: 1rem; color: var(--gray-500);">Import from Zoho Analytics CSV export</p>
                    <input type="file" id="csvFile" accept=".csv">
                    <button id="importBtn" class="btn btn-primary" style="margin-left: 1rem;">Import</button>
                    <div id="importStatus"></div>
                </div>
                
                <!-- Sync History -->
                <div class="admin-section">
                    <h2>Sync History</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Type</th>
                                <th>Status</th>
                                <th>Records</th>
                                <th>Error</th>
                            </tr>
                        </thead>
                        <tbody id="syncHistoryBody"></tbody>
                    </table>
                </div>
                
                <!-- User Management -->
                <div class="admin-section">
                    <h2>User Management</h2>
                    <div style="display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap;">
                        <input type="text" id="newUsername" placeholder="Username" style="padding: 0.5rem;">
                        <input type="password" id="newPassword" placeholder="Password" style="padding: 0.5rem;">
                        <select id="newRole" style="padding: 0.5rem;">
                            <option value="sales_rep">Sales Rep</option>
                            <option value="admin">Admin</option>
                        </select>
                        <button id="addUserBtn" class="btn btn-primary">Add User</button>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Role</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="userTableBody"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let products = [];
        let currentCategory = 'all';
        let currentUser = null;
        
        // Check session on load
        async function checkSession() {
            try {
                const res = await fetch('/api/session');
                const data = await res.json();
                
                if (data.authenticated) {
                    currentUser = data.user;
                    showApp();
                } else {
                    showLogin();
                }
            } catch (err) {
                showLogin();
            }
        }
        
        function showLogin() {
            document.getElementById('loginScreen').classList.remove('hidden');
            document.getElementById('appScreen').classList.add('hidden');
        }
        
        function showApp() {
            document.getElementById('loginScreen').classList.add('hidden');
            document.getElementById('appScreen').classList.remove('hidden');
            document.getElementById('userDisplay').textContent = currentUser.username + ' (' + currentUser.role + ')';
            
            if (currentUser.role !== 'admin') {
                document.getElementById('adminTab').classList.add('hidden');
            } else {
                document.getElementById('adminTab').classList.remove('hidden');
            }
            
            loadProducts();
            loadZohoStatus();
            loadSyncHistory();
            loadUsers();
        }
        
        // Login form
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            
            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: username, password: password })
                });
                const data = await res.json();
                
                if (data.success) {
                    currentUser = data.user;
                    showApp();
                } else {
                    document.getElementById('loginError').textContent = data.error;
                    document.getElementById('loginError').classList.remove('hidden');
                }
            } catch (err) {
                document.getElementById('loginError').textContent = 'Login failed';
                document.getElementById('loginError').classList.remove('hidden');
            }
        });
        
        // Logout
        document.getElementById('logoutBtn').addEventListener('click', async function() {
            await fetch('/api/logout', { method: 'POST' });
            currentUser = null;
            showLogin();
        });
        
        // Tabs
        document.querySelectorAll('.tab').forEach(function(tab) {
            tab.addEventListener('click', function() {
                document.querySelectorAll('.tab').forEach(function(t) {
                    t.classList.remove('active');
                });
                this.classList.add('active');
                
                const tabName = this.dataset.tab;
                if (tabName === 'catalog') {
                    document.getElementById('catalogTab').classList.remove('hidden');
                    document.getElementById('adminTabContent').classList.add('hidden');
                } else {
                    document.getElementById('catalogTab').classList.add('hidden');
                    document.getElementById('adminTabContent').classList.remove('hidden');
                }
            });
        });
        
        // Search
        document.getElementById('searchInput').addEventListener('input', function() {
            renderProducts();
        });
        
        // Load products
        async function loadProducts() {
            try {
                const res = await fetch('/api/products');
                products = await res.json();
                updateCategoryFilters();
                renderProducts();
            } catch (err) {
                console.error('Failed to load products:', err);
            }
        }
        
        function updateCategoryFilters() {
            var cats = [];
            products.forEach(function(p) {
                if (p.category && cats.indexOf(p.category) === -1) {
                    cats.push(p.category);
                }
            });
            cats.sort();
            
            var c = document.getElementById('categoryFilters');
            c.innerHTML = '<button class="filter-pill active" data-category="all">All</button>';
            
            cats.forEach(function(cat) {
                c.innerHTML += '<button class="filter-pill" data-category="' + cat + '">' + cat + '</button>';
            });
            
            document.querySelectorAll('.filter-pill').forEach(function(pill) {
                pill.addEventListener('click', function(e) {
                    document.querySelectorAll('.filter-pill').forEach(function(p) {
                        p.classList.remove('active');
                    });
                    e.target.classList.add('active');
                    currentCategory = e.target.dataset.category;
                    renderProducts();
                });
            });
        }
        
        function formatNumber(n) {
            return (n || 0).toLocaleString();
        }
        
        function getSwatchStyle(colorName) {
            var colors = {
                'black': '#1A1A1A',
                'white': '#FFFFFF',
                'ivory': 'linear-gradient(145deg, #FFFFF0, #F5F5DC)',
                'cream': 'linear-gradient(145deg, #FFFDD0, #F5E6C8)',
                'heather grey': 'linear-gradient(145deg, #9CA3AF, #6B7280)',
                'grey': '#808080',
                'gray': '#808080',
                'charcoal': '#36454F',
                'navy': '#1E3A5F',
                'blue': '#2563EB',
                'pink': 'linear-gradient(145deg, #F9A8D4, #EC4899)',
                'red': '#DC2626',
                'burgundy': '#722F37',
                'brown': 'linear-gradient(145deg, #A78B71, #78583A)',
                'olive': '#556B2F',
                'green': '#16A34A',
                'yellow': '#EAB308',
                'purple': '#9333EA',
                'orange': '#F97316',
                'beige': '#D4C4A8',
                'silver': '#C0C0C0',
                'gold': '#FFD700',
                'sage': '#9CAF88'
            };
            var key = (colorName || '').toLowerCase();
            return colors[key] || '#CCCCCC';
        }
        
        function renderProducts() {
            var searchTerm = document.getElementById('searchInput').value.toLowerCase();
            
            var filtered = products.filter(function(p) {
                var matchesSearch = !searchTerm ||
                    (p.style_id || '').toLowerCase().indexOf(searchTerm) !== -1 ||
                    (p.name || '').toLowerCase().indexOf(searchTerm) !== -1 ||
                    (p.category || '').toLowerCase().indexOf(searchTerm) !== -1 ||
                    (p.colors || []).some(function(c) {
                        return (c.color_name || '').toLowerCase().indexOf(searchTerm) !== -1;
                    });
                
                var matchesCategory = currentCategory === 'all' || p.category === currentCategory;
                
                return matchesSearch && matchesCategory;
            });
            
            // Group by category
            var byCategory = {};
            filtered.forEach(function(p) {
                var cat = p.category || 'Uncategorized';
                if (!byCategory[cat]) {
                    byCategory[cat] = [];
                }
                byCategory[cat].push(p);
            });
            
            var html = '';
            var catKeys = Object.keys(byCategory).sort();
            
            catKeys.forEach(function(cat) {
                var catProducts = byCategory[cat];
                html += '<section class="category-section">';
                html += '<div class="category-header">';
                html += '<h2 class="category-title">' + cat + '</h2>';
                html += '<span class="category-count">' + catProducts.length + ' style' + (catProducts.length !== 1 ? 's' : '') + '</span>';
                html += '</div>';
                html += '<div class="product-grid">';
                
                catProducts.forEach(function(p) {
                    var colors = p.colors || [];
                    var total = colors.reduce(function(sum, c) {
                        return sum + (c.available_qty || 0);
                    }, 0);
                    
                    html += '<div class="product-card">';
                    html += '<div class="product-header">';
                    html += '<div class="product-name">' + (p.name || 'Unknown') + '</div>';
                    html += '<div class="product-style">' + (p.style_id || '') + '</div>';
                    html += '</div>';
                    html += '<div class="product-colors">';
                    
                    colors.forEach(function(c) {
                        var qtyClass = '';
                        if (c.available_qty === 0) {
                            qtyClass = ' out';
                        } else if (c.available_qty < 100) {
                            qtyClass = ' low';
                        }
                        
                        html += '<div class="color-row">';
                        html += '<div class="color-info">';
                        html += '<div class="color-swatch" style="background: ' + getSwatchStyle(c.color_name) + '"></div>';
                        html += '<span class="color-name">' + (c.color_name || 'Unknown') + '</span>';
                        html += '</div>';
                        html += '<span class="color-qty' + qtyClass + '">' + formatNumber(c.available_qty) + '</span>';
                        html += '</div>';
                    });
                    
                    html += '</div>';
                    html += '<div class="total-row">';
                    html += '<span>Total Available</span>';
                    html += '<span>' + formatNumber(total) + '</span>';
                    html += '</div>';
                    html += '</div>';
                });
                
                html += '</div></section>';
            });
            
            document.getElementById('productsContainer').innerHTML = html;
        }
        
        // Zoho functions
        async function loadZohoStatus() {
            try {
                var res = await fetch('/api/zoho/status');
                var data = await res.json();
                
                var statusHtml = '<p>Status: ';
                if (data.connected) {
                    statusHtml += '<span class="status-badge success">Connected</span>';
                } else if (data.configured) {
                    statusHtml += '<span class="status-badge" style="background:#fef3c7;color:#92400e;">Configured - Not Connected</span>';
                } else {
                    statusHtml += '<span class="status-badge error">Not Configured</span>';
                }
                
                if (data.viewId) {
                    statusHtml += ' | View ID: ' + data.viewId;
                } else {
                    statusHtml += ' | <span style="color:var(--warning);">View ID not set</span>';
                }
                
                statusHtml += '</p>';
                document.getElementById('zohoStatus').innerHTML = statusHtml;
            } catch (err) {
                console.error('Failed to load Zoho status:', err);
            }
        }
        
        document.getElementById('saveZohoBtn').addEventListener('click', async function() {
            var clientId = document.getElementById('zohoClientId').value;
            var clientSecret = document.getElementById('zohoClientSecret').value;
            var refreshToken = document.getElementById('zohoRefreshToken').value;
            
            if (!clientId || !clientSecret || !refreshToken) {
                document.getElementById('zohoMessage').innerHTML = '<span class="error-message">Please fill all fields</span>';
                return;
            }
            
            try {
                var res = await fetch('/api/zoho/save-credentials', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        clientId: clientId,
                        clientSecret: clientSecret,
                        refreshToken: refreshToken
                    })
                });
                var data = await res.json();
                
                if (data.success) {
                    document.getElementById('zohoMessage').innerHTML = '<span class="success-message">Credentials saved!</span>';
                    loadZohoStatus();
                } else {
                    document.getElementById('zohoMessage').innerHTML = '<span class="error-message">' + data.error + '</span>';
                }
            } catch (err) {
                document.getElementById('zohoMessage').innerHTML = '<span class="error-message">Failed to save</span>';
            }
        });
        
        document.getElementById('testZohoBtn').addEventListener('click', async function() {
            try {
                document.getElementById('zohoMessage').innerHTML = 'Testing...';
                var res = await fetch('/api/zoho/test-connection', { method: 'POST' });
                var data = await res.json();
                
                if (data.success) {
                    document.getElementById('zohoMessage').innerHTML = '<span class="success-message">Connection successful!</span>';
                    loadZohoStatus();
                } else {
                    document.getElementById('zohoMessage').innerHTML = '<span class="error-message">' + data.error + '</span>';
                }
            } catch (err) {
                document.getElementById('zohoMessage').innerHTML = '<span class="error-message">Test failed</span>';
            }
        });
        
        document.getElementById('syncZohoBtn').addEventListener('click', async function() {
            try {
                document.getElementById('zohoMessage').innerHTML = 'Syncing...';
                var res = await fetch('/api/zoho/sync', { method: 'POST' });
                var data = await res.json();
                
                if (data.success) {
                    document.getElementById('zohoMessage').innerHTML = '<span class="success-message">' + data.message + '</span>';
                    loadProducts();
                    loadSyncHistory();
                } else {
                    document.getElementById('zohoMessage').innerHTML = '<span class="error-message">' + data.error + '</span>';
                    loadSyncHistory();
                }
            } catch (err) {
                document.getElementById('zohoMessage').innerHTML = '<span class="error-message">Sync failed</span>';
            }
        });
        
        // Sync history
        async function loadSyncHistory() {
            try {
                var res = await fetch('/api/sync-history');
                var history = await res.json();
                
                var html = '';
                history.forEach(function(h) {
                    html += '<tr>';
                    html += '<td>' + new Date(h.created_at).toLocaleString() + '</td>';
                    html += '<td>' + h.sync_type + '</td>';
                    html += '<td style="color:' + (h.status === 'success' ? 'var(--success)' : 'var(--danger)') + '">' + h.status + '</td>';
                    html += '<td>' + (h.records_synced || '-') + '</td>';
                    html += '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + (h.error_message || '-') + '</td>';
                    html += '</tr>';
                });
                
                document.getElementById('syncHistoryBody').innerHTML = html;
            } catch (err) {
                console.error('Failed to load sync history:', err);
            }
        }
        
        // CSV Import
        document.getElementById('importBtn').addEventListener('click', async function() {
            var fileInput = document.getElementById('csvFile');
            if (!fileInput.files[0]) {
                document.getElementById('importStatus').innerHTML = '<p class="error-message">Please select a file</p>';
                return;
            }
            
            var formData = new FormData();
            formData.append('file', fileInput.files[0]);
            
            try {
                var res = await fetch('/api/import', {
                    method: 'POST',
                    body: formData
                });
                var data = await res.json();
                
                if (data.success) {
                    document.getElementById('importStatus').innerHTML = '<p class="success-message">Imported ' + data.imported + ' records</p>';
                    loadProducts();
                    loadSyncHistory();
                } else {
                    document.getElementById('importStatus').innerHTML = '<p class="error-message">' + data.error + '</p>';
                }
            } catch (err) {
                document.getElementById('importStatus').innerHTML = '<p class="error-message">Upload failed</p>';
            }
        });
        
        // User management
        async function loadUsers() {
            try {
                var res = await fetch('/api/users');
                var users = await res.json();
                
                var html = '';
                users.forEach(function(u) {
                    html += '<tr>';
                    html += '<td>' + u.username + '</td>';
                    html += '<td>' + u.role + '</td>';
                    html += '<td>' + new Date(u.created_at).toLocaleDateString() + '</td>';
                    html += '<td><button class="btn btn-danger" onclick="deleteUser(' + u.id + ')" style="padding:0.5rem 1rem;font-size:0.8125rem">Delete</button></td>';
                    html += '</tr>';
                });
                
                document.getElementById('userTableBody').innerHTML = html;
            } catch (err) {
                console.error('Failed to load users:', err);
            }
        }
        
        document.getElementById('addUserBtn').addEventListener('click', async function() {
            var username = document.getElementById('newUsername').value;
            var password = document.getElementById('newPassword').value;
            var role = document.getElementById('newRole').value;
            
            if (!username || !password) {
                alert('Please enter username and password');
                return;
            }
            
            try {
                var res = await fetch('/api/users', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: username, password: password, role: role })
                });
                var data = await res.json();
                
                if (data.success) {
                    document.getElementById('newUsername').value = '';
                    document.getElementById('newPassword').value = '';
                    loadUsers();
                } else {
                    alert(data.error || 'Failed to add user');
                }
            } catch (err) {
                alert('Error: ' + err.message);
            }
        });
        
        async function deleteUser(id) {
            if (!confirm('Delete this user?')) return;
            
            try {
                var res = await fetch('/api/users/' + id, { method: 'DELETE' });
                var data = await res.json();
                
                if (data.success) {
                    loadUsers();
                } else {
                    alert(data.error || 'Failed to delete');
                }
            } catch (err) {
                alert('Error: ' + err.message);
            }
        }
        
        // Initialize
        checkSession();
    </script>
</body>
</html>`;
}

// Start server
initDB().then(function() {
    app.listen(PORT, function() {
        console.log('Product Catalog running on port ' + PORT);
    });
    setTimeout(function() {
        startTokenRefreshJob();
    }, 5000);
});
