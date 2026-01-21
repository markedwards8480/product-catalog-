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

async function initDB() {
    try {
        await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL, role VARCHAR(50) DEFAULT 'sales_rep', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, style_id VARCHAR(100) NOT NULL, base_style VARCHAR(100), name VARCHAR(255) NOT NULL, category VARCHAR(100), image_url TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS product_colors (id SERIAL PRIMARY KEY, product_id INTEGER REFERENCES products(id) ON DELETE CASCADE, color_name VARCHAR(100) NOT NULL, available_qty INTEGER DEFAULT 0, on_hand INTEGER DEFAULT 0, open_order INTEGER DEFAULT 0, to_come INTEGER DEFAULT 0, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS sync_history (id SERIAL PRIMARY KEY, sync_type VARCHAR(50), status VARCHAR(50), records_synced INTEGER DEFAULT 0, error_message TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
        const userCheck = await pool.query('SELECT COUNT(*) FROM users');
        if (parseInt(userCheck.rows[0].count) === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await pool.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', ['admin', hash, 'admin']);
            console.log('Default admin user created (admin/admin123)');
        }
        console.log('Database initialized successfully');
    } catch (err) { console.error('Database initialization error:', err); }
}

function requireAuth(req, res, next) { if (req.session && req.session.userId) next(); else res.status(401).json({ error: 'Unauthorized' }); }
function requireAdmin(req, res, next) { if (req.session && req.session.role === 'admin') next(); else res.status(403).json({ error: 'Admin access required' }); }

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        const user = result.rows[0];
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        res.json({ success: true, username: user.username, role: user.role });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/session', (req, res) => {
    if (req.session && req.session.userId) res.json({ loggedIn: true, username: req.session.username, role: req.session.role });
    else res.json({ loggedIn: false });
});

app.get('/api/products', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT p.id, p.style_id, p.base_style, p.name, p.category, p.image_url,
            json_agg(json_build_object('id', pc.id, 'color_name', pc.color_name, 'available_qty', pc.available_qty, 'on_hand', pc.on_hand)) FILTER (WHERE pc.id IS NOT NULL) as colors
            FROM products p LEFT JOIN product_colors pc ON p.id = pc.product_id
            GROUP BY p.id ORDER BY p.category, p.name`);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/zoho/sync-history', requireAuth, requireAdmin, async (req, res) => {
    try { const result = await pool.query('SELECT * FROM sync_history ORDER BY created_at DESC LIMIT 20'); res.json(result.rows); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

function parseCSVLine(line) {
    const result = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
        const char = line[i];
        if (char === '"') { inQuotes = !inQuotes; }
        else if (char === ',' && !inQuotes) { result.push(current.trim()); current = ''; }
        else { current += char; }
    }
    result.push(current.trim());
    return result;
}

function parseNumber(val) {
    if (!val) return 0;
    return parseInt(val.toString().replace(/,/g, '').replace(/"/g, '').trim()) || 0;
}

app.post('/api/import', requireAuth, requireAdmin, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        const content = req.file.buffer.toString('utf-8');
        const lines = content.split('\n').filter(line => line.trim());
        if (lines.length < 2) return res.status(400).json({ error: 'File appears empty' });

        let headerLine = lines[0];
        if (headerLine.charCodeAt(0) === 0xFEFF) headerLine = headerLine.slice(1);
        const headers = parseCSVLine(headerLine).map(h => h.toLowerCase().replace(/[^\w\s]/g, '').trim());
        console.log('CSV Headers:', headers);

        const headerMap = {};
        headers.forEach((h, idx) => { headerMap[h] = idx; });

        let imported = 0, skipped = 0;
        let lastStyleId = null, lastImageUrl = null, lastCategory = null;

        for (let i = 1; i < lines.length; i++) {
            try {
                const values = parseCSVLine(lines[i]);
                if (values[0] && values[0].includes('Grand Summary')) { skipped++; continue; }

                let styleId = values[headerMap['style name']] || values[0];
                let imageUrl = values[headerMap['style image']] || values[1];
                let color = values[headerMap['color']] || values[2];
                let category = values[headerMap['commodity']] || values[3];
                let onHand = parseNumber(values[headerMap['on hand']] || values[4]);
                let allocated = parseNumber(values[headerMap['allocated on hand']] || values[5]);
                let available = parseNumber(values[headerMap['available now']] || values[headerMap['left to sell']] || values[7]);

                if (!styleId && color) {
                    styleId = lastStyleId;
                    if (!imageUrl || imageUrl === '-No Value-') imageUrl = lastImageUrl;
                    if (!category || category === '-No Value-') category = lastCategory;
                }
                if (!styleId) { skipped++; continue; }

                lastStyleId = styleId;
                if (imageUrl && imageUrl !== '-No Value-' && imageUrl.startsWith('http')) lastImageUrl = imageUrl;
                if (category && category !== '-No Value-') lastCategory = category;

                const baseStyle = styleId.split('-')[0];
                const validCategory = (category && category !== '-No Value-') ? category : 'Uncategorized';
                const name = validCategory + ' - ' + baseStyle;
                const validImageUrl = (imageUrl && imageUrl !== '-No Value-' && imageUrl.startsWith('http')) ? imageUrl : lastImageUrl;

                let productResult = await pool.query('SELECT id, image_url FROM products WHERE style_id = $1', [styleId]);
                let productId;

                if (productResult.rows.length > 0) {
                    productId = productResult.rows[0].id;
                    const finalImage = validImageUrl || productResult.rows[0].image_url;
                    await pool.query('UPDATE products SET name=$1, category=$2, base_style=$3, image_url=$4, updated_at=CURRENT_TIMESTAMP WHERE id=$5',
                        [name, validCategory, baseStyle, finalImage, productId]);
                } else {
                    const ins = await pool.query('INSERT INTO products (style_id, base_style, name, category, image_url) VALUES ($1,$2,$3,$4,$5) RETURNING id',
                        [styleId, baseStyle, name, validCategory, validImageUrl]);
                    productId = ins.rows[0].id;
                }

                if (color && color !== '-No Value-') {
                    const colorResult = await pool.query('SELECT id FROM product_colors WHERE product_id=$1 AND color_name=$2', [productId, color]);
                    if (colorResult.rows.length > 0) {
                        await pool.query('UPDATE product_colors SET available_qty=$1, on_hand=$2, updated_at=CURRENT_TIMESTAMP WHERE id=$3',
                            [available, onHand, colorResult.rows[0].id]);
                    } else {
                        await pool.query('INSERT INTO product_colors (product_id, color_name, available_qty, on_hand) VALUES ($1,$2,$3,$4)',
                            [productId, color, available, onHand]);
                    }
                }
                imported++;
            } catch (rowErr) { console.error('Row error:', rowErr.message); skipped++; }
        }

        await pool.query('INSERT INTO sync_history (sync_type, status, records_synced) VALUES ($1,$2,$3)', ['csv_import', 'success', imported]);
        res.json({ success: true, imported, skipped });
    } catch (err) { console.error('Import error:', err); res.status(500).json({ error: err.message }); }
});

app.post('/api/products/clear', requireAuth, requireAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM product_colors');
        await pool.query('DELETE FROM products');
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try { const result = await pool.query('SELECT id, username, role, created_at FROM users ORDER BY created_at'); res.json(result.rows); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username, password, role } = req.body;
        const hash = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password, role) VALUES ($1,$2,$3)', [username, hash, role || 'sales_rep']);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        if (req.params.id == req.session.userId) return res.status(400).json({ error: 'Cannot delete yourself' });
        await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('*', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Product Catalog</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
.login-page { min-height: 100vh; display: flex; align-items: center; justify-content: center; }
.login-box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 100%; max-width: 360px; }
.login-box h1 { margin-bottom: 1.5rem; font-size: 1.5rem; text-align: center; }
.form-group { margin-bottom: 1rem; }
.form-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
.form-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; }
.btn { padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }
.btn-primary { background: #2c5545; color: white; width: 100%; }
.btn-secondary { background: #eee; color: #333; }
.btn-danger { background: #c4553d; color: white; }
.error { color: #c4553d; margin-top: 1rem; text-align: center; }
.success { color: #2e7d32; }
.hidden { display: none !important; }
.header { background: white; padding: 1rem 2rem; border-bottom: 1px solid #ddd; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }
.header h1 { font-size: 1.25rem; }
.header-right { display: flex; gap: 1rem; align-items: center; }
.search-box input { padding: 0.5rem 1rem; border: 1px solid #ddd; border-radius: 4px; width: 250px; }
.main { max-width: 1400px; margin: 0 auto; padding: 2rem; }
.admin-panel { background: white; padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem; }
.admin-panel h2 { margin-bottom: 1rem; }
.tabs { display: flex; gap: 0.5rem; margin-bottom: 1rem; }
.tab { padding: 0.5rem 1rem; border: none; background: #eee; cursor: pointer; border-radius: 4px; }
.tab.active { background: #2c5545; color: white; }
.tab-content { display: none; }
.tab-content.active { display: block; }
.upload-area { border: 2px dashed #ddd; padding: 2rem; text-align: center; border-radius: 4px; margin-bottom: 1rem; }
.upload-area input { display: none; }
.upload-area label { color: #2c5545; cursor: pointer; }
.stats { display: flex; gap: 2rem; margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 8px; }
.stat-value { font-size: 1.5rem; font-weight: bold; }
.stat-label { color: #666; font-size: 0.875rem; }
.filters { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }
.filter-btn { padding: 0.5rem 1rem; border: 1px solid #ddd; background: white; border-radius: 20px; cursor: pointer; }
.filter-btn.active { background: #2c5545; color: white; border-color: #2c5545; }
.product-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1.5rem; }
.product-card { background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); cursor: pointer; }
.product-card:hover { transform: translateY(-2px); box-shadow: 0 4px 16px rgba(0,0,0,0.15); }
.product-image { height: 200px; background: #f0f0f0; display: flex; align-items: center; justify-content: center; overflow: hidden; }
.product-image img { width: 100%; height: 100%; object-fit: cover; }
.product-info { padding: 1rem; }
.product-style { font-size: 0.75rem; color: #666; text-transform: uppercase; }
.product-name { font-size: 1.1rem; font-weight: 600; margin: 0.25rem 0; }
.color-list { margin-top: 0.75rem; }
.color-row { display: flex; justify-content: space-between; padding: 0.25rem 0; font-size: 0.875rem; }
.total-row { margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid #eee; font-weight: bold; display: flex; justify-content: space-between; }
.empty { text-align: center; padding: 3rem; color: #666; }
.modal { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: none; align-items: center; justify-content: center; z-index: 1000; }
.modal.active { display: flex; }
.modal-content { background: white; border-radius: 8px; max-width: 800px; width: 90%; max-height: 90vh; overflow: auto; display: flex; }
.modal-image { width: 50%; background: #f0f0f0; display: flex; align-items: center; justify-content: center; }
.modal-image img { width: 100%; height: 100%; object-fit: cover; }
.modal-details { width: 50%; padding: 2rem; }
.modal-close { position: absolute; top: 1rem; right: 1rem; background: white; border: none; font-size: 1.5rem; cursor: pointer; border-radius: 50%; width: 36px; height: 36px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #eee; }
.add-form { display: flex; gap: 0.5rem; margin-top: 1rem; flex-wrap: wrap; }
.add-form input, .add-form select { padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; }
@media (max-width: 768px) { .modal-content { flex-direction: column; } .modal-image, .modal-details { width: 100%; } }
</style>
</head>
<body>

<div id="loginPage" class="login-page">
<div class="login-box">
<h1>Product Catalog</h1>
<form id="loginForm">
<div class="form-group"><label>Username</label><input type="text" id="username" required></div>
<div class="form-group"><label>Password</label><input type="password" id="password" required></div>
<button type="submit" class="btn btn-primary">Sign In</button>
<div id="loginError" class="error hidden"></div>
</form>
</div>
</div>

<div id="mainApp" class="hidden">
<header class="header">
<h1>Product Catalog</h1>
<div class="search-box"><input type="text" id="searchInput" placeholder="Search products..."></div>
<div class="header-right">
<span id="userInfo"></span>
<button class="btn btn-secondary" id="adminBtn" style="display:none">Admin</button>
<button class="btn btn-secondary" id="logoutBtn">Sign Out</button>
</div>
</header>

<main class="main">
<div id="adminPanel" class="admin-panel hidden">
<h2>Admin Panel</h2>
<div class="tabs">
<button class="tab active" data-tab="import">Import CSV</button>
<button class="tab" data-tab="users">Users</button>
<button class="tab" data-tab="history">History</button>
</div>

<div id="importTab" class="tab-content active">
<div class="upload-area">
<input type="file" id="csvFile" accept=".csv">
<label for="csvFile">Click to upload CSV file</label>
</div>
<div id="importStatus"></div>
<button class="btn btn-danger" id="clearBtn" style="margin-top:1rem">Clear All Products</button>
</div>

<div id="usersTab" class="tab-content">
<table><thead><tr><th>Username</th><th>Role</th><th>Actions</th></tr></thead><tbody id="usersTable"></tbody></table>
<div class="add-form">
<input type="text" id="newUser" placeholder="Username">
<input type="password" id="newPass" placeholder="Password">
<select id="newRole"><option value="sales_rep">Sales Rep</option><option value="admin">Admin</option></select>
<button class="btn btn-primary" id="addUserBtn">Add</button>
</div>
</div>

<div id="historyTab" class="tab-content">
<table><thead><tr><th>Date</th><th>Type</th><th>Status</th><th>Records</th></tr></thead><tbody id="historyTable"></tbody></table>
</div>
</div>

<div class="stats">
<div><div class="stat-value" id="totalStyles">0</div><div class="stat-label">Styles</div></div>
<div><div class="stat-value" id="totalUnits">0</div><div class="stat-label">Units Available</div></div>
</div>

<div class="filters" id="filters"></div>
<div class="product-grid" id="productGrid"></div>
<div class="empty hidden" id="emptyState">No products found. Import a CSV to get started.</div>
</main>
</div>

<div class="modal" id="modal">
<button class="modal-close" onclick="closeModal()">&times;</button>
<div class="modal-content">
<div class="modal-image"><img id="modalImage" src="" alt=""></div>
<div class="modal-details">
<div class="product-style" id="modalStyle"></div>
<h2 id="modalName"></h2>
<p id="modalCategory" style="color:#666;margin-bottom:1rem"></p>
<div id="modalColors"></div>
<div class="total-row"><span>Total Available</span><span id="modalTotal"></span></div>
</div>
</div>
</div>

<script>
let products = [];
let currentFilter = 'all';

async function checkSession() {
    const res = await fetch('/api/session');
    const data = await res.json();
    if (data.loggedIn) {
        showApp(data.username, data.role);
        loadProducts();
        if (data.role === 'admin') { loadUsers(); loadHistory(); }
    } else {
        document.getElementById('loginPage').classList.remove('hidden');
        document.getElementById('mainApp').classList.add('hidden');
    }
}

function showApp(username, role) {
    document.getElementById('loginPage').classList.add('hidden');
    document.getElementById('mainApp').classList.remove('hidden');
    document.getElementById('userInfo').textContent = 'Welcome, ' + username;
    if (role === 'admin') document.getElementById('adminBtn').style.display = 'block';
}

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (data.success) {
        showApp(data.username, data.role);
        loadProducts();
        if (data.role === 'admin') { loadUsers(); loadHistory(); }
    } else {
        document.getElementById('loginError').textContent = data.error;
        document.getElementById('loginError').classList.remove('hidden');
    }
});

document.getElementById('logoutBtn').addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    location.reload();
});

document.getElementById('adminBtn').addEventListener('click', () => {
    document.getElementById('adminPanel').classList.toggle('hidden');
});

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(tab.dataset.tab + 'Tab').classList.add('active');
    });
});

async function loadProducts() {
    const res = await fetch('/api/products');
    products = await res.json();
    renderFilters();
    renderProducts();
}

function renderFilters() {
    const cats = [...new Set(products.map(p => p.category).filter(Boolean))];
    const html = '<button class="filter-btn active" data-cat="all">All</button>' +
        cats.sort().map(c => '<button class="filter-btn" data-cat="' + c + '">' + c + '</button>').join('');
    document.getElementById('filters').innerHTML = html;
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.dataset.cat;
            renderProducts();
        });
    });
}

function renderProducts() {
    const search = document.getElementById('searchInput').value.toLowerCase();
    let filtered = products.filter(p => {
        const matchSearch = !search || p.style_id.toLowerCase().includes(search) || p.name.toLowerCase().includes(search) ||
            (p.colors || []).some(c => c.color_name.toLowerCase().includes(search));
        const matchCat = currentFilter === 'all' || p.category === currentFilter;
        return matchSearch && matchCat;
    });

    if (filtered.length === 0) {
        document.getElementById('productGrid').innerHTML = '';
        document.getElementById('emptyState').classList.remove('hidden');
    } else {
        document.getElementById('emptyState').classList.add('hidden');
        document.getElementById('productGrid').innerHTML = filtered.map(p => {
            const colors = p.colors || [];
            const total = colors.reduce((s, c) => s + (c.available_qty || 0), 0);
            const colorHtml = colors.slice(0, 3).map(c =>
                '<div class="color-row"><span>' + c.color_name + '</span><span>' + (c.available_qty || 0).toLocaleString() + '</span></div>'
            ).join('') + (colors.length > 3 ? '<div class="color-row" style="color:#999">+' + (colors.length - 3) + ' more</div>' : '');
            return '<div class="product-card" onclick="openModal(' + p.id + ')">' +
                '<div class="product-image">' + (p.image_url ? '<img src="' + p.image_url + '" onerror="this.style.display=\'none\'">' : 'No Image') + '</div>' +
                '<div class="product-info"><div class="product-style">' + p.style_id + '</div>' +
                '<div class="product-name">' + p.name + '</div>' +
                '<div class="color-list">' + colorHtml + '</div>' +
                '<div class="total-row"><span>Total</span><span>' + total.toLocaleString() + '</span></div></div></div>';
        }).join('');
    }

    document.getElementById('totalStyles').textContent = filtered.length;
    document.getElementById('totalUnits').textContent = filtered.reduce((s, p) => s + (p.colors || []).reduce((x, c) => x + (c.available_qty || 0), 0), 0).toLocaleString();
}

document.getElementById('searchInput').addEventListener('input', renderProducts);

function openModal(id) {
    const p = products.find(x => x.id === id);
    if (!p) return;
    const colors = p.colors || [];
    const total = colors.reduce((s, c) => s + (c.available_qty || 0), 0);
    document.getElementById('modalImage').src = p.image_url || '';
    document.getElementById('modalImage').style.display = p.image_url ? 'block' : 'none';
    document.getElementById('modalStyle').textContent = p.style_id;
    document.getElementById('modalName').textContent = p.name;
    document.getElementById('modalCategory').textContent = p.category || '';
    document.getElementById('modalColors').innerHTML = colors.map(c =>
        '<div class="color-row"><span>' + c.color_name + '</span><span>' + (c.available_qty || 0).toLocaleString() + '</span></div>'
    ).join('');
    document.getElementById('modalTotal').textContent = total.toLocaleString();
    document.getElementById('modal').classList.add('active');
}

function closeModal() { document.getElementById('modal').classList.remove('active'); }
document.getElementById('modal').addEventListener('click', (e) => { if (e.target.id === 'modal') closeModal(); });

document.getElementById('csvFile').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const formData = new FormData();
    formData.append('file', file);
    document.getElementById('importStatus').innerHTML = 'Importing...';
    const res = await fetch('/api/import', { method: 'POST', body: formData });
    const data = await res.json();
    if (data.success) {
        document.getElementById('importStatus').innerHTML = '<span class="success">Imported ' + data.imported + ' products</span>';
        loadProducts();
        loadHistory();
    } else {
        document.getElementById('importStatus').innerHTML = '<span class="error">' + data.error + '</span>';
    }
});

document.getElementById('clearBtn').addEventListener('click', async () => {
    if (!confirm('Delete all products?')) return;
    await fetch('/api/products/clear', { method: 'POST' });
    loadProducts();
});

async function loadUsers() {
    const res = await fetch('/api/users');
    const users = await res.json();
    document.getElementById('usersTable').innerHTML = users.map(u =>
        '<tr><td>' + u.username + '</td><td>' + u.role + '</td><td><button class="btn btn-danger" onclick="deleteUser(' + u.id + ')">Delete</button></td></tr>'
    ).join('');
}

document.getElementById('addUserBtn').addEventListener('click', async () => {
    const username = document.getElementById('newUser').value;
    const password = document.getElementById('newPass').value;
    const role = document.getElementById('newRole').value;
    if (!username || !password) return alert('Enter username and password');
    await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, role })
    });
    document.getElementById('newUser').value = '';
    document.getElementById('newPass').value = '';
    loadUsers();
});

async function deleteUser(id) {
    if (!confirm('Delete this user?')) return;
    await fetch('/api/users/' + id, { method: 'DELETE' });
    loadUsers();
}

async function loadHistory() {
    const res = await fetch('/api/zoho/sync-history');
    const history = await res.json();
    document.getElementById('historyTable').innerHTML = history.map(h =>
        '<tr><td>' + new Date(h.created_at).toLocaleString() + '</td><td>' + h.sync_type + '</td><td>' + h.status + '</td><td>' + (h.records_synced || '-') + '</td></tr>'
    ).join('');
}

checkSession();
</script>
</body>
</html>`);
});

initDB().then(() => {
    app.listen(PORT, () => console.log('Product Catalog running on port ' + PORT));
});
