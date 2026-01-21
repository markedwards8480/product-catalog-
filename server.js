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

// AUTH BYPASS - just pass through
function requireAuth(req, res, next) { next(); }
function requireAdmin(req, res, next) { next(); }

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

// AUTH BYPASS - always return logged in as admin
app.get('/api/session', (req, res) => {
    res.json({ loggedIn: true, username: 'admin', role: 'admin' });
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
    var result = [];
    var current = '';
    var inQuotes = false;
    for (var i = 0; i < line.length; i++) {
        var char = line[i];
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
        var content = req.file.buffer.toString('utf-8');
        var lines = content.split('\n');
        var filteredLines = [];
        for (var i = 0; i < lines.length; i++) {
            if (lines[i].trim()) filteredLines.push(lines[i]);
        }
        lines = filteredLines;
        if (lines.length < 2) return res.status(400).json({ error: 'File appears empty' });

        var headerLine = lines[0];
        if (headerLine.charCodeAt(0) === 0xFEFF) headerLine = headerLine.slice(1);
        var headersRaw = parseCSVLine(headerLine);
        var headers = [];
        for (var h = 0; h < headersRaw.length; h++) {
            headers.push(headersRaw[h].toLowerCase().replace(/[^\w\s]/g, '').trim());
        }
        console.log('CSV Headers:', headers);

        var headerMap = {};
        for (var hi = 0; hi < headers.length; hi++) { headerMap[headers[hi]] = hi; }

        var imported = 0, skipped = 0;
        var lastStyleId = null, lastImageUrl = null, lastCategory = null;

        for (var li = 1; li < lines.length; li++) {
            try {
                var values = parseCSVLine(lines[li]);
                if (values[0] && values[0].indexOf('Grand Summary') !== -1) { skipped++; continue; }

                var styleId = values[headerMap['style name']] || values[0];
                var imageUrl = values[headerMap['style image']] || values[1];
                var color = values[headerMap['color']] || values[2];
                var category = values[headerMap['commodity']] || values[3];
                var onHand = parseNumber(values[headerMap['on hand']] || values[4]);
                var allocated = parseNumber(values[headerMap['allocated on hand']] || values[5]);
                var available = parseNumber(values[headerMap['available now']] || values[headerMap['left to sell']] || values[7]);

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

                var productResult = await pool.query('SELECT id, image_url FROM products WHERE style_id = $1', [styleId]);
                var productId;

                if (productResult.rows.length > 0) {
                    productId = productResult.rows[0].id;
                    var finalImage = validImageUrl || productResult.rows[0].image_url;
                    await pool.query('UPDATE products SET name=$1, category=$2, base_style=$3, image_url=$4, updated_at=CURRENT_TIMESTAMP WHERE id=$5',
                        [name, validCategory, baseStyle, finalImage, productId]);
                } else {
                    var ins = await pool.query('INSERT INTO products (style_id, base_style, name, category, image_url) VALUES ($1,$2,$3,$4,$5) RETURNING id',
                        [styleId, baseStyle, name, validCategory, validImageUrl]);
                    productId = ins.rows[0].id;
                }

                if (color && color !== '-No Value-') {
                    var colorResult = await pool.query('SELECT id FROM product_colors WHERE product_id=$1 AND color_name=$2', [productId, color]);
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
        res.json({ success: true, imported: imported, skipped: skipped });
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
    try { var result = await pool.query('SELECT id, username, role, created_at FROM users ORDER BY created_at'); res.json(result.rows); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        var username = req.body.username;
        var password = req.body.password;
        var role = req.body.role;
        var hash = await bcrypt.hash(password, 10);
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

app.get('*', function(req, res) {
    res.send(getHTML());
});

function getHTML() {
    return '<!DOCTYPE html>\
<html lang="en">\
<head>\
<meta charset="UTF-8">\
<meta name="viewport" content="width=device-width, initial-scale=1.0">\
<title>Product Catalog</title>\
<style>\
* { margin: 0; padding: 0; box-sizing: border-box; }\
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #f5f5f5; }\
.login-page { min-height: 100vh; display: flex; align-items: center; justify-content: center; }\
.login-box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 100%; max-width: 360px; }\
.login-box h1 { margin-bottom: 1.5rem; font-size: 1.5rem; text-align: center; }\
.form-group { margin-bottom: 1rem; }\
.form-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }\
.form-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; }\
.btn { padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }\
.btn-primary { background: #2c5545; color: white; width: 100%; }\
.btn-secondary { background: #eee; color: #333; }\
.btn-danger { background: #c4553d; color: white; }\
.error { color: #c4553d; margin-top: 1rem; text-align: center; }\
.success { color: #2e7d32; }\
.hidden { display: none !important; }\
.header { background: white; padding: 1rem 2rem; border-bottom: 1px solid #ddd; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }\
.header h1 { font-size: 1.25rem; }\
.header-right { display: flex; gap: 1rem; align-items: center; }\
.search-box input { padding: 0.5rem 1rem; border: 1px solid #ddd; border-radius: 4px; width: 250px; }\
.main { max-width: 1400px; margin: 0 auto; padding: 2rem; }\
.admin-panel { background: white; padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem; }\
.admin-panel h2 { margin-bottom: 1rem; }\
.tabs { display: flex; gap: 0.5rem; margin-bottom: 1rem; }\
.tab { padding: 0.5rem 1rem; border: none; background: #eee; cursor: pointer; border-radius: 4px; }\
.tab.active { background: #2c5545; color: white; }\
.tab-content { display: none; }\
.tab-content.active { display: block; }\
.upload-area { border: 2px dashed #ddd; padding: 2rem; text-align: center; border-radius: 4px; margin-bottom: 1rem; }\
.upload-area input { display: none; }\
.upload-area label { color: #2c5545; cursor: pointer; }\
.stats { display: flex; gap: 2rem; margin-bottom: 1rem; padding: 1rem; background: white; border-radius: 8px; }\
.stat-value { font-size: 1.5rem; font-weight: bold; }\
.stat-label { color: #666; font-size: 0.875rem; }\
.filters { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }\
.filter-btn { padding: 0.5rem 1rem; border: 1px solid #ddd; background: white; border-radius: 20px; cursor: pointer; }\
.filter-btn.active { background: #2c5545; color: white; border-color: #2c5545; }\
.product-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1.5rem; }\
.product-card { background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); cursor: pointer; transition: transform 0.2s; }\
.product-card:hover { transform: translateY(-2px); box-shadow: 0 4px 16px rgba(0,0,0,0.15); }\
.product-image { height: 200px; background: #f0f0f0; display: flex; align-items: center; justify-content: center; overflow: hidden; }\
.product-image img { width: 100%; height: 100%; object-fit: cover; }\
.product-info { padding: 1rem; }\
.product-style { font-size: 0.75rem; color: #666; text-transform: uppercase; }\
.product-name { font-size: 1.1rem; font-weight: 600; margin: 0.25rem 0; }\
.color-list { margin-top: 0.75rem; }\
.color-row { display: flex; justify-content: space-between; padding: 0.25rem 0; font-size: 0.875rem; }\
.total-row { margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid #eee; font-weight: bold; display: flex; justify-content: space-between; }\
.empty { text-align: center; padding: 3rem; color: #666; }\
.modal { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: none; align-items: center; justify-content: center; z-index: 1000; }\
.modal.active { display: flex; }\
.modal-content { background: white; border-radius: 8px; max-width: 800px; width: 90%; max-height: 90vh; overflow: auto; position: relative; }\
.modal-body { display: flex; }\
.modal-image { width: 50%; background: #f0f0f0; min-height: 300px; }\
.modal-image img { width: 100%; height: 100%; object-fit: cover; }\
.modal-details { width: 50%; padding: 2rem; }\
.modal-close { position: absolute; top: 1rem; right: 1rem; background: white; border: none; font-size: 1.5rem; cursor: pointer; border-radius: 50%; width: 36px; height: 36px; }\
table { width: 100%; border-collapse: collapse; }\
th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #eee; }\
.add-form { display: flex; gap: 0.5rem; margin-top: 1rem; flex-wrap: wrap; }\
.add-form input, .add-form select { padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; }\
</style>\
</head>\
<body>\
<div id="loginPage" class="login-page">\
<div class="login-box">\
<h1>Product Catalog</h1>\
<form id="loginForm">\
<div class="form-group"><label>Username</label><input type="text" id="username" required></div>\
<div class="form-group"><label>Password</label><input type="password" id="password" required></div>\
<button type="submit" class="btn btn-primary">Sign In</button>\
<div id="loginError" class="error hidden"></div>\
</form>\
</div>\
</div>\
<div id="mainApp" class="hidden">\
<header class="header">\
<h1>Product Catalog</h1>\
<div class="search-box"><input type="text" id="searchInput" placeholder="Search products..."></div>\
<div class="header-right">\
<span id="userInfo"></span>\
<button class="btn btn-secondary" id="adminBtn" style="display:none">Admin</button>\
<button class="btn btn-secondary" id="logoutBtn">Sign Out</button>\
</div>\
</header>\
<main class="main">\
<div id="adminPanel" class="admin-panel hidden">\
<h2>Admin Panel</h2>\
<div class="tabs">\
<button class="tab active" data-tab="import">Import CSV</button>\
<button class="tab" data-tab="users">Users</button>\
<button class="tab" data-tab="history">History</button>\
</div>\
<div id="importTab" class="tab-content active">\
<div class="upload-area">\
<input type="file" id="csvFile" accept=".csv">\
<label for="csvFile">Click to upload CSV file</label>\
</div>\
<div id="importStatus"></div>\
<button class="btn btn-danger" id="clearBtn" style="margin-top:1rem">Clear All Products</button>\
</div>\
<div id="usersTab" class="tab-content">\
<table><thead><tr><th>Username</th><th>Role</th><th>Actions</th></tr></thead><tbody id="usersTable"></tbody></table>\
<div class="add-form">\
<input type="text" id="newUser" placeholder="Username">\
<input type="password" id="newPass" placeholder="Password">\
<select id="newRole"><option value="sales_rep">Sales Rep</option><option value="admin">Admin</option></select>\
<button class="btn btn-primary" id="addUserBtn">Add</button>\
</div>\
</div>\
<div id="historyTab" class="tab-content">\
<table><thead><tr><th>Date</th><th>Type</th><th>Status</th><th>Records</th></tr></thead><tbody id="historyTable"></tbody></table>\
</div>\
</div>\
<div class="stats">\
<div><div class="stat-value" id="totalStyles">0</div><div class="stat-label">Styles</div></div>\
<div><div class="stat-value" id="totalUnits">0</div><div class="stat-label">Units Available</div></div>\
</div>\
<div class="filters" id="filters"></div>\
<div class="product-grid" id="productGrid"></div>\
<div class="empty hidden" id="emptyState">No products found. Import a CSV to get started.</div>\
</main>\
</div>\
<div class="modal" id="modal">\
<div class="modal-content">\
<button class="modal-close" id="modalClose">&times;</button>\
<div class="modal-body">\
<div class="modal-image"><img id="modalImage" src="" alt=""></div>\
<div class="modal-details">\
<div class="product-style" id="modalStyle"></div>\
<h2 id="modalName"></h2>\
<p id="modalCategory" style="color:#666;margin-bottom:1rem"></p>\
<div id="modalColors"></div>\
<div class="total-row"><span>Total Available</span><span id="modalTotal"></span></div>\
</div>\
</div>\
</div>\
</div>\
<script>\
var products = [];\
var currentFilter = "all";\
function checkSession() {\
    fetch("/api/session").then(function(res) { return res.json(); }).then(function(data) {\
        if (data.loggedIn) {\
            showApp(data.username, data.role);\
            loadProducts();\
            if (data.role === "admin") { loadUsers(); loadHistory(); }\
        } else {\
            document.getElementById("loginPage").classList.remove("hidden");\
            document.getElementById("mainApp").classList.add("hidden");\
        }\
    });\
}\
function showApp(username, role) {\
    document.getElementById("loginPage").classList.add("hidden");\
    document.getElementById("mainApp").classList.remove("hidden");\
    document.getElementById("userInfo").textContent = "Welcome, " + username;\
    if (role === "admin") document.getElementById("adminBtn").style.display = "block";\
}\
document.getElementById("loginForm").addEventListener("submit", function(e) {\
    e.preventDefault();\
    var username = document.getElementById("username").value;\
    var password = document.getElementById("password").value;\
    fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: username, password: password }) })\
    .then(function(res) { return res.json(); })\
    .then(function(data) {\
        if (data.success) { showApp(data.username, data.role); loadProducts(); if (data.role === "admin") { loadUsers(); loadHistory(); } }\
        else { document.getElementById("loginError").textContent = data.error; document.getElementById("loginError").classList.remove("hidden"); }\
    });\
});\
document.getElementById("logoutBtn").addEventListener("click", function() { fetch("/api/logout", { method: "POST" }).then(function() { location.reload(); }); });\
document.getElementById("adminBtn").addEventListener("click", function() { document.getElementById("adminPanel").classList.toggle("hidden"); });\
var tabs = document.querySelectorAll(".tab");\
for (var i = 0; i < tabs.length; i++) {\
    tabs[i].addEventListener("click", function(e) {\
        var allTabs = document.querySelectorAll(".tab");\
        var allContents = document.querySelectorAll(".tab-content");\
        for (var j = 0; j < allTabs.length; j++) { allTabs[j].classList.remove("active"); }\
        for (var k = 0; k < allContents.length; k++) { allContents[k].classList.remove("active"); }\
        e.target.classList.add("active");\
        document.getElementById(e.target.getAttribute("data-tab") + "Tab").classList.add("active");\
    });\
}\
function loadProducts() {\
    fetch("/api/products").then(function(res) { return res.json(); }).then(function(data) { products = data; renderFilters(); renderProducts(); });\
}\
function renderFilters() {\
    var cats = [];\
    for (var i = 0; i < products.length; i++) { if (products[i].category && cats.indexOf(products[i].category) === -1) { cats.push(products[i].category); } }\
    cats.sort();\
    var html = "<button class=\\"filter-btn active\\" data-cat=\\"all\\">All</button>";\
    for (var j = 0; j < cats.length; j++) { html += "<button class=\\"filter-btn\\" data-cat=\\"" + cats[j] + "\\">" + cats[j] + "</button>"; }\
    document.getElementById("filters").innerHTML = html;\
    var btns = document.querySelectorAll(".filter-btn");\
    for (var k = 0; k < btns.length; k++) {\
        btns[k].addEventListener("click", function(e) {\
            var allBtns = document.querySelectorAll(".filter-btn");\
            for (var m = 0; m < allBtns.length; m++) { allBtns[m].classList.remove("active"); }\
            e.target.classList.add("active");\
            currentFilter = e.target.getAttribute("data-cat");\
            renderProducts();\
        });\
    }\
}\
function renderProducts() {\
    var search = document.getElementById("searchInput").value.toLowerCase();\
    var filtered = [];\
    for (var i = 0; i < products.length; i++) {\
        var p = products[i];\
        var matchSearch = !search || p.style_id.toLowerCase().indexOf(search) !== -1 || p.name.toLowerCase().indexOf(search) !== -1;\
        var matchCat = currentFilter === "all" || p.category === currentFilter;\
        if (matchSearch && matchCat) filtered.push(p);\
    }\
    if (filtered.length === 0) { document.getElementById("productGrid").innerHTML = ""; document.getElementById("emptyState").classList.remove("hidden"); }\
    else {\
        document.getElementById("emptyState").classList.add("hidden");\
        var html = "";\
        for (var j = 0; j < filtered.length; j++) {\
            var prod = filtered[j];\
            var colors = prod.colors || [];\
            var total = 0;\
            for (var c = 0; c < colors.length; c++) { total += colors[c].available_qty || 0; }\
            var colorHtml = "";\
            var maxColors = Math.min(colors.length, 3);\
            for (var d = 0; d < maxColors; d++) { colorHtml += "<div class=\\"color-row\\"><span>" + colors[d].color_name + "</span><span>" + (colors[d].available_qty || 0).toLocaleString() + "</span></div>"; }\
            if (colors.length > 3) { colorHtml += "<div class=\\"color-row\\" style=\\"color:#999\\">+" + (colors.length - 3) + " more</div>"; }\
            var imgHtml = prod.image_url ? "<img src=\\"" + prod.image_url + "\\" onerror=\\"this.parentElement.innerHTML=\'No Image\';\\">" : "No Image";\
            html += "<div class=\\"product-card\\" onclick=\\"openModal(" + prod.id + ")\\">" +\
                "<div class=\\"product-image\\">" + imgHtml + "</div>" +\
                "<div class=\\"product-info\\"><div class=\\"product-style\\">" + prod.style_id + "</div>" +\
                "<div class=\\"product-name\\">" + prod.name + "</div>" +\
                "<div class=\\"color-list\\">" + colorHtml + "</div>" +\
                "<div class=\\"total-row\\"><span>Total</span><span>" + total.toLocaleString() + "</span></div></div></div>";\
        }\
        document.getElementById("productGrid").innerHTML = html;\
    }\
    document.getElementById("totalStyles").textContent = filtered.length;\
    var totalUnits = 0;\
    for (var t = 0; t < filtered.length; t++) { var cols = filtered[t].colors || []; for (var u = 0; u < cols.length; u++) { totalUnits += cols[u].available_qty || 0; } }\
    document.getElementById("totalUnits").textContent = totalUnits.toLocaleString();\
}\
document.getElementById("searchInput").addEventListener("input", renderProducts);\
function openModal(id) {\
    var p = null;\
    for (var i = 0; i < products.length; i++) { if (products[i].id === id) { p = products[i]; break; } }\
    if (!p) return;\
    var colors = p.colors || [];\
    var total = 0;\
    for (var c = 0; c < colors.length; c++) { total += colors[c].available_qty || 0; }\
    var img = document.getElementById("modalImage");\
    if (p.image_url) { img.src = p.image_url; img.style.display = "block"; } else { img.style.display = "none"; }\
    document.getElementById("modalStyle").textContent = p.style_id;\
    document.getElementById("modalName").textContent = p.name;\
    document.getElementById("modalCategory").textContent = p.category || "";\
    var colorHtml = "";\
    for (var d = 0; d < colors.length; d++) { colorHtml += "<div class=\\"color-row\\"><span>" + colors[d].color_name + "</span><span>" + (colors[d].available_qty || 0).toLocaleString() + "</span></div>"; }\
    document.getElementById("modalColors").innerHTML = colorHtml;\
    document.getElementById("modalTotal").textContent = total.toLocaleString();\
    document.getElementById("modal").classList.add("active");\
}\
document.getElementById("modalClose").addEventListener("click", function() { document.getElementById("modal").classList.remove("active"); });\
document.getElementById("modal").addEventListener("click", function(e) { if (e.target.id === "modal") document.getElementById("modal").classList.remove("active"); });\
document.getElementById("csvFile").addEventListener("change", function(e) {\
    var file = e.target.files[0];\
    if (!file) return;\
    var formData = new FormData();\
    formData.append("file", file);\
    document.getElementById("importStatus").innerHTML = "Importing...";\
    fetch("/api/import", { method: "POST", body: formData }).then(function(res) { return res.json(); }).then(function(data) {\
        if (data.success) { document.getElementById("importStatus").innerHTML = "<span class=\\"success\\">Imported " + data.imported + " products</span>"; loadProducts(); loadHistory(); }\
        else { document.getElementById("importStatus").innerHTML = "<span class=\\"error\\">" + data.error + "</span>"; }\
    });\
});\
document.getElementById("clearBtn").addEventListener("click", function() { if (!confirm("Delete all products?")) return; fetch("/api/products/clear", { method: "POST" }).then(function() { loadProducts(); }); });\
function loadUsers() {\
    fetch("/api/users").then(function(res) { return res.json(); }).then(function(users) {\
        var html = "";\
        for (var i = 0; i < users.length; i++) { html += "<tr><td>" + users[i].username + "</td><td>" + users[i].role + "</td><td><button class=\\"btn btn-danger\\" onclick=\\"deleteUser(" + users[i].id + ")\\">Delete</button></td></tr>"; }\
        document.getElementById("usersTable").innerHTML = html;\
    });\
}\
document.getElementById("addUserBtn").addEventListener("click", function() {\
    var username = document.getElementById("newUser").value;\
    var password = document.getElementById("newPass").value;\
    var role = document.getElementById("newRole").value;\
    if (!username || !password) { alert("Enter username and password"); return; }\
    fetch("/api/users", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: username, password: password, role: role }) }).then(function() { document.getElementById("newUser").value = ""; document.getElementById("newPass").value = ""; loadUsers(); });\
});\
function deleteUser(id) { if (!confirm("Delete this user?")) return; fetch("/api/users/" + id, { method: "DELETE" }).then(function() { loadUsers(); }); }\
function loadHistory() {\
    fetch("/api/zoho/sync-history").then(function(res) { return res.json(); }).then(function(history) {\
        var html = "";\
        for (var i = 0; i < history.length; i++) { html += "<tr><td>" + new Date(history[i].created_at).toLocaleString() + "</td><td>" + history[i].sync_type + "</td><td>" + history[i].status + "</td><td>" + (history[i].records_synced || "-") + "</td></tr>"; }\
        document.getElementById("historyTable").innerHTML = html;\
    });\
}\
checkSession();\
</script>\
</body>\
</html>';
}

initDB().then(function() {
    app.listen(PORT, function() { console.log("Product Catalog running on port " + PORT); });
});
