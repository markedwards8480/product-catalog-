const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'catalog-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// File upload config
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Initialize database
async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'sales_rep',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                style_id VARCHAR(100) NOT NULL,
                base_style VARCHAR(100),
                name VARCHAR(255) NOT NULL,
                category VARCHAR(100),
                image_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS product_colors (
                id SERIAL PRIMARY KEY,
                product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
                color_name VARCHAR(100) NOT NULL,
                available_qty INTEGER DEFAULT 0,
                on_hand INTEGER DEFAULT 0,
                open_order INTEGER DEFAULT 0,
                to_come INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create default admin user if none exists
        const userCheck = await pool.query('SELECT COUNT(*) FROM users');
        if (parseInt(userCheck.rows[0].count) === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await pool.query(
                'INSERT INTO users (username, password, role) VALUES ($1, $2, $3)',
                ['admin', hashedPassword, 'admin']
            );
            console.log('Default admin user created (admin/admin123)');
        }

        console.log('Database initialized successfully');
    } catch (err) {
        console.error('Database initialization error:', err);
    }
}

// Auth middleware
function requireAuth(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
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
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        
        res.json({ success: true, username: user.username, role: user.role });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/session', (req, res) => {
    if (req.session && req.session.userId) {
        res.json({ 
            loggedIn: true, 
            username: req.session.username,
            role: req.session.role 
        });
    } else {
        res.json({ loggedIn: false });
    }
});

// Product routes
app.get('/api/products', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                p.id,
                p.style_id,
                p.base_style,
                p.name,
                p.category,
                p.image_url,
                json_agg(
                    json_build_object(
                        'id', pc.id,
                        'color_name', pc.color_name,
                        'available_qty', pc.available_qty,
                        'on_hand', pc.on_hand,
                        'open_order', pc.open_order,
                        'to_come', pc.to_come
                    )
                ) FILTER (WHERE pc.id IS NOT NULL) as colors
            FROM products p
            LEFT JOIN product_colors pc ON p.id = pc.product_id
            GROUP BY p.id
            ORDER BY p.category, p.name, p.style_id
        `);
        
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/products', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { style_id, base_style, name, category, image_url, colors } = req.body;
        
        const result = await pool.query(
            'INSERT INTO products (style_id, base_style, name, category, image_url) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [style_id, base_style || style_id.split('-')[0], name, category, image_url]
        );
        
        const productId = result.rows[0].id;
        
        if (colors && colors.length > 0) {
            for (const color of colors) {
                await pool.query(
                    'INSERT INTO product_colors (product_id, color_name, available_qty, on_hand, open_order, to_come) VALUES ($1, $2, $3, $4, $5, $6)',
                    [productId, color.color_name, color.available_qty || 0, color.on_hand || 0, color.open_order || 0, color.to_come || 0]
                );
            }
        }
        
        res.json({ success: true, id: productId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/products/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { style_id, base_style, name, category, image_url, colors } = req.body;
        
        await pool.query(
            'UPDATE products SET style_id = $1, base_style = $2, name = $3, category = $4, image_url = $5, updated_at = CURRENT_TIMESTAMP WHERE id = $6',
            [style_id, base_style, name, category, image_url, id]
        );
        
        // Update colors
        if (colors) {
            await pool.query('DELETE FROM product_colors WHERE product_id = $1', [id]);
            for (const color of colors) {
                await pool.query(
                    'INSERT INTO product_colors (product_id, color_name, available_qty, on_hand, open_order, to_come) VALUES ($1, $2, $3, $4, $5, $6)',
                    [id, color.color_name, color.available_qty || 0, color.on_hand || 0, color.open_order || 0, color.to_come || 0]
                );
            }
        }
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/products/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM products WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Bulk import from CSV/Zoho export
app.post('/api/import', requireAuth, requireAdmin, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const content = req.file.buffer.toString('utf-8');
        const lines = content.split('\n').filter(line => line.trim());
        
        if (lines.length < 2) {
            return res.status(400).json({ error: 'File appears empty or invalid' });
        }

        const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/"/g, ''));
        let imported = 0;
        let errors = [];

        for (let i = 1; i < lines.length; i++) {
            try {
                const values = lines[i].match(/("([^"]*)"|[^,]*)/g).map(v => v.replace(/^"|"$/g, '').trim());
                
                const row = {};
                headers.forEach((h, idx) => {
                    row[h] = values[idx] || '';
                });

                // Map common Zoho field names
                const styleId = row['style name'] || row['style_id'] || row['style'] || row['sku'];
                const name = row['name'] || row['product name'] || row['description'] || styleId;
                const category = row['commodity'] || row['category'] || row['type'] || 'Uncategorized';
                const color = row['color'] || row['colour'] || '';
                const available = parseInt(row['left to sell'] || row['available'] || row['qty'] || 0) || 0;
                const onHand = parseInt(row['on hand'] || row['onhand'] || 0) || 0;
                const openOrder = parseInt(row['open order'] || row['openorder'] || 0) || 0;
                const toCome = parseInt(row['to come'] || row['tocome'] || row['incoming'] || 0) || 0;

                if (!styleId) continue;

                const baseStyle = styleId.split('-')[0];

                // Check if product exists
                let productResult = await pool.query(
                    'SELECT id FROM products WHERE style_id = $1',
                    [styleId]
                );

                let productId;
                if (productResult.rows.length > 0) {
                    productId = productResult.rows[0].id;
                    await pool.query(
                        'UPDATE products SET name = $1, category = $2, base_style = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4',
                        [name, category, baseStyle, productId]
                    );
                } else {
                    const insertResult = await pool.query(
                        'INSERT INTO products (style_id, base_style, name, category) VALUES ($1, $2, $3, $4) RETURNING id',
                        [styleId, baseStyle, name, category]
                    );
                    productId = insertResult.rows[0].id;
                }

                // Update or insert color
                if (color) {
                    const colorResult = await pool.query(
                        'SELECT id FROM product_colors WHERE product_id = $1 AND color_name = $2',
                        [productId, color]
                    );

                    if (colorResult.rows.length > 0) {
                        await pool.query(
                            'UPDATE product_colors SET available_qty = $1, on_hand = $2, open_order = $3, to_come = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5',
                            [available, onHand, openOrder, toCome, colorResult.rows[0].id]
                        );
                    } else {
                        await pool.query(
                            'INSERT INTO product_colors (product_id, color_name, available_qty, on_hand, open_order, to_come) VALUES ($1, $2, $3, $4, $5, $6)',
                            [productId, color, available, onHand, openOrder, toCome]
                        );
                    }
                }

                imported++;
            } catch (rowErr) {
                errors.push(`Row ${i + 1}: ${rowErr.message}`);
            }
        }

        res.json({ 
            success: true, 
            imported,
            errors: errors.length > 0 ? errors.slice(0, 10) : undefined
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// User management (admin only)
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, role, created_at FROM users ORDER BY created_at');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        await pool.query(
            'INSERT INTO users (username, password, role) VALUES ($1, $2, $3)',
            [username, hashedPassword, role || 'sales_rep']
        );
        
        res.json({ success: true });
    } catch (err) {
        if (err.code === '23505') {
            res.status(400).json({ error: 'Username already exists' });
        } else {
            res.status(500).json({ error: err.message });
        }
    }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        if (req.params.id == req.session.userId) {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }
        await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Serve the frontend
app.get('*', (req, res) => {
    res.send(getHTML());
});

function getHTML() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Product Catalog | Available Inventory</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600&family=Playfair+Display:wght@500;600&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --bg-primary: #FAFAF8;
            --bg-card: #FFFFFF;
            --text-primary: #1A1A1A;
            --text-secondary: #666666;
            --text-muted: #999999;
            --border: #E8E8E6;
            --accent: #2C5545;
            --accent-light: #E8F0EC;
            --danger: #C4553D;
            --shadow: 0 2px 8px rgba(0,0,0,0.04), 0 4px 24px rgba(0,0,0,0.06);
            --shadow-hover: 0 8px 32px rgba(0,0,0,0.08), 0 16px 48px rgba(0,0,0,0.08);
        }

        body {
            font-family: 'DM Sans', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
        }

        /* Login Page */
        .login-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
            background: linear-gradient(135deg, #f5f5f3 0%, #e8e8e6 100%);
        }

        .login-box {
            background: var(--bg-card);
            padding: 3rem;
            border-radius: 16px;
            box-shadow: var(--shadow);
            width: 100%;
            max-width: 400px;
        }

        .login-logo {
            font-family: 'Playfair Display', serif;
            font-size: 1.75rem;
            font-weight: 600;
            text-align: center;
            margin-bottom: 2rem;
        }

        .login-logo span { color: var(--accent); }

        .form-group {
            margin-bottom: 1.25rem;
        }

        .form-group label {
            display: block;
            font-size: 0.875rem;
            font-weight: 500;
            margin-bottom: 0.5rem;
            color: var(--text-secondary);
        }

        .form-group input {
            width: 100%;
            padding: 0.875rem 1rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            font-family: inherit;
            font-size: 1rem;
            transition: all 0.2s ease;
        }

        .form-group input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-light);
        }

        .btn {
            padding: 0.875rem 1.5rem;
            border: none;
            border-radius: 8px;
            font-family: inherit;
            font-size: 0.9375rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn-primary {
            background: var(--accent);
            color: white;
            width: 100%;
        }

        .btn-primary:hover {
            background: #234536;
        }

        .btn-secondary {
            background: var(--bg-primary);
            color: var(--text-primary);
            border: 1px solid var(--border);
        }

        .btn-secondary:hover {
            border-color: var(--accent);
            color: var(--accent);
        }

        .btn-danger {
            background: var(--danger);
            color: white;
        }

        .error-message {
            color: var(--danger);
            font-size: 0.875rem;
            margin-top: 1rem;
            text-align: center;
        }

        /* Header */
        .header {
            background: var(--bg-card);
            border-bottom: 1px solid var(--border);
            padding: 1.25rem 2rem;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .header-inner {
            max-width: 1600px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 2rem;
        }

        .logo {
            font-family: 'Playfair Display', serif;
            font-size: 1.5rem;
            font-weight: 600;
            letter-spacing: -0.02em;
        }

        .logo span { color: var(--accent); }

        .header-right {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .user-info {
            font-size: 0.875rem;
            color: var(--text-secondary);
        }

        .user-info strong {
            color: var(--text-primary);
        }

        /* Controls */
        .controls {
            display: flex;
            align-items: center;
            gap: 1rem;
            flex: 1;
            max-width: 600px;
        }

        .search-box {
            flex: 1;
            position: relative;
        }

        .search-box input {
            width: 100%;
            padding: 0.75rem 1rem 0.75rem 2.75rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            font-family: inherit;
            font-size: 0.9375rem;
            background: var(--bg-primary);
            transition: all 0.2s ease;
        }

        .search-box input:focus {
            outline: none;
            border-color: var(--accent);
            background: var(--bg-card);
            box-shadow: 0 0 0 3px var(--accent-light);
        }

        .search-box::before {
            content: '';
            position: absolute;
            left: 1rem;
            top: 50%;
            transform: translateY(-50%);
            width: 18px;
            height: 18px;
            background: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%23999'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z'/%3E%3C/svg%3E") center/contain no-repeat;
        }

        /* Filter Pills */
        .filter-pills {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }

        .filter-pill {
            padding: 0.5rem 1rem;
            border: 1px solid var(--border);
            border-radius: 20px;
            background: var(--bg-card);
            font-family: inherit;
            font-size: 0.8125rem;
            font-weight: 500;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .filter-pill:hover {
            border-color: var(--accent);
            color: var(--accent);
        }

        .filter-pill.active {
            background: var(--accent);
            border-color: var(--accent);
            color: white;
        }

        /* Stats Bar */
        .stats-bar {
            background: var(--bg-card);
            padding: 1rem 2rem;
            border-bottom: 1px solid var(--border);
        }

        .stats-inner {
            max-width: 1600px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            gap: 2rem;
        }

        .stat {
            display: flex;
            align-items: baseline;
            gap: 0.5rem;
        }

        .stat-value {
            font-size: 1.5rem;
            font-weight: 600;
        }

        .stat-label {
            font-size: 0.875rem;
            color: var(--text-muted);
        }

        /* Main Content */
        .main {
            max-width: 1600px;
            margin: 0 auto;
            padding: 2rem;
        }

        /* Category Section */
        .category-section {
            margin-bottom: 3rem;
        }

        .category-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1.5rem;
            padding-bottom: 0.75rem;
            border-bottom: 2px solid var(--text-primary);
        }

        .category-title {
            font-family: 'Playfair Display', serif;
            font-size: 1.75rem;
            font-weight: 500;
            letter-spacing: -0.02em;
        }

        .category-count {
            font-size: 0.875rem;
            color: var(--text-muted);
        }

        /* Product Grid */
        .product-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
            gap: 1.5rem;
        }

        /* Product Card */
        .product-card {
            background: var(--bg-card);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: var(--shadow);
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .product-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-hover);
        }

        .product-image-container {
            position: relative;
            aspect-ratio: 4/3;
            background: linear-gradient(145deg, #f5f5f5 0%, #ebebeb 100%);
            overflow: hidden;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .product-image {
            width: 100%;
            height: 100%;
            object-fit: cover;
            transition: transform 0.4s ease;
        }

        .product-card:hover .product-image {
            transform: scale(1.05);
        }

        .no-image {
            color: var(--text-muted);
            font-size: 0.875rem;
        }

        .product-badge {
            position: absolute;
            top: 1rem;
            left: 1rem;
            padding: 0.375rem 0.75rem;
            background: var(--accent);
            color: white;
            font-size: 0.75rem;
            font-weight: 600;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .product-badge.low-stock {
            background: var(--danger);
        }

        .product-info {
            padding: 1.25rem;
        }

        .product-style {
            font-size: 0.8125rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 0.25rem;
        }

        .product-name {
            font-family: 'Playfair Display', serif;
            font-size: 1.25rem;
            font-weight: 500;
            margin-bottom: 1rem;
        }

        /* Color Availability */
        .color-availability {
            display: flex;
            flex-direction: column;
            gap: 0.625rem;
        }

        .color-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.5rem 0.75rem;
            background: var(--bg-primary);
            border-radius: 6px;
        }

        .color-info {
            display: flex;
            align-items: center;
            gap: 0.625rem;
        }

        .color-swatch {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            border: 2px solid rgba(0,0,0,0.08);
            flex-shrink: 0;
        }

        .color-name {
            font-size: 0.875rem;
            font-weight: 500;
        }

        .color-qty {
            font-size: 0.9375rem;
            font-weight: 600;
            color: var(--accent);
        }

        .color-qty.low { color: var(--danger); }
        .color-qty.out { color: var(--text-muted); text-decoration: line-through; }

        /* Total Row */
        .total-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding-top: 0.75rem;
            margin-top: 0.5rem;
            border-top: 1px solid var(--border);
        }

        .total-label {
            font-size: 0.8125rem;
            font-weight: 500;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .total-value {
            font-size: 1.125rem;
            font-weight: 600;
        }

        /* Admin Panel */
        .admin-panel {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow);
        }

        .admin-panel h2 {
            font-family: 'Playfair Display', serif;
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
        }

        .admin-tabs {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1rem;
        }

        .admin-tab {
            padding: 0.625rem 1.25rem;
            border: none;
            background: none;
            font-family: inherit;
            font-size: 0.9375rem;
            font-weight: 500;
            color: var(--text-secondary);
            cursor: pointer;
            border-radius: 6px;
            transition: all 0.2s ease;
        }

        .admin-tab:hover {
            background: var(--bg-primary);
            color: var(--text-primary);
        }

        .admin-tab.active {
            background: var(--accent);
            color: white;
        }

        .admin-section { display: none; }
        .admin-section.active { display: block; }

        .file-upload-area {
            border: 2px dashed var(--border);
            border-radius: 8px;
            padding: 2rem;
            text-align: center;
            transition: all 0.2s ease;
        }

        .file-upload-area:hover {
            border-color: var(--accent);
        }

        .file-upload-area input[type="file"] {
            display: none;
        }

        .file-upload-area label {
            cursor: pointer;
            color: var(--accent);
            font-weight: 500;
        }

        .user-table {
            width: 100%;
            border-collapse: collapse;
        }

        .user-table th,
        .user-table td {
            padding: 0.875rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        .user-table th {
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 0.8125rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .add-user-form {
            display: flex;
            gap: 1rem;
            margin-top: 1.5rem;
            flex-wrap: wrap;
        }

        .add-user-form input,
        .add-user-form select {
            padding: 0.75rem 1rem;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-family: inherit;
            font-size: 0.9375rem;
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 4rem 2rem;
        }

        .empty-state h3 {
            font-family: 'Playfair Display', serif;
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
        }

        .empty-state p {
            color: var(--text-muted);
        }

        /* Modal */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.6);
            backdrop-filter: blur(4px);
            z-index: 1000;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }

        .modal-overlay.active { display: flex; }

        .modal-content {
            background: var(--bg-card);
            border-radius: 16px;
            max-width: 900px;
            width: 100%;
            max-height: 90vh;
            overflow: hidden;
            display: grid;
            grid-template-columns: 1fr 1fr;
            box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25);
            position: relative;
        }

        .modal-close {
            position: absolute;
            top: 1rem;
            right: 1rem;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: var(--bg-card);
            border: none;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            color: var(--text-secondary);
            transition: all 0.2s ease;
            z-index: 10;
        }

        .modal-close:hover {
            background: var(--text-primary);
            color: white;
        }

        .modal-image {
            aspect-ratio: 1;
            background: #f5f5f5;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-image img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }

        .modal-details {
            padding: 2rem;
            display: flex;
            flex-direction: column;
        }

        .modal-style {
            font-size: 0.875rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-bottom: 0.5rem;
        }

        .modal-name {
            font-family: 'Playfair Display', serif;
            font-size: 2rem;
            font-weight: 500;
            margin-bottom: 0.5rem;
        }

        .modal-category {
            font-size: 1rem;
            color: var(--text-secondary);
            margin-bottom: 2rem;
        }

        .modal-availability-title {
            font-size: 0.8125rem;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-bottom: 1rem;
        }

        .modal-colors {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            flex: 1;
        }

        .modal-color-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.875rem 1rem;
            background: var(--bg-primary);
            border-radius: 8px;
        }

        .modal-color-info {
            display: flex;
            align-items: center;
            gap: 0.875rem;
        }

        .modal-color-swatch {
            width: 28px;
            height: 28px;
            border-radius: 50%;
            border: 2px solid rgba(0,0,0,0.1);
        }

        .modal-color-name { font-size: 1rem; font-weight: 500; }
        .modal-color-qty { font-size: 1.25rem; font-weight: 600; color: var(--accent); }

        .modal-total {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding-top: 1.5rem;
            margin-top: 1rem;
            border-top: 2px solid var(--border);
        }

        .modal-total-label { font-size: 1rem; font-weight: 500; color: var(--text-secondary); }
        .modal-total-value { font-size: 1.75rem; font-weight: 600; }

        /* Responsive */
        @media (max-width: 768px) {
            .header { padding: 1rem; }
            .header-inner { flex-direction: column; align-items: stretch; gap: 1rem; }
            .controls { max-width: none; }
            .stats-bar { padding: 0.75rem 1rem; overflow-x: auto; }
            .main { padding: 1rem; }
            .product-grid { grid-template-columns: 1fr; }
            .modal-content { grid-template-columns: 1fr; max-height: 85vh; overflow-y: auto; }
            .admin-panel { padding: 1rem; }
            .add-user-form { flex-direction: column; }
        }

        /* Animations */
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .product-card {
            animation: fadeInUp 0.4s ease forwards;
            opacity: 0;
        }

        .product-card:nth-child(1) { animation-delay: 0.05s; }
        .product-card:nth-child(2) { animation-delay: 0.1s; }
        .product-card:nth-child(3) { animation-delay: 0.15s; }
        .product-card:nth-child(4) { animation-delay: 0.2s; }
        .product-card:nth-child(5) { animation-delay: 0.25s; }
        .product-card:nth-child(6) { animation-delay: 0.3s; }

        .hidden { display: none !important; }
    </style>
</head>
<body>
    <!-- Login Page -->
    <div id="loginPage" class="login-container">
        <div class="login-box">
            <div class="login-logo">Product <span>Catalog</span></div>
            <form id="loginForm">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="loginUsername" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="loginPassword" required>
                </div>
                <button type="submit" class="btn btn-primary">Sign In</button>
                <div id="loginError" class="error-message hidden"></div>
            </form>
        </div>
    </div>

    <!-- Main App -->
    <div id="mainApp" class="hidden">
        <header class="header">
            <div class="header-inner">
                <div class="logo">Product <span>Catalog</span></div>
                <div class="controls">
                    <div class="search-box">
                        <input type="text" id="searchInput" placeholder="Search by style, color, or category...">
                    </div>
                </div>
                <div class="filter-pills" id="categoryFilters">
                    <button class="filter-pill active" data-category="all">All</button>
                </div>
                <div class="header-right">
                    <span class="user-info">Signed in as <strong id="currentUser"></strong></span>
                    <button class="btn btn-secondary" id="adminBtn" style="display:none;">Admin</button>
                    <button class="btn btn-secondary" id="logoutBtn">Sign Out</button>
                </div>
            </div>
        </header>

        <div class="stats-bar">
            <div class="stats-inner">
                <div class="stat">
                    <span class="stat-value" id="totalStyles">0</span>
                    <span class="stat-label">Styles</span>
                </div>
                <div class="stat">
                    <span class="stat-value" id="totalUnits">0</span>
                    <span class="stat-label">Units Available</span>
                </div>
                <div class="stat">
                    <span class="stat-value" id="inStockCount">0</span>
                    <span class="stat-label">In Stock</span>
                </div>
            </div>
        </div>

        <main class="main">
            <!-- Admin Panel -->
            <div id="adminPanel" class="admin-panel hidden">
                <h2>Admin Panel</h2>
                <div class="admin-tabs">
                    <button class="admin-tab active" data-tab="import">Import Data</button>
                    <button class="admin-tab" data-tab="users">Manage Users</button>
                </div>

                <div id="importSection" class="admin-section active">
                    <p style="margin-bottom: 1rem; color: var(--text-secondary);">
                        Upload a CSV export from Zoho Analytics. The file should include columns for Style Name, Color, Commodity, and Left to Sell.
                    </p>
                    <div class="file-upload-area">
                        <input type="file" id="csvUpload" accept=".csv">
                        <label for="csvUpload">Click to upload CSV file</label>
                        <p style="margin-top: 0.5rem; font-size: 0.875rem; color: var(--text-muted);">or drag and drop</p>
                    </div>
                    <div id="importStatus" style="margin-top: 1rem;"></div>
                </div>

                <div id="usersSection" class="admin-section">
                    <table class="user-table">
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
                    <div class="add-user-form">
                        <input type="text" id="newUsername" placeholder="Username">
                        <input type="password" id="newPassword" placeholder="Password">
                        <select id="newRole">
                            <option value="sales_rep">Sales Rep</option>
                            <option value="admin">Admin</option>
                        </select>
                        <button class="btn btn-primary" id="addUserBtn">Add User</button>
                    </div>
                </div>
            </div>

            <div id="productContainer"></div>
        </main>
    </div>

    <!-- Modal -->
    <div class="modal-overlay" id="modal">
        <div class="modal-content">
            <button class="modal-close" onclick="closeModal()">&times;</button>
            <div class="modal-image">
                <img id="modalImage" src="" alt="">
            </div>
            <div class="modal-details">
                <div class="modal-style" id="modalStyle"></div>
                <h2 class="modal-name" id="modalName"></h2>
                <div class="modal-category" id="modalCategory"></div>
                <div class="modal-availability-title">Availability by Color</div>
                <div class="modal-colors" id="modalColors"></div>
                <div class="modal-total">
                    <span class="modal-total-label">Total Available</span>
                    <span class="modal-total-value" id="modalTotal"></span>
                </div>
            </div>
        </div>
    </div>

    <script>
        let products = [];
        let currentCategory = 'all';
        let isAdmin = false;

        // Check session on load
        async function checkSession() {
            try {
                const res = await fetch('/api/session');
                const data = await res.json();
                
                if (data.loggedIn) {
                    showApp(data.username, data.role);
                    loadProducts();
                } else {
                    showLogin();
                }
            } catch (err) {
                showLogin();
            }
        }

        function showLogin() {
            document.getElementById('loginPage').classList.remove('hidden');
            document.getElementById('mainApp').classList.add('hidden');
        }

        function showApp(username, role) {
            document.getElementById('loginPage').classList.add('hidden');
            document.getElementById('mainApp').classList.remove('hidden');
            document.getElementById('currentUser').textContent = username;
            
            isAdmin = role === 'admin';
            document.getElementById('adminBtn').style.display = isAdmin ? 'block' : 'none';
            
            if (isAdmin) {
                loadUsers();
            }
        }

        // Login
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            
            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await res.json();
                
                if (data.success) {
                    showApp(data.username, data.role);
                    loadProducts();
                } else {
                    document.getElementById('loginError').textContent = data.error || 'Login failed';
                    document.getElementById('loginError').classList.remove('hidden');
                }
            } catch (err) {
                document.getElementById('loginError').textContent = 'Connection error';
                document.getElementById('loginError').classList.remove('hidden');
            }
        });

        // Logout
        document.getElementById('logoutBtn').addEventListener('click', async () => {
            await fetch('/api/logout', { method: 'POST' });
            showLogin();
        });

        // Admin toggle
        document.getElementById('adminBtn').addEventListener('click', () => {
            const panel = document.getElementById('adminPanel');
            panel.classList.toggle('hidden');
        });

        // Admin tabs
        document.querySelectorAll('.admin-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                document.querySelectorAll('.admin-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.admin-section').forEach(s => s.classList.remove('active'));
                
                e.target.classList.add('active');
                document.getElementById(e.target.dataset.tab + 'Section').classList.add('active');
            });
        });

        // Load products
        async function loadProducts() {
            try {
                const res = await fetch('/api/products');
                products = await res.json();
                updateCategoryFilters();
                renderProducts();
            } catch (err) {
                console.error('Error loading products:', err);
            }
        }

        // Update category filters based on actual data
        function updateCategoryFilters() {
            const categories = [...new Set(products.map(p => p.category).filter(Boolean))];
            const container = document.getElementById('categoryFilters');
            
            container.innerHTML = '<button class="filter-pill active" data-category="all">All</button>';
            categories.sort().forEach(cat => {
                container.innerHTML += '<button class="filter-pill" data-category="' + cat + '">' + cat + 's</button>';
            });
            
            // Re-attach listeners
            document.querySelectorAll('.filter-pill').forEach(pill => {
                pill.addEventListener('click', (e) => {
                    document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
                    e.target.classList.add('active');
                    currentCategory = e.target.dataset.category;
                    renderProducts();
                });
            });
        }

        // Format number
        function formatNumber(num) {
            return (num || 0).toLocaleString();
        }

        // Get color swatch style
        function getSwatchStyle(colorName) {
            const colors = {
                'black': '#1A1A1A',
                'ivory': 'linear-gradient(145deg, #FFFFF0 0%, #F5F5DC 100%)',
                'heather grey': 'linear-gradient(145deg, #9CA3AF 0%, #6B7280 100%)',
                'pink': 'linear-gradient(145deg, #F9A8D4 0%, #EC4899 100%)',
                'brown': 'linear-gradient(145deg, #A78B71 0%, #78583A 100%)',
                'navy': '#1E3A5F',
                'burgundy': '#722F37',
                'olive': '#556B2F',
                'cream': 'linear-gradient(145deg, #FFFDD0 0%, #F5E6C8 100%)',
                'charcoal': '#36454F',
                'forest': '#228B22',
                'rust': '#B7410E',
                'camel': '#C19A6B',
                'slate': '#708090',
                'white': '#FFFFFF',
                'grey': '#808080',
                'gray': '#808080',
                'red': '#DC2626',
                'blue': '#2563EB',
                'green': '#16A34A'
            };
            
            const name = (colorName || '').toLowerCase();
            return colors[name] || '#CCCCCC';
        }

        // Render products
        function renderProducts() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            
            let filtered = products.filter(product => {
                const matchesSearch = !searchTerm || 
                    (product.style_id || '').toLowerCase().includes(searchTerm) ||
                    (product.name || '').toLowerCase().includes(searchTerm) ||
                    (product.category || '').toLowerCase().includes(searchTerm) ||
                    (product.colors || []).some(c => (c.color_name || '').toLowerCase().includes(searchTerm));
                
                const matchesCategory = currentCategory === 'all' || product.category === currentCategory;
                
                return matchesSearch && matchesCategory;
            });

            // Group by category
            const byCategory = {};
            filtered.forEach(product => {
                const cat = product.category || 'Uncategorized';
                if (!byCategory[cat]) byCategory[cat] = [];
                byCategory[cat].push(product);
            });

            let html = '';
            Object.keys(byCategory).sort().forEach(category => {
                const categoryProducts = byCategory[category];
                html += '<section class="category-section">';
                html += '<div class="category-header">';
                html += '<h2 class="category-title">' + category + 's</h2>';
                html += '<span class="category-count">' + categoryProducts.length + ' style' + (categoryProducts.length !== 1 ? 's' : '') + '</span>';
                html += '</div>';
                html += '<div class="product-grid">';
                
                categoryProducts.forEach(product => {
                    const colors = product.colors || [];
                    const totalAvailable = colors.reduce((sum, c) => sum + (c.available_qty || 0), 0);
                    const isLowStock = totalAvailable < 5000 && totalAvailable > 0;
                    
                    let colorsHtml = colors.map(color => {
                        const bg = getSwatchStyle(color.color_name);
                        const qtyClass = color.available_qty === 0 ? 'out' : color.available_qty < 1000 ? 'low' : '';
                        return '<div class="color-row">' +
                            '<div class="color-info">' +
                            '<div class="color-swatch" style="background: ' + bg + '"></div>' +
                            '<span class="color-name">' + (color.color_name || 'Unknown') + '</span>' +
                            '</div>' +
                            '<span class="color-qty ' + qtyClass + '">' + formatNumber(color.available_qty) + '</span>' +
                            '</div>';
                    }).join('');

                    html += '<div class="product-card" onclick="openModal(' + product.id + ')">';
                    html += '<div class="product-image-container">';
                    if (product.image_url) {
                        html += '<img class="product-image" src="' + product.image_url + '" alt="' + product.name + '" loading="lazy">';
                    } else {
                        html += '<span class="no-image">No Image</span>';
                    }
                    if (isLowStock) html += '<span class="product-badge low-stock">Low Stock</span>';
                    html += '</div>';
                    html += '<div class="product-info">';
                    html += '<div class="product-style">' + (product.style_id || product.base_style) + '</div>';
                    html += '<h3 class="product-name">' + (product.name || 'Unnamed Product') + '</h3>';
                    html += '<div class="color-availability">' + colorsHtml + '</div>';
                    html += '<div class="total-row">';
                    html += '<span class="total-label">Total Available</span>';
                    html += '<span class="total-value">' + formatNumber(totalAvailable) + '</span>';
                    html += '</div></div></div>';
                });
                
                html += '</div></section>';
            });

            if (html === '') {
                html = '<div class="empty-state"><h3>No products found</h3><p>Try adjusting your search or filters, or import data from Zoho.</p></div>';
            }

            document.getElementById('productContainer').innerHTML = html;
            updateStats(filtered);
        }

        // Update stats
        function updateStats(filtered) {
            const totalStyles = filtered.length;
            const totalUnits = filtered.reduce((sum, p) => 
                sum + (p.colors || []).reduce((s, c) => s + (c.available_qty || 0), 0), 0);
            const inStock = filtered.filter(p => 
                (p.colors || []).some(c => c.available_qty > 0)).length;

            document.getElementById('totalStyles').textContent = totalStyles;
            document.getElementById('totalUnits').textContent = formatNumber(totalUnits);
            document.getElementById('inStockCount').textContent = inStock;
        }

        // Search
        document.getElementById('searchInput').addEventListener('input', renderProducts);

        // Modal
        function openModal(productId) {
            const product = products.find(p => p.id === productId);
            if (!product) return;

            const colors = product.colors || [];
            const totalAvailable = colors.reduce((sum, c) => sum + (c.available_qty || 0), 0);

            if (product.image_url) {
                document.getElementById('modalImage').src = product.image_url;
                document.getElementById('modalImage').style.display = 'block';
            } else {
                document.getElementById('modalImage').style.display = 'none';
            }
            
            document.getElementById('modalStyle').textContent = product.style_id || product.base_style;
            document.getElementById('modalName').textContent = product.name || 'Unnamed Product';
            document.getElementById('modalCategory').textContent = product.category || '';
            document.getElementById('modalTotal').textContent = formatNumber(totalAvailable);

            const colorsHtml = colors.map(color => {
                const bg = getSwatchStyle(color.color_name);
                return '<div class="modal-color-row">' +
                    '<div class="modal-color-info">' +
                    '<div class="modal-color-swatch" style="background: ' + bg + '"></div>' +
                    '<span class="modal-color-name">' + (color.color_name || 'Unknown') + '</span>' +
                    '</div>' +
                    '<span class="modal-color-qty">' + formatNumber(color.available_qty) + '</span>' +
                    '</div>';
            }).join('');
            document.getElementById('modalColors').innerHTML = colorsHtml;

            document.getElementById('modal').classList.add('active');
            document.body.style.overflow = 'hidden';
        }

        function closeModal() {
            document.getElementById('modal').classList.remove('active');
            document.body.style.overflow = '';
        }

        document.getElementById('modal').addEventListener('click', (e) => {
            if (e.target.id === 'modal') closeModal();
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeModal();
        });

        // CSV Upload
        document.getElementById('csvUpload').addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const formData = new FormData();
            formData.append('file', file);

            document.getElementById('importStatus').innerHTML = '<p>Importing...</p>';

            try {
                const res = await fetch('/api/import', {
                    method: 'POST',
                    body: formData
                });

                const data = await res.json();

                if (data.success) {
                    document.getElementById('importStatus').innerHTML = 
                        '<p style="color: var(--accent);">✓ Successfully imported ' + data.imported + ' products</p>';
                    loadProducts();
                } else {
                    document.getElementById('importStatus').innerHTML = 
                        '<p style="color: var(--danger);">Error: ' + data.error + '</p>';
                }
            } catch (err) {
                document.getElementById('importStatus').innerHTML = 
                    '<p style="color: var(--danger);">Upload failed: ' + err.message + '</p>';
            }
        });

        // User Management
        async function loadUsers() {
            try {
                const res = await fetch('/api/users');
                const users = await res.json();
                
                const tbody = document.getElementById('userTableBody');
                tbody.innerHTML = users.map(user => 
                    '<tr>' +
                    '<td>' + user.username + '</td>' +
                    '<td>' + user.role + '</td>' +
                    '<td>' + new Date(user.created_at).toLocaleDateString() + '</td>' +
                    '<td><button class="btn btn-danger" onclick="deleteUser(' + user.id + ')" style="padding: 0.5rem 1rem; font-size: 0.8125rem;">Delete</button></td>' +
                    '</tr>'
                ).join('');
            } catch (err) {
                console.error('Error loading users:', err);
            }
        }

        document.getElementById('addUserBtn').addEventListener('click', async () => {
            const username = document.getElementById('newUsername').value;
            const password = document.getElementById('newPassword').value;
            const role = document.getElementById('newRole').value;

            if (!username || !password) {
                alert('Please enter username and password');
                return;
            }

            try {
                const res = await fetch('/api/users', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password, role })
                });

                const data = await res.json();

                if (data.success) {
                    document.getElementById('newUsername').value = '';
                    document.getElementById('newPassword').value = '';
                    loadUsers();
                } else {
                    alert(data.error || 'Failed to add user');
                }
            } catch (err) {
                alert('Error adding user: ' + err.message);
            }
        });

        async function deleteUser(id) {
            if (!confirm('Are you sure you want to delete this user?')) return;

            try {
                const res = await fetch('/api/users/' + id, { method: 'DELETE' });
                const data = await res.json();

                if (data.success) {
                    loadUsers();
                } else {
                    alert(data.error || 'Failed to delete user');
                }
            } catch (err) {
                alert('Error deleting user: ' + err.message);
            }
        }

        // Initialize
        checkSession();
    </script>
</body>
</html>`;
}

// Start server
initDB().then(() => {
    app.listen(PORT, () => {
        console.log(\`Product Catalog running on port \${PORT}\`);
    });
});
