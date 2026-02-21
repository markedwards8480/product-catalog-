const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const cron = require('node-cron');
require('dotenv').config();

// =============================================
// ADMIN PANEL INTEGRATION
// =============================================
const ADMIN_PANEL_URL = process.env.ADMIN_PANEL_URL;
const ADMIN_PANEL_API_KEY = process.env.ADMIN_PANEL_API_KEY;
const APP_SLUG = process.env.APP_SLUG || 'grand-emotion';

// Helper: Verify user with admin panel
async function verifyWithAdminPanel(email, password) {
      try {
              const response = await fetch(`${ADMIN_PANEL_URL}/api/auth/verify`, {
                        method: 'POST',
                        headers: {
                                    'Content-Type': 'application/json',
                                    'X-API-Key': ADMIN_PANEL_API_KEY
                        },
                        body: JSON.stringify({ email, password, app_slug: APP_SLUG })
              });
              return await response.json();
      } catch (error) {
              console.error('Admin panel auth error:', error);
              return { success: false, error: 'Admin panel unavailable' };
      }
}

// Helper: Check user access
async function checkUserAccess(userId) {
      try {
              const response = await fetch(
                        `${ADMIN_PANEL_URL}/api/auth/check-access?user_id=${userId}&app_slug=${APP_SLUG}`,
                  { headers: { 'X-API-Key': ADMIN_PANEL_API_KEY } }
                      );
              return await response.json();
      } catch (error) {
              console.error('Admin panel access check error:', error);
              return { hasAccess: false };
      }
}

// Helper: Report data freshness to admin panel
async function reportDataFreshness(dataSource, recordCount, notes) {
    if (!ADMIN_PANEL_URL || !ADMIN_PANEL_API_KEY) {
        console.log('Admin panel not configured, skipping freshness report');
        return;
    }
    try {
        await fetch(`${ADMIN_PANEL_URL}/api/health/freshness`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': ADMIN_PANEL_API_KEY
            },
            body: JSON.stringify({
                data_source: dataSource,
                record_count: recordCount,
                notes: notes || null
            })
        });
        console.log('Reported freshness to admin panel:', dataSource, recordCount, 'records');
    } catch (err) {
        console.error('Failed to report data freshness:', err.message);
    }
}
// =============================================

// ============================================
// AUTHENTICATION TOGGLE
// Set to true to require PIN login
// Set to false to bypass login (dev mode)
// ============================================
const AUTH_ENABLED = false;
// ============================================

// ============================================
// SUPPLY VS DEMAND FEATURE TOGGLE
// Set to true to enable Supply vs Demand view
// Set to false to disable this feature
// ============================================
const SUPPLY_DEMAND_FEATURE_ENABLED = false;
// ============================================

// Image cache directory (Railway Volume mount point)
const IMAGE_CACHE_DIR = process.env.IMAGE_CACHE_DIR || '/cache';

// Ensure cache directory exists
try {
    if (!fs.existsSync(IMAGE_CACHE_DIR)) {
        fs.mkdirSync(IMAGE_CACHE_DIR, { recursive: true });
        console.log('Created image cache directory:', IMAGE_CACHE_DIR);
    }
} catch (err) {
    console.log('Note: Image cache directory not available, will use direct Zoho API calls');
}

const app = express();

// --- Origin Protection ---
const ORIGIN_SECRET = process.env.ORIGIN_SECRET;
if (ORIGIN_SECRET) {
  app.use((req, res, next) => {
    if (req.headers['x-origin-secret'] === ORIGIN_SECRET) {
      return next();
    }
    res.status(403).json({ error: 'Direct access not allowed' });
  });
}
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
        await pool.query('CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255), pin VARCHAR(4), display_name VARCHAR(255), role VARCHAR(50) DEFAULT \'sales_rep\', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, style_id VARCHAR(100) NOT NULL, base_style VARCHAR(100), name VARCHAR(255) NOT NULL, category VARCHAR(100), image_url TEXT, first_seen_import INTEGER, ai_tags TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS product_colors (id SERIAL PRIMARY KEY, product_id INTEGER REFERENCES products(id) ON DELETE CASCADE, color_name VARCHAR(100) NOT NULL, available_qty INTEGER DEFAULT 0, on_hand INTEGER DEFAULT 0, open_order INTEGER DEFAULT 0, to_come INTEGER DEFAULT 0, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS sync_history (id SERIAL PRIMARY KEY, sync_type VARCHAR(50), status VARCHAR(50), records_synced INTEGER DEFAULT 0, error_message TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS zoho_tokens (id SERIAL PRIMARY KEY, access_token TEXT, refresh_token TEXT, expires_at TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS selections (id SERIAL PRIMARY KEY, share_id VARCHAR(50) UNIQUE NOT NULL, name VARCHAR(255), product_ids INTEGER[], created_by VARCHAR(255), share_type VARCHAR(50) DEFAULT \'link\', options TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        // Add options column if it doesn't exist (for existing databases)
        await pool.query('ALTER TABLE selections ADD COLUMN IF NOT EXISTS options TEXT');
        await pool.query('CREATE TABLE IF NOT EXISTS user_picks (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, product_id INTEGER REFERENCES products(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, product_id))');
        await pool.query('CREATE TABLE IF NOT EXISTS user_notes (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, product_id INTEGER REFERENCES products(id) ON DELETE CASCADE, note TEXT, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, product_id))');
        // Add base_style column for storing notes by style instead of individual product
        await pool.query('ALTER TABLE user_notes ADD COLUMN IF NOT EXISTS base_style VARCHAR(100)');
        // Make product_id and user_id nullable since we're using base_style now
        await pool.query('ALTER TABLE user_notes ALTER COLUMN product_id DROP NOT NULL');
        await pool.query('ALTER TABLE user_notes ALTER COLUMN user_id DROP NOT NULL');
        // Create index for faster lookups by base_style
        await pool.query('CREATE INDEX IF NOT EXISTS idx_user_notes_base_style ON user_notes(base_style)');
        await pool.query('CREATE TABLE IF NOT EXISTS sales_history_cache (id SERIAL PRIMARY KEY, base_style VARCHAR(100) UNIQUE NOT NULL, summary JSONB, history JSONB, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        await pool.query('CREATE TABLE IF NOT EXISTS sales_data (id SERIAL PRIMARY KEY, document_type VARCHAR(50), document_number VARCHAR(100), doc_date DATE, in_warehouse_date DATE, customer_vendor VARCHAR(255), line_item_sku VARCHAR(255), base_style VARCHAR(100), status VARCHAR(50), quantity DECIMAL(12,2), amount DECIMAL(12,2), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        // Add in_warehouse_date column if it doesn't exist (for existing databases)
        await pool.query('ALTER TABLE sales_data ADD COLUMN IF NOT EXISTS in_warehouse_date DATE');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_sales_data_base_style ON sales_data(base_style)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_sales_data_document_type ON sales_data(document_type)');
        // Clean up duplicates before creating unique index (handle NULLs properly)
        try {
            // First drop the index if it exists (in case it's corrupted or partial)
            await pool.query('DROP INDEX IF EXISTS idx_sales_data_unique');
            // Delete duplicate rows, keeping only the one with the highest id
            // Use COALESCE to handle NULL values in the comparison
            await pool.query(`DELETE FROM sales_data a USING sales_data b
                WHERE a.id < b.id
                AND a.document_number = b.document_number
                AND COALESCE(a.line_item_sku, '') = COALESCE(b.line_item_sku, '')`);
            console.log('Cleaned up duplicate sales_data rows');
        } catch (e) { console.log('No duplicates to clean or table empty:', e.message); }
        // Unique constraint for upsert functionality (use COALESCE for NULL-safe uniqueness)
        try {
            await pool.query('CREATE UNIQUE INDEX idx_sales_data_unique ON sales_data(document_number, COALESCE(line_item_sku, \'\'))');
        } catch (e) { console.log('Unique index may already exist or duplicates remain:', e.message); }
        
        // Add columns if they don't exist (for existing databases)
        try { await pool.query('ALTER TABLE selections ADD COLUMN IF NOT EXISTS share_type VARCHAR(50) DEFAULT \'link\''); } catch (e) {}
        try { await pool.query('ALTER TABLE selections ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP'); } catch (e) {}
        try { await pool.query('UPDATE selections SET expires_at = created_at + INTERVAL \'60 days\' WHERE expires_at IS NULL'); } catch (e) {}
        try { await pool.query('ALTER TABLE products ADD COLUMN IF NOT EXISTS first_seen_import INTEGER'); } catch (e) {}
        try { await pool.query('ALTER TABLE products ADD COLUMN IF NOT EXISTS ai_tags TEXT'); } catch (e) {}
        try { await pool.query('ALTER TABLE product_colors ADD COLUMN IF NOT EXISTS left_to_sell INTEGER DEFAULT 0'); } catch (e) {}
        try { await pool.query('ALTER TABLE product_colors ADD COLUMN IF NOT EXISTS available_now INTEGER DEFAULT 0'); } catch (e) {}
        try { await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS pin VARCHAR(4)'); } catch (e) {}
        try { await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(255)'); } catch (e) {}
        
        // WorkDrive auto-import tracking
        await pool.query('CREATE TABLE IF NOT EXISTS workdrive_imports (id SERIAL PRIMARY KEY, file_id VARCHAR(255) UNIQUE NOT NULL, file_name VARCHAR(255), file_type VARCHAR(50), processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, records_imported INTEGER DEFAULT 0, status VARCHAR(50), error_message TEXT)');

        // Export job tracking for Zoho Flow webhook integration
        await pool.query('CREATE TABLE IF NOT EXISTS export_jobs (id SERIAL PRIMARY KEY, job_id VARCHAR(100) UNIQUE NOT NULL, export_type VARCHAR(50), status VARCHAR(50) DEFAULT \'pending\', file_name VARCHAR(255), file_id VARCHAR(255), error_message TEXT, triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, completed_at TIMESTAMP)');

        // Catalog sharing recipients and schedules
        await pool.query('CREATE TABLE IF NOT EXISTS catalog_subscriptions (id SERIAL PRIMARY KEY, recipient_name VARCHAR(255) NOT NULL, recipient_email VARCHAR(255) NOT NULL, company VARCHAR(255), categories TEXT[], frequency VARCHAR(50) DEFAULT \'weekly\', send_days TEXT[] DEFAULT \'{monday}\', send_time VARCHAR(10) DEFAULT \'08:00\', quantity_mode VARCHAR(50) DEFAULT \'available_now\', min_quantity INTEGER DEFAULT 0, show_pricing BOOLEAN DEFAULT true, show_images BOOLEAN DEFAULT true, custom_message TEXT, is_active BOOLEAN DEFAULT true, created_by VARCHAR(255), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        // Migrate send_day to send_days array if old column exists
        try { await pool.query('ALTER TABLE catalog_subscriptions ADD COLUMN IF NOT EXISTS send_days TEXT[] DEFAULT \'{monday}\''); } catch(e) {}
        try { await pool.query('UPDATE catalog_subscriptions SET send_days = ARRAY[send_day] WHERE send_days IS NULL AND send_day IS NOT NULL'); } catch(e) {}

        // Log of every catalog email sent
        await pool.query('CREATE TABLE IF NOT EXISTS catalog_send_log (id SERIAL PRIMARY KEY, subscription_id INTEGER REFERENCES catalog_subscriptions(id) ON DELETE SET NULL, recipient_email VARCHAR(255) NOT NULL, recipient_name VARCHAR(255), company VARCHAR(255), categories TEXT[], share_url TEXT, status VARCHAR(50) DEFAULT \'sent\', opened_at TIMESTAMP, clicked_at TIMESTAMP, error_message TEXT, sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');


        // Order Requests
        await pool.query(`CREATE TABLE IF NOT EXISTS order_requests (
            id SERIAL PRIMARY KEY,
            request_number VARCHAR(20) UNIQUE NOT NULL,
            detail_id VARCHAR(50) UNIQUE NOT NULL,
            user_id INTEGER,
            user_name VARCHAR(255),
            customer_name VARCHAR(255) NOT NULL,
            product_ids TEXT NOT NULL,
            product_count INTEGER DEFAULT 0,
            cancel_date DATE,
            notes TEXT,
            status VARCHAR(50) DEFAULT 'pending',
            zoho_so_number VARCHAR(100),
            admin_notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        try { await pool.query('CREATE INDEX IF NOT EXISTS idx_order_requests_status ON order_requests(status)'); } catch(e) {}
        try { await pool.query('CREATE INDEX IF NOT EXISTS idx_order_requests_detail_id ON order_requests(detail_id)'); } catch(e) {}
        // Migrate order_requests: add columns that may be missing from earlier version
        try { await pool.query('ALTER TABLE order_requests ADD COLUMN IF NOT EXISTS detail_id VARCHAR(50)'); } catch(e) {}
        try { await pool.query('ALTER TABLE order_requests ADD COLUMN IF NOT EXISTS product_ids TEXT'); } catch(e) {}
        try { await pool.query('ALTER TABLE order_requests ADD COLUMN IF NOT EXISTS product_count INTEGER DEFAULT 0'); } catch(e) {}
        try { await pool.query('ALTER TABLE order_requests ADD COLUMN IF NOT EXISTS style_ids TEXT'); } catch(e) {}
        try { await pool.query('ALTER TABLE order_requests ADD COLUMN IF NOT EXISTS cancel_date DATE'); } catch(e) {}
        try { await pool.query("UPDATE order_requests SET detail_id = 'ord_' || substr(md5(random()::text), 1, 12) WHERE detail_id IS NULL"); } catch(e) {}
        try { await pool.query('ALTER TABLE order_requests ALTER COLUMN size_breakdown DROP NOT NULL'); } catch(e) {}
        try { await pool.query("ALTER TABLE order_requests ALTER COLUMN size_breakdown SET DEFAULT ''"); } catch(e) {}

        // Data freshness detail table - tracks when each data type was last updated
        await pool.query('CREATE TABLE IF NOT EXISTS data_freshness_detail (id SERIAL PRIMARY KEY, data_type VARCHAR(100) UNIQUE NOT NULL, last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP, record_count INTEGER DEFAULT 0, file_name VARCHAR(255), has_sizes BOOLEAN DEFAULT false)');

        // Product sizes table - stores per-size inventory breakdown
        await pool.query('CREATE TABLE IF NOT EXISTS product_sizes (id SERIAL PRIMARY KEY, style_id VARCHAR(100) NOT NULL, color_name VARCHAR(100) NOT NULL, size VARCHAR(20) NOT NULL, size_rank INTEGER DEFAULT 0, available_now INTEGER DEFAULT 0, left_to_sell INTEGER DEFAULT 0, on_hand INTEGER DEFAULT 0, to_come INTEGER DEFAULT 0, open_order INTEGER DEFAULT 0, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
        try { await pool.query('CREATE INDEX IF NOT EXISTS idx_product_sizes_style ON product_sizes(style_id)'); } catch(e) {}
        try { await pool.query('CREATE INDEX IF NOT EXISTS idx_product_sizes_style_color ON product_sizes(style_id, color_name)'); } catch(e) {}
        try { await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_product_sizes_unique ON product_sizes(style_id, color_name, size)'); } catch(e) {}

        // Migrate existing users: set PIN if not set, set display_name from username
        await pool.query("UPDATE users SET pin = LPAD(FLOOR(RANDOM() * 10000)::TEXT, 4, '0') WHERE pin IS NULL");
        await pool.query("UPDATE users SET display_name = username WHERE display_name IS NULL");
        
        var userCheck = await pool.query('SELECT COUNT(*) FROM users');
        if (parseInt(userCheck.rows[0].count) === 0) {
            await pool.query('INSERT INTO users (username, display_name, pin, role) VALUES ($1, $2, $3, $4)', ['admin', 'Admin', '1234', 'admin']);
            console.log('Default admin user created (Admin / PIN: 1234)');
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
        const { email, password } = req.body;

        // NEW: Admin panel authentication (email/password)
        if (email && password) {
                  const authResult = await verifyWithAdminPanel(email, password);

                  if (!authResult.success) {
                              return res.status(401).json({
                                            error: authResult.error || 'Invalid credentials or no access to this app'
                              });
                  }

                  req.session.userId = authResult.user.id;
                  req.session.username = authResult.user.email;
                  req.session.displayName = authResult.user.name;
                  req.session.role = authResult.user.is_admin ? 'admin' : 'sales';
                  req.session.adminPanelUser = true;

                  return res.json({
                              success: true,
                              username: authResult.user.email,
                              displayName: authResult.user.name,
                              role: authResult.user.is_admin ? 'admin' : 'sales'
                  });
        }

        // LEGACY: PIN-based login (existing code below)
    try {
        var userId = req.body.userId;
        var pin = req.body.pin;
        var result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'User not found' });
        var user = result.rows[0];
        if (user.pin !== pin && pin !== '') {
            // PIN check disabled for now - allow login with any PIN or empty
            // return res.status(401).json({ error: 'Invalid PIN' });
        }
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.displayName = user.display_name;
        req.session.role = user.role;
        res.json({ success: true, username: user.username, displayName: user.display_name, role: user.role });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Get all users for login dropdown (public - no auth required)
app.get('/api/users/list', async function(req, res) {
    try {
        var result = await pool.query('SELECT id, display_name FROM users ORDER BY display_name');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Change own PIN
app.post('/api/change-pin', async function(req, res) {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
        var currentPin = req.body.currentPin;
        var newPin = req.body.newPin;
        if (!newPin || newPin.length !== 4 || !/^\d{4}$/.test(newPin)) {
            return res.status(400).json({ error: 'PIN must be 4 digits' });
        }
        var result = await pool.query('SELECT pin FROM users WHERE id = $1', [req.session.userId]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        if (result.rows[0].pin !== currentPin) return res.status(401).json({ error: 'Current PIN is incorrect' });
        await pool.query('UPDATE users SET pin = $1 WHERE id = $2', [newPin, req.session.userId]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/logout', function(req, res) { req.session.destroy(); res.json({ success: true }); });

app.get('/api/session', function(req, res) {
    if (!AUTH_ENABLED) {
        // Auth disabled - auto-login as admin
        res.json({ loggedIn: true, username: 'admin', displayName: 'Admin', role: 'admin', userId: 1 });
    } else {
        res.json({ loggedIn: !!req.session.userId, username: req.session.username || '', displayName: req.session.displayName || '', role: req.session.role || '', userId: req.session.userId || null });
    }
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

// Product sizes API - get size breakdown for a style+color or entire style
app.get('/api/sizes/:styleId', requireAuth, async function(req, res) {
    try {
        var styleId = req.params.styleId;
        var color = req.query.color;
        var isBaseStyle = styleId.indexOf('-') === -1;
        var result;
        if (color) {
            result = await pool.query('SELECT size, size_rank, available_now, left_to_sell, on_hand, to_come, open_order FROM product_sizes WHERE style_id = $1 AND LOWER(TRIM(color_name)) = LOWER($2) ORDER BY size_rank', [styleId, color.trim()]);
        } else if (isBaseStyle) {
            result = await pool.query('SELECT style_id, color_name, size, size_rank, available_now, left_to_sell, on_hand, to_come, open_order FROM product_sizes WHERE style_id LIKE $1 ORDER BY color_name, size_rank', [styleId + '-%']);
        } else {
            result = await pool.query('SELECT color_name, size, size_rank, available_now, left_to_sell, on_hand, to_come, open_order FROM product_sizes WHERE style_id = $1 ORDER BY color_name, size_rank', [styleId]);
        }
        res.json({ sizes: result.rows });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/size-grid.js', function(req, res) {
    res.type('application/javascript').send(`
function loadSizeGrid(styleId) {
    var container = document.getElementById("sizeGridContainer");
    if (!container) return;
    container.innerHTML = '<div style="color:#999;font-size:0.8rem;padding:0.5rem 0">Loading sizes...</div>';
    fetch("/api/sizes/" + encodeURIComponent(styleId))
    .then(function(r) { return r.json(); })
    .then(function(d) {
        var sizes = d.sizes || [];
        if (sizes.length === 0) { container.innerHTML = ""; return; }
        window._sizeData = sizes;
        window._sizeIsLts = true;
        renderSizeGrid(true);
    })
    .catch(function(err) { container.innerHTML = ""; });
}

function renderSizeGrid(isLts) {
    var container = document.getElementById("sizeGridContainer");
    var sizes = window._sizeData;
    if (!container || !sizes || !sizes.length) return;

    var byColor = {};
    sizes.forEach(function(s) {
        var cn = s.color_name || "—";
        if (!byColor[cn]) byColor[cn] = [];
        byColor[cn].push(s);
    });

    var allSizes = [];
    var sizeOrder = {};
    sizes.forEach(function(s) {
        if (sizeOrder[s.size] === undefined) { sizeOrder[s.size] = s.size_rank; allSizes.push(s.size); }
    });
    allSizes.sort(function(a, b) { return sizeOrder[a] - sizeOrder[b]; });

    var colors = Object.keys(byColor);
    var h = '<div style="margin-top:0.5rem;border-top:1px solid #e0e0e0;padding-top:0.75rem">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem">';
    h += '<span style="font-size:0.8rem;font-weight:600;color:#1e3a5f">Size Breakdown</span>';
    h += '<div style="display:flex;gap:0.25rem">';
    h += '<button onclick="renderSizeGrid(false)" style="font-size:0.7rem;padding:0.2rem 0.5rem;border:1px solid #ccc;border-radius:3px;cursor:pointer;background:' + (isLts ? '#fff' : '#0088c2') + ';color:' + (isLts ? '#666' : '#fff') + '">Avail Now</button>';
    h += '<button onclick="renderSizeGrid(true)" style="font-size:0.7rem;padding:0.2rem 0.5rem;border:1px solid #ccc;border-radius:3px;cursor:pointer;background:' + (isLts ? '#0088c2' : '#fff') + ';color:' + (isLts ? '#fff' : '#666') + '">Left to Sell</button>';
    h += '</div></div>';

    h += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:0.75rem;white-space:nowrap">';
    h += '<thead><tr style="border-bottom:2px solid #ddd"><th style="text-align:left;padding:0.3rem 0.5rem;font-weight:600;color:#666;position:sticky;left:0;background:#fff">Color</th>';
    allSizes.forEach(function(sz) { h += '<th style="text-align:center;padding:0.3rem 0.4rem;font-weight:600;color:#1e3a5f;min-width:36px">' + sz + '</th>'; });
    h += '<th style="text-align:center;padding:0.3rem 0.5rem;font-weight:700;color:#1e3a5f;border-left:2px solid #ddd">Total</th></tr></thead><tbody>';

    colors.forEach(function(cn, ci) {
        var sizeMap = {}; var rowTotal = 0;
        byColor[cn].forEach(function(s) { sizeMap[s.size] = s; var v = isLts ? (s.left_to_sell || 0) : (s.available_now || 0); rowTotal += v; });
        var bg = ci % 2 === 1 ? '#f8f9fa' : '#fff';
        h += '<tr style="border-bottom:1px solid #f0f0f0;background:' + bg + '"><td style="padding:0.3rem 0.5rem;font-weight:500;color:#333;position:sticky;left:0;background:' + bg + '">' + (colors.length === 1 ? '' : cn) + '</td>';
        allSizes.forEach(function(sz) {
            var s = sizeMap[sz]; var v = s ? (isLts ? (s.left_to_sell || 0) : (s.available_now || 0)) : 0;
            h += '<td style="text-align:center;padding:0.3rem 0.4rem;color:' + (v === 0 ? '#ccc' : '#333') + '">' + (v === 0 ? '\u2014' : v.toLocaleString()) + '</td>';
        });
        h += '<td style="text-align:center;padding:0.3rem 0.5rem;font-weight:700;border-left:2px solid #ddd">' + (rowTotal === 0 ? '\u2014' : rowTotal.toLocaleString()) + '</td></tr>';
    });

    if (colors.length > 1) {
        h += '<tr style="border-top:2px solid #ddd;font-weight:700"><td style="padding:0.3rem 0.5rem;position:sticky;left:0;background:#fff">Total</td>';
        var grand = 0;
        allSizes.forEach(function(sz) {
            var col = 0;
            colors.forEach(function(cn) { var m = {}; byColor[cn].forEach(function(s) { m[s.size] = s; }); var s = m[sz]; if (s) col += isLts ? (s.left_to_sell || 0) : (s.available_now || 0); });
            grand += col;
            h += '<td style="text-align:center;padding:0.3rem 0.4rem">' + (col === 0 ? '\u2014' : col.toLocaleString()) + '</td>';
        });
        h += '<td style="text-align:center;padding:0.3rem 0.5rem;border-left:2px solid #ddd">' + grand.toLocaleString() + '</td></tr>';
    }
    h += '</tbody></table></div></div>';
    container.innerHTML = h;
}
`);
});

app.get('/api/sizes-stats', requireAuth, async function(req, res) {
    try {
        var totalRows = await pool.query('SELECT COUNT(*) FROM product_sizes');
        var uniqueStyles = await pool.query('SELECT COUNT(DISTINCT style_id) FROM product_sizes');
        var uniqueSizes = await pool.query('SELECT COUNT(DISTINCT size) FROM product_sizes');
        res.json({
            total_size_rows: parseInt(totalRows.rows[0].count),
            styles_with_sizes: parseInt(uniqueStyles.rows[0].count),
            unique_sizes: parseInt(uniqueSizes.rows[0].count)
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
        console.log('GET /api/notes - Fetching all communal notes by base_style');
        // Notes are stored by base_style, not product_id
        var result = await pool.query('SELECT base_style, note FROM user_notes WHERE base_style IS NOT NULL');
        var notes = {};
        result.rows.forEach(function(r) { 
            if (r.base_style) {
                notes[r.base_style] = r.note; 
            }
        });
        console.log('Returning', Object.keys(notes).length, 'notes');
        res.json(notes);
    } catch (err) { 
        console.error('Error fetching notes:', err);
        res.status(500).json({ error: err.message }); 
    }
});

app.post('/api/notes/:baseStyle', requireAuth, async function(req, res) {
    try {
        console.log('POST /api/notes/:baseStyle - Saving note');
        var baseStyle = req.params.baseStyle;
        var note = req.body.note || '';
        console.log('Base Style:', baseStyle, 'Note length:', note.length, 'chars');
        
        if (note.trim() === '') {
            console.log('Deleting note for style', baseStyle);
            await pool.query('DELETE FROM user_notes WHERE base_style = $1', [baseStyle]);
        } else {
            console.log('Saving note for style', baseStyle);
            // Check if a note exists for this base_style
            var existing = await pool.query('SELECT id FROM user_notes WHERE base_style = $1', [baseStyle]);
            if (existing.rows.length > 0) {
                // Update existing note
                await pool.query('UPDATE user_notes SET note = $1, updated_at = NOW() WHERE base_style = $2', [note, baseStyle]);
            } else {
                // Insert new note - only base_style and note (user_id and product_id will be NULL)
                await pool.query('INSERT INTO user_notes (base_style, note, updated_at) VALUES ($1, $2, NOW())', [baseStyle, note]);
            }
        }
        console.log('Note save SUCCESS');
        res.json({ success: true });
    } catch (err) { 
        console.error('Error saving note:', err);
        res.status(500).json({ success: false, error: err.message }); 
    }
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

// WorkDrive Auto-Import Configuration
var WORKDRIVE_INVENTORY_FOLDER_ID = process.env.WORKDRIVE_INVENTORY_FOLDER_ID || '3coje5ffa47c2f53543d9814479ee005e317b';
var WORKDRIVE_SALES_FOLDER_ID = process.env.WORKDRIVE_SALES_FOLDER_ID || '3coje6ebe1a58ee344469bbe84d67e5395f53';
var WORKDRIVE_CHECK_INTERVAL = parseInt(process.env.WORKDRIVE_CHECK_INTERVAL) || 6 * 60 * 60 * 1000; // 6 hours default

// List files in WorkDrive folder
async function listWorkDriveFiles(folderId) {
    try {
        if (!zohoAccessToken) await refreshZohoToken();
        var url = 'https://www.zohoapis.com/workdrive/api/v1/files/' + folderId + '/files';
        var response = await fetch(url, {
            headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken }
        });
        if (!response.ok) {
            console.error('WorkDrive API error:', response.status);
            return [];
        }
        var data = await response.json();
        return data.data || [];
    } catch (err) {
        console.error('Error listing WorkDrive files:', err);
        return [];
    }
}

// Download file from WorkDrive
async function downloadWorkDriveFile(fileId) {
    try {
        if (!zohoAccessToken) await refreshZohoToken();
        var url = 'https://workdrive.zoho.com/api/v1/download/' + fileId;
        var response = await fetch(url, {
            headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken }
        });
        if (!response.ok) {
            console.error('WorkDrive download error:', response.status);
            return null;
        }
        return Buffer.from(await response.arrayBuffer());
    } catch (err) {
        console.error('Error downloading WorkDrive file:', err);
        return null;
    }
}

// Determine file type from filename
function detectImportFileType(filename) {
    var lower = filename.toLowerCase();
    if (lower.indexOf('inventory') !== -1 || lower.indexOf('availability') !== -1) {
        return 'inventory';
    } else if (lower.indexOf('po-so') !== -1 || lower.indexOf('sales') !== -1 || lower.indexOf('order') !== -1) {
        return 'sales';
    }
    return 'unknown';
}

// Process inventory CSV (supports both two-file mode and legacy combined mode)
async function processInventoryCSV(csvContent, filename) {
    var lines = csvContent.split('\n');
    if (lines.length < 2) return { success: false, error: 'Empty file', imported: 0 };

    // Detect file type from filename
    var lowerFilename = filename.toLowerCase();
    var isAvailableNowFile = lowerFilename.indexOf('available now') !== -1 || lowerFilename.indexOf('available_now') !== -1;
    var isLeftToSellFile = lowerFilename.indexOf('left to sell') !== -1 || lowerFilename.indexOf('left_to_sell') !== -1;
    var fileType = isAvailableNowFile ? 'available_now' : (isLeftToSellFile ? 'left_to_sell' : 'combined');
    var isTwoFileMode = isAvailableNowFile || isLeftToSellFile;
    console.log('Processing inventory file as type:', fileType, '- filename:', filename);

    // Extract date from filename (e.g., "2026-01-30" from "Inventory Availability Report (Available Now) 2026-01-30.csv")
    var dateMatch = filename.match(/(\d{4}-\d{2}-\d{2})/);
    var fileDate = dateMatch ? dateMatch[1] : null;
    console.log('Extracted file date:', fileDate);

    var headers = lines[0].toLowerCase().replace(/['"]/g, '').replace(/^\ufeff/, '').split(',').map(function(h) { return h.trim(); });
    var headerMap = {};
    headers.forEach(function(h, i) { headerMap[h] = i; });

    // Detect if this is a "Sizes Included" file
    var hasSizes = headerMap["size"] !== undefined && headerMap["__size_rank"] !== undefined;
    console.log("File has sizes:", hasSizes);

    var syncResult = await pool.query('INSERT INTO sync_history (sync_type, status) VALUES ($1, $2) RETURNING id', ['csv_import', 'in_progress']);
    var currentImportId = syncResult.rows[0].id;

    // Determine if we need to do a full delete based on FILE TYPE (not partner detection)
    // Left to Sell = ALWAYS delete first (it's the primary data source)
    // Available Now = NEVER delete (it updates existing records)
    // Combined = ALWAYS delete (legacy mode)
    var shouldDelete = false;
    var existingStyleSet = {};

    if (fileType === 'left_to_sell') {
        // Left to Sell is the primary file - always start fresh
        shouldDelete = true;
        console.log('Left to Sell file: Clearing all existing data for fresh import');
    } else if (fileType === 'available_now') {
        // Available Now updates existing records - never delete
        shouldDelete = false;
        console.log('Available Now file: Updating existing records (no delete)');
        console.log('Total lines to process:', lines.length - 1);
    } else {
        // Legacy combined file: always do full replace
        shouldDelete = true;
        console.log('Combined file: Clearing all existing data for fresh import');
    }

    if (shouldDelete) {
        console.log('Clearing all existing products and colors...');
        // Only delete product_sizes if the incoming file has size columns
        // This prevents wiping size data when a non-size file comes in
        if (hasSizes) {
            await pool.query('DELETE FROM product_sizes');
            console.log('Size data cleared (incoming file has size columns).');
        } else {
            console.log('PRESERVING existing size data (incoming file has NO size columns).');
        }
        await pool.query('DELETE FROM product_colors');
        await pool.query('DELETE FROM products');
        console.log('Existing data cleared. Importing fresh inventory...');
    } else {
        // Load existing styles for upsert
        var existingStylesResult = await pool.query('SELECT style_id FROM products');
        existingStylesResult.rows.forEach(function(r) { existingStyleSet[r.style_id] = true; });
    }

    var imported = 0, skipped = 0, newArrivals = 0;
    var lastStyleId = '', lastImageUrl = '', lastCategory = '', lastColor = '';
    var sizeAccum = [];
    var accumStyleId = '', accumColor = '', accumImageUrl = '', accumCategory = '';
    var sizeBatchValues = [], sizeBatchParams = [], sizeBatchCount = 0;

    async function flushSizeAccum() {
        if (sizeAccum.length === 0 || !accumStyleId || !accumColor) return;
        var totalOnHand = 0, totalAvailableNow = 0, totalLeftToSell = 0, totalToCome = 0, totalOpenOrder = 0;
        for (var s = 0; s < sizeAccum.length; s++) {
            totalOnHand += sizeAccum[s].onHand; totalAvailableNow += sizeAccum[s].availableNow;
            totalLeftToSell += sizeAccum[s].leftToSell; totalToCome += sizeAccum[s].toCome; totalOpenOrder += sizeAccum[s].openOrder;
        }
        var baseStyle = accumStyleId.split('-')[0];
        var validCategory = (accumCategory && accumCategory !== '-No Value-') ? accumCategory : 'Uncategorized';
        var name = validCategory + ' - ' + baseStyle;
        var validImageUrl = (accumImageUrl && accumImageUrl !== '-No Value-' && accumImageUrl.indexOf('http') === 0) ? accumImageUrl : lastImageUrl;
        var productId;
        if (shouldDelete) {
            if (existingStyleSet[accumStyleId]) {
                var pr = await pool.query('SELECT id FROM products WHERE style_id = $1', [accumStyleId]); productId = pr.rows[0].id;
            } else {
                var ins = await pool.query('INSERT INTO products (style_id, base_style, name, category, image_url, first_seen_import) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id', [accumStyleId, baseStyle, name, validCategory, validImageUrl, currentImportId]);
                productId = ins.rows[0].id; newArrivals++; existingStyleSet[accumStyleId] = true;
            }
        } else {
            var pr = await pool.query('SELECT id, image_url FROM products WHERE style_id = $1', [accumStyleId]);
            if (pr.rows.length > 0) { productId = pr.rows[0].id; await pool.query('UPDATE products SET name=$1, category=$2, base_style=$3, image_url=$4, updated_at=CURRENT_TIMESTAMP WHERE id=$5', [name, validCategory, baseStyle, validImageUrl || pr.rows[0].image_url, productId]);
            } else { var ins = await pool.query('INSERT INTO products (style_id, base_style, name, category, image_url, first_seen_import) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id', [accumStyleId, baseStyle, name, validCategory, validImageUrl, currentImportId]); productId = ins.rows[0].id; existingStyleSet[accumStyleId] = true; }
        }
        var normalizedColor = accumColor.trim();
        if (shouldDelete) {
            await pool.query('INSERT INTO product_colors (product_id, color_name, available_now, left_to_sell, on_hand, open_order, to_come, available_qty) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [productId, normalizedColor, totalAvailableNow, totalLeftToSell, totalOnHand, totalOpenOrder, totalToCome, totalAvailableNow]);
        } else {
            var cr = await pool.query('SELECT id, available_now FROM product_colors WHERE product_id=$1 AND LOWER(TRIM(color_name))=LOWER($2)', [productId, normalizedColor]);
            if (cr.rows.length > 0) { var newAN = (cr.rows[0].available_now || 0) + totalAvailableNow; await pool.query('UPDATE product_colors SET available_now=$1, available_qty=$2, updated_at=CURRENT_TIMESTAMP WHERE id=$3', [newAN, newAN, cr.rows[0].id]);
            } else { await pool.query('INSERT INTO product_colors (product_id, color_name, available_now, left_to_sell, on_hand, open_order, to_come, available_qty) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [productId, normalizedColor, totalAvailableNow, totalLeftToSell, totalOnHand, totalOpenOrder, totalToCome, totalAvailableNow]); }
        }
        for (var s = 0; s < sizeAccum.length; s++) {
            var sz = sizeAccum[s];
            if (shouldDelete) {
                sizeBatchCount++; var off = (sizeBatchCount - 1) * 9;
                sizeBatchParams.push(accumStyleId, normalizedColor, sz.size, sz.sizeRank, sz.availableNow, sz.leftToSell, sz.onHand, sz.toCome, sz.openOrder);
                sizeBatchValues.push('($'+(off+1)+',$'+(off+2)+',$'+(off+3)+',$'+(off+4)+',$'+(off+5)+',$'+(off+6)+',$'+(off+7)+',$'+(off+8)+',$'+(off+9)+')');
                if (sizeBatchCount >= 200) { await pool.query('INSERT INTO product_sizes (style_id, color_name, size, size_rank, available_now, left_to_sell, on_hand, to_come, open_order) VALUES ' + sizeBatchValues.join(','), sizeBatchParams); sizeBatchValues = []; sizeBatchParams = []; sizeBatchCount = 0; }
            } else {
                var sr = await pool.query('SELECT id, available_now FROM product_sizes WHERE style_id=$1 AND LOWER(TRIM(color_name))=LOWER($2) AND size=$3', [accumStyleId, normalizedColor, sz.size]);
                if (sr.rows.length > 0) { await pool.query('UPDATE product_sizes SET available_now=$1, updated_at=CURRENT_TIMESTAMP WHERE id=$2', [(sr.rows[0].available_now||0)+sz.availableNow, sr.rows[0].id]);
                } else { await pool.query('INSERT INTO product_sizes (style_id, color_name, size, size_rank, available_now, left_to_sell, on_hand, to_come, open_order) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [accumStyleId, normalizedColor, sz.size, sz.sizeRank, sz.availableNow, sz.leftToSell, sz.onHand, sz.toCome, sz.openOrder]); }
            }
        }
        imported += sizeAccum.length; sizeAccum = [];
    }

    function parseNumber(val) {
        if (!val) return 0;
        return parseInt(String(val).replace(/[,"]/g, '')) || 0;
    }

    function parseCSVLine(line) {
        var result = [];
        var current = '';
        var inQuotes = false;
        for (var i = 0; i < line.length; i++) {
            var ch = line[i];
            if (ch === '"') { inQuotes = !inQuotes; }
            else if (ch === ',' && !inQuotes) { result.push(current.trim()); current = ''; }
            else { current += ch; }
        }
        result.push(current.trim());
        return result;
    }

    for (var li = 1; li < lines.length; li++) {
        try {
            var values = parseCSVLine(lines[li]);
            if (values[0] && values[0].indexOf('Grand Summary') !== -1) { skipped++; continue; }

            var styleId = values[headerMap['style name']] || values[0];
            var imageUrl = values[headerMap['style image']] || values[1];
            var color = values[headerMap['color']] || values[2];
            var category = values[headerMap['commodity']] || values[3];

            // Parse values based on file type
            var onHand = 0, availableNow = 0, openOrder = 0, toCome = 0, leftToSell = 0;

            if (fileType === 'available_now') {
                // Available Now file: Style, Image, Color, Commodity, Date, On Hand(5), Allocated(6), Picked(7), Available Now(8)
                onHand = parseNumber(values[headerMap['on hand']] || values[5]);
                availableNow = parseNumber(values[headerMap['available now']] || values[8]);
            } else if (fileType === 'left_to_sell') {
                // Left to Sell file: Style, Image, Color, Commodity, Date, On Hand(5), To Come(6), Open Order(7), Left to Sell(8)
                onHand = parseNumber(values[headerMap['on hand']] || values[5]);
                toCome = parseNumber(values[headerMap['to come']] || values[6]);
                openOrder = parseNumber(values[headerMap['open order']] || values[7]);
                leftToSell = parseNumber(values[headerMap['left to sell']] || values[8]);
            } else {
                // Legacy combined file format
                onHand = parseNumber(values[headerMap['net on hand']] || values[4]);
                availableNow = parseNumber(values[headerMap['available now']] || values[7]);
                openOrder = parseNumber(values[headerMap['open order']] || values[8]);
                toCome = parseNumber(values[headerMap['to come']] || values[9]);
                leftToSell = parseNumber(values[headerMap['left to sell']] || values[10]);
            }

            if (!styleId && color) {
                styleId = lastStyleId;
                if (!imageUrl || imageUrl === '-No Value-') imageUrl = lastImageUrl;
                if (!category || category === '-No Value-') category = lastCategory;
            }
            if (hasSizes && !styleId && !color) {
                styleId = lastStyleId; color = lastColor;
                if (!imageUrl || imageUrl === '-No Value-') imageUrl = lastImageUrl;
                if (!category || category === '-No Value-') category = lastCategory;
            }
            if (!styleId) { skipped++; continue; }

            lastStyleId = styleId;
            if (color && color !== '-No Value-') lastColor = color;
            if (imageUrl && imageUrl !== '-No Value-' && imageUrl.indexOf('http') === 0) lastImageUrl = imageUrl;
            if (category && category !== '-No Value-') lastCategory = category;

            var baseStyle = styleId.split('-')[0];
            var validCategory = (category && category !== '-No Value-') ? category : 'Uncategorized';
            var name = validCategory + ' - ' + baseStyle;
            var validImageUrl = (imageUrl && imageUrl !== '-No Value-' && imageUrl.indexOf('http') === 0) ? imageUrl : lastImageUrl;

            if (hasSizes) {
                var sizeVal = values[headerMap['size']] || '';
                var sizeRank = parseNumber(values[headerMap['__size_rank']]);
                if (styleId !== accumStyleId || color !== accumColor) {
                    await flushSizeAccum(); accumStyleId = styleId; accumColor = color; accumImageUrl = validImageUrl; accumCategory = category;
                }
                if (sizeVal) { sizeAccum.push({size:sizeVal, sizeRank:sizeRank, onHand:onHand, availableNow:availableNow, leftToSell:leftToSell, toCome:toCome, openOrder:openOrder}); }
                if (li % 5000 === 0) { console.log('Progress (sizes): processed', li, 'rows'); }
                continue;
            }

            var productId;
            if (shouldDelete) {
                // We deleted all data - just INSERT directly (FAST)
                // But we need to handle duplicate styles within the same file
                if (existingStyleSet[styleId]) {
                    // Style already inserted in this import - get its ID
                    var productResult = await pool.query('SELECT id FROM products WHERE style_id = $1', [styleId]);
                    productId = productResult.rows[0].id;
                } else {
                    var ins = await pool.query('INSERT INTO products (style_id, base_style, name, category, image_url, first_seen_import) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id', [styleId, baseStyle, name, validCategory, validImageUrl, currentImportId]);
                    productId = ins.rows[0].id;
                    newArrivals++;
                    existingStyleSet[styleId] = true;
                }
            } else {
                // Available Now: UPDATE existing products or INSERT new ones
                var productResult = await pool.query('SELECT id, image_url FROM products WHERE style_id = $1', [styleId]);
                if (productResult.rows.length > 0) {
                    productId = productResult.rows[0].id;
                    var finalImage = validImageUrl || productResult.rows[0].image_url;
                    await pool.query('UPDATE products SET name=$1, category=$2, base_style=$3, image_url=$4, updated_at=CURRENT_TIMESTAMP WHERE id=$5', [name, validCategory, baseStyle, finalImage, productId]);
                } else {
                    var ins = await pool.query('INSERT INTO products (style_id, base_style, name, category, image_url, first_seen_import) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id', [styleId, baseStyle, name, validCategory, validImageUrl, currentImportId]);
                    productId = ins.rows[0].id;
                    existingStyleSet[styleId] = true;
                }
            }

            if (color && color !== '-No Value-') {
                // Normalize color name for consistent matching
                var normalizedColor = color.trim();

                if (shouldDelete) {
                    // We deleted all data, so just INSERT directly - no need to check if exists
                    // This is MUCH faster than doing SELECT + INSERT/UPDATE for each row
                    await pool.query('INSERT INTO product_colors (product_id, color_name, available_now, left_to_sell, on_hand, open_order, to_come, available_qty) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
                        [productId, normalizedColor, availableNow, leftToSell, onHand, openOrder, toCome, availableNow]);
                } else {
                    // Available Now file: need to UPDATE existing records from Left to Sell
                    var colorResult = await pool.query('SELECT id, available_now FROM product_colors WHERE product_id=$1 AND LOWER(TRIM(color_name))=LOWER($2)', [productId, normalizedColor]);
                    if (colorResult.rows.length > 0) {
                        var existing = colorResult.rows[0];
                        // SUM duplicates: add new value to existing value
                        var newAvailableNow = (existing.available_now || 0) + availableNow;
                        await pool.query('UPDATE product_colors SET available_now=$1, available_qty=$2, updated_at=CURRENT_TIMESTAMP WHERE id=$3',
                            [newAvailableNow, newAvailableNow, existing.id]);
                    } else {
                        // Color doesn't exist (not in Left to Sell) - insert new
                        await pool.query('INSERT INTO product_colors (product_id, color_name, available_now, left_to_sell, on_hand, open_order, to_come, available_qty) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
                            [productId, normalizedColor, availableNow, leftToSell, onHand, openOrder, toCome, availableNow]);
                    }
                }
            }
            imported++;
            if (imported % 5000 === 0) {
                console.log('Progress: imported', imported, 'rows, skipped', skipped);
            }
        } catch (rowErr) {
            console.error('Row error at line', li, ':', rowErr.message);
            skipped++;
        }
    }

    if (hasSizes) {
        await flushSizeAccum();
        if (sizeBatchCount > 0) { await pool.query('INSERT INTO product_sizes (style_id, color_name, size, size_rank, available_now, left_to_sell, on_hand, to_come, open_order) VALUES ' + sizeBatchValues.join(','), sizeBatchParams); }
        console.log('Size data import complete');
    }

    console.log('Import complete: imported', imported, ', skipped', skipped, ', newArrivals', newArrivals);
    await pool.query('UPDATE sync_history SET records_synced = $1, status = $2 WHERE id = $3', [imported, 'success', currentImportId]);
    lastImportId = currentImportId;

    // Report freshness to admin panel
    await reportDataFreshness('Product Catalog', imported, fileType + ' import');

    // Track granular freshness per data type
    try {
        if (fileType === 'left_to_sell') {
            if (hasSizes) {
                await pool.query("INSERT INTO data_freshness_detail (data_type, last_updated, record_count, file_name, has_sizes) VALUES ('lts_inventory_sizes', CURRENT_TIMESTAMP, $1, $2, true) ON CONFLICT (data_type) DO UPDATE SET last_updated = CURRENT_TIMESTAMP, record_count = $1, file_name = $2, has_sizes = true", [imported, filename]);
            }
            await pool.query("INSERT INTO data_freshness_detail (data_type, last_updated, record_count, file_name, has_sizes) VALUES ('lts_inventory', CURRENT_TIMESTAMP, $1, $2, $3) ON CONFLICT (data_type) DO UPDATE SET last_updated = CURRENT_TIMESTAMP, record_count = $1, file_name = $2, has_sizes = $3", [imported, filename, hasSizes]);
        } else if (fileType === 'available_now') {
            if (hasSizes) {
                await pool.query("INSERT INTO data_freshness_detail (data_type, last_updated, record_count, file_name, has_sizes) VALUES ('avail_now_inventory_sizes', CURRENT_TIMESTAMP, $1, $2, true) ON CONFLICT (data_type) DO UPDATE SET last_updated = CURRENT_TIMESTAMP, record_count = $1, file_name = $2, has_sizes = true", [imported, filename]);
            }
            await pool.query("INSERT INTO data_freshness_detail (data_type, last_updated, record_count, file_name, has_sizes) VALUES ('avail_now_inventory', CURRENT_TIMESTAMP, $1, $2, $3) ON CONFLICT (data_type) DO UPDATE SET last_updated = CURRENT_TIMESTAMP, record_count = $1, file_name = $2, has_sizes = $3", [imported, filename, hasSizes]);
        } else {
            await pool.query("INSERT INTO data_freshness_detail (data_type, last_updated, record_count, file_name, has_sizes) VALUES ('combined_inventory', CURRENT_TIMESTAMP, $1, $2, $3) ON CONFLICT (data_type) DO UPDATE SET last_updated = CURRENT_TIMESTAMP, record_count = $1, file_name = $2, has_sizes = $3", [imported, filename, hasSizes]);
        }
    } catch (freshErr) { console.error('Error tracking freshness detail:', freshErr.message); }

    return { success: true, imported: imported, skipped: skipped, newArrivals: newArrivals, fileType: fileType };
}

// Process sales CSV (same logic as manual upload)
// shouldClear: if true, delete all existing data first (for first file of a batch)
// if false, just append (for subsequent files like V2, V3, etc.)
async function processSalesCSV(csvContent, filename, shouldClear) {
    // Default to true for backwards compatibility with manual uploads
    if (shouldClear === undefined) shouldClear = true;

    var lines = csvContent.split('\n');
    if (lines.length < 2) return { success: false, error: 'Empty file', imported: 0 };

    var headers = lines[0].toLowerCase().replace(/^\ufeff/, '').split(',').map(function(h) { return h.trim().replace(/['"]/g, '').replace(/\s+/g, '_').replace(/\//g, '_'); });
    var colMap = {};
    headers.forEach(function(h, i) { colMap[h] = i; });
    console.log('processSalesCSV headers:', headers);

    var docTypeIdx = colMap['document_type'] !== undefined ? colMap['document_type'] : 0;
    var docNumIdx = colMap['document_number'] !== undefined ? colMap['document_number'] : 1;
    var dateIdx = colMap['date'] !== undefined ? colMap['date'] : 2;
    var inWarehouseIdx = colMap['in_warehouse_date'];
    var custIdx = colMap['customer_vendor'] !== undefined ? colMap['customer_vendor'] : 3;
    var skuIdx = colMap['line_item_sku'];
    var styleIdx = colMap['line_item_style'];
    var statusIdx = colMap['status'];
    var qtyIdx = colMap['quantity'];
    var amtIdx = colMap['amount'];

    // Only clear data if this is the first file of a batch (shouldClear=true)
    // For split files (V1, V2), only V1 clears, V2 appends
    if (shouldClear) {
        console.log('Full replace: Clearing all existing sales data (first file of batch)...');
        await pool.query('DELETE FROM sales_data');
        console.log('Existing sales data cleared. Importing fresh sales data...');
    } else {
        console.log('Appending to existing sales data (additional file in batch: ' + filename + ')...');
    }
    
    var imported = 0, skipped = 0, errors = 0;
    var batch = [];
    var batchSize = 500; // Moderate batch size to avoid overwhelming PostgreSQL
    var totalLines = lines.length - 1;
    console.log('Processing', totalLines, 'lines from sales CSV...');
    console.log('Starting CSV parse loop...');

    for (var i = 1; i < lines.length; i++) {
        // Log first row to confirm loop started
        if (i === 1) {
            console.log('CSV parse loop started, processing first row...');
        }
        // Yield to event loop every 1000 rows to allow log flushing
        if (i % 1000 === 0) {
            console.log('Parsed', i, 'of', totalLines, 'rows (' + Math.round(i/totalLines*100) + '%)');
            await new Promise(function(resolve) { setImmediate(resolve); });
        }
        try {
            var line = lines[i];
            if (!line.trim()) continue;

            // Fast path: if line has no quotes, just split by comma
            var row;
            if (line.indexOf('"') === -1) {
                row = line.split(',').map(function(c) { return c.trim(); });
            } else {
                // Slow path: handle quoted fields
                row = [];
                var cell = '';
                var inQuotes = false;
                for (var j = 0; j < line.length; j++) {
                    var ch = line[j];
                    if (ch === '"') { inQuotes = !inQuotes; }
                    else if (ch === ',' && !inQuotes) { row.push(cell.trim()); cell = ''; }
                    else { cell += ch; }
                }
                row.push(cell.trim());
            }

            var docType = row[docTypeIdx] || '';
            var docNum = row[docNumIdx] || '';
            var docDate = row[dateIdx] || null;
            var inWarehouseRaw = inWarehouseIdx !== undefined ? row[inWarehouseIdx] || '' : '';
            // Parse in_warehouse_date - format is "11 May, 2025 00:00:00"
            var inWarehouseDate = null;
            if (inWarehouseRaw) {
                try {
                    var parsed = new Date(inWarehouseRaw.replace(/,/g, ''));
                    if (!isNaN(parsed.getTime())) {
                        inWarehouseDate = parsed.toISOString().split('T')[0];
                    }
                } catch (e) { }
            }
            var customer = row[custIdx] || '';
            var sku = skuIdx !== undefined ? row[skuIdx] || '' : '';
            var style = styleIdx !== undefined ? row[styleIdx] || '' : '';
            var status = statusIdx !== undefined ? row[statusIdx] || '' : '';
            var qty = qtyIdx !== undefined ? parseFloat((row[qtyIdx] || '0').replace(/,/g, '')) || 0 : 0;
            var amt = amtIdx !== undefined ? parseFloat((row[amtIdx] || '0').replace(/,/g, '')) || 0 : 0;
            
            var baseStyle = style ? style.split('-')[0] : (sku ? sku.split('-')[0] : '');
            
            if (docType && docNum && baseStyle) {
                // Since we deleted all data, just add to batch
                batch.push([docType, docNum, docDate, inWarehouseDate, customer, sku, baseStyle, status, qty, amt]);
                
                if (batch.length >= batchSize) {
                    var values = [];
                    var placeholders = [];
                    var paramIdx = 1;
                    for (var b = 0; b < batch.length; b++) {
                        var item = batch[b];
                        placeholders.push('($' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ')');
                        values = values.concat(item);
                    }
                    console.log('Inserting batch of', batch.length, 'rows...');
                    try {
                        await pool.query('INSERT INTO sales_data (document_type, document_number, doc_date, in_warehouse_date, customer_vendor, line_item_sku, base_style, status, quantity, amount) VALUES ' + placeholders.join(','), values);
                        console.log('Batch insert successful');
                    } catch (insertErr) {
                        // Duplicate key errors are expected - the CSV may have duplicate rows
                        if (insertErr.message.includes('duplicate key')) {
                            console.log('Batch has duplicates, inserting rows one by one...');
                            // Fall back to inserting one at a time to skip duplicates
                            for (var r = 0; r < batch.length; r++) {
                                try {
                                    await pool.query('INSERT INTO sales_data (document_type, document_number, doc_date, in_warehouse_date, customer_vendor, line_item_sku, base_style, status, quantity, amount) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', batch[r]);
                                } catch (singleErr) {
                                    // Skip duplicate rows silently
                                }
                            }
                        } else {
                            console.error('Batch insert FAILED:', insertErr.message);
                            throw insertErr;
                        }
                    }
                    imported += batch.length;
                    batch = [];
                    // Log every batch to show progress
                    console.log('Sales import progress:', imported, 'of ~' + totalLines, 'rows (' + Math.round(imported/totalLines*100) + '%)');
                    // Yield after each batch insert
                    await new Promise(function(resolve) { setImmediate(resolve); });
                }
            }
        } catch (err) {
            errors++;
        }
    }
    
    // Insert remaining batch
    if (batch.length > 0) {
        var values = [];
        var placeholders = [];
        var paramIdx = 1;
        for (var b = 0; b < batch.length; b++) {
            var item = batch[b];
            placeholders.push('($' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ')');
            values = values.concat(item);
        }
        try {
            await pool.query('INSERT INTO sales_data (document_type, document_number, doc_date, in_warehouse_date, customer_vendor, line_item_sku, base_style, status, quantity, amount) VALUES ' + placeholders.join(','), values);
        } catch (insertErr) {
            if (insertErr.message.includes('duplicate key')) {
                // Insert remaining rows one by one
                for (var r = 0; r < batch.length; r++) {
                    try {
                        await pool.query('INSERT INTO sales_data (document_type, document_number, doc_date, in_warehouse_date, customer_vendor, line_item_sku, base_style, status, quantity, amount) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', batch[r]);
                    } catch (singleErr) { }
                }
            } else {
                throw insertErr;
            }
        }
        imported += batch.length;
    }

    console.log('Sales CSV import complete:', imported, 'rows imported,', skipped, 'skipped,', errors, 'errors');
    await pool.query('INSERT INTO sync_history (sync_type, status, records_synced) VALUES ($1, $2, $3)', ['sales_import', 'success', imported]);

    // Report freshness to admin panel
    await reportDataFreshness('Sales Data', imported, 'Sales CSV import');

    // Track granular freshness
    try {
        await pool.query("INSERT INTO data_freshness_detail (data_type, last_updated, record_count, file_name) VALUES ('sales_orders_pos', CURRENT_TIMESTAMP, $1, $2) ON CONFLICT (data_type) DO UPDATE SET last_updated = CURRENT_TIMESTAMP, record_count = $1, file_name = $2", [imported, filename]);
    } catch (freshErr) { console.error('Error tracking sales freshness detail:', freshErr.message); }

    return { success: true, imported: imported, skipped: skipped, errors: errors };
}

// Check WorkDrive folders for new files and process them
async function checkWorkDriveFolderForImports() {
    console.log('Checking WorkDrive folders for new files...');
    var totalProcessed = 0;
    
    try {
        // Check Inventory folder
        console.log('Checking Inventory folder...');
        var inventoryResult = await processWorkDriveFolder(WORKDRIVE_INVENTORY_FOLDER_ID, 'inventory');
        totalProcessed += inventoryResult.processed;
        
        // Check Sales-PO folder
        console.log('Checking Sales-PO folder...');
        var salesResult = await processWorkDriveFolder(WORKDRIVE_SALES_FOLDER_ID, 'sales');
        totalProcessed += salesResult.processed;
        
        console.log('WorkDrive check complete. Processed ' + totalProcessed + ' new files.');
        return { success: true, processed: totalProcessed, inventory: inventoryResult.processed, sales: salesResult.processed };
    } catch (err) {
        console.error('Error checking WorkDrive folders:', err);
        return { success: false, error: err.message };
    }
}

// Process a single WorkDrive folder
async function processWorkDriveFolder(folderId, fileType) {
    var processed = 0;
    try {
        var files = await listWorkDriveFiles(folderId);
        console.log('Found ' + files.length + ' files in ' + fileType + ' folder (folderId: ' + folderId + ')');
        if (files.length > 0) {
            console.log('Files found:', files.map(function(f) { return f.attributes ? f.attributes.name : f.name; }).join(', '));
        }

        // For inventory files, we ONLY process the NEWEST date's files
        // This ensures we always have a complete fresh dataset
        if (fileType === 'inventory') {
            // Extract dates from filenames and find the newest date
            var newestDate = null;
            files.forEach(function(f) {
                var name = f.attributes ? f.attributes.name : (f.name || '');
                var dateMatch = name.match(/(\d{4}-\d{2}-\d{2})/);
                if (dateMatch) {
                    var fileDate = dateMatch[1];
                    if (!newestDate || fileDate > newestDate) {
                        newestDate = fileDate;
                    }
                }
            });

            console.log('Newest inventory date found:', newestDate);

            // Filter to only files from the newest date
            if (newestDate) {
                files = files.filter(function(f) {
                    var name = f.attributes ? f.attributes.name : (f.name || '');
                    return name.indexOf(newestDate) !== -1;
                });
                console.log('Filtered to', files.length, 'files from newest date:', newestDate);
            }

            // Sort so Left to Sell comes BEFORE Available Now
            // This is critical because Left to Sell clears all data, Available Now updates it
            files.sort(function(a, b) {
                var nameA = (a.attributes ? a.attributes.name : (a.name || '')).toLowerCase();
                var nameB = (b.attributes ? b.attributes.name : (b.name || '')).toLowerCase();
                var aIsLeftToSell = nameA.indexOf('left to sell') !== -1 || nameA.indexOf('left_to_sell') !== -1;
                var bIsLeftToSell = nameB.indexOf('left to sell') !== -1 || nameB.indexOf('left_to_sell') !== -1;
                // Left to Sell files come first
                if (aIsLeftToSell && !bIsLeftToSell) return -1;
                if (!aIsLeftToSell && bIsLeftToSell) return 1;
                return 0;
            });
            console.log('Inventory files sorted: Left to Sell will be processed first');
        }

        // For sales files (PO-SO Query), also filter to newest date and sort by V1, V2, etc.
        // This handles Felix's split files: PO-SO_Query_V1_2026-02-05, PO-SO_Query_V2_2026-02-05
        var salesFilesCleared = false; // Track if we've cleared data for this batch
        if (fileType === 'sales') {
            // Extract dates from filenames and find the newest date
            var newestSalesDate = null;
            files.forEach(function(f) {
                var name = f.attributes ? f.attributes.name : (f.name || '');
                var dateMatch = name.match(/(\d{4}-\d{2}-\d{2})/);
                if (dateMatch) {
                    var fileDate = dateMatch[1];
                    if (!newestSalesDate || fileDate > newestSalesDate) {
                        newestSalesDate = fileDate;
                    }
                }
            });

            console.log('Newest sales date found:', newestSalesDate);

            // Filter to only files from the newest date
            if (newestSalesDate) {
                files = files.filter(function(f) {
                    var name = f.attributes ? f.attributes.name : (f.name || '');
                    return name.indexOf(newestSalesDate) !== -1;
                });
                console.log('Filtered to', files.length, 'sales files from newest date:', newestSalesDate);
            }

            // Sort by V1, V2, etc. so they process in order
            files.sort(function(a, b) {
                var nameA = (a.attributes ? a.attributes.name : (a.name || '')).toLowerCase();
                var nameB = (b.attributes ? b.attributes.name : (b.name || '')).toLowerCase();
                // Extract version numbers (V1, V2, etc.)
                var vMatchA = nameA.match(/_v(\d+)/i);
                var vMatchB = nameB.match(/_v(\d+)/i);
                var vA = vMatchA ? parseInt(vMatchA[1]) : 0;
                var vB = vMatchB ? parseInt(vMatchB[1]) : 0;
                return vA - vB; // V1 before V2
            });
            console.log('Sales files sorted by version (V1, V2, etc.)');
        }

        for (var i = 0; i < files.length; i++) {
            var file = files[i];
            var fileId = file.id;
            var fileName = file.attributes ? file.attributes.name : (file.name || 'unknown');

            console.log('Checking file:', fileName, '(id:', fileId + ')');

            // Skip non-CSV files
            if (!fileName.toLowerCase().endsWith('.csv')) {
                console.log('  -> SKIPPED: Not a CSV file');
                continue;
            }

            // Check if already processed RECENTLY (within last 5 hours)
            // This allows re-processing files that are overwritten/updated every 6 hours
            var existing = await pool.query(
                "SELECT id, processed_at FROM workdrive_imports WHERE file_id = $1 AND processed_at > NOW() - INTERVAL '5 hours'",
                [fileId]
            );
            if (existing.rows.length > 0) {
                console.log('  -> SKIPPED: Already processed at', existing.rows[0].processed_at);
                continue;
            }

            console.log('Processing new file:', fileName, 'as', fileType);

            // Download file
            var fileBuffer = await downloadWorkDriveFile(fileId);
            if (!fileBuffer) {
                await pool.query('INSERT INTO workdrive_imports (file_id, file_name, file_type, status, error_message) VALUES ($1, $2, $3, $4, $5)',
                    [fileId, fileName, fileType, 'error', 'Failed to download']);
                console.error('Failed to download file:', fileName);
                continue;
            }

            var csvContent = fileBuffer.toString('utf-8');
            console.log('Downloaded file:', fileName, '- size:', csvContent.length, 'bytes');
            var result;

            if (fileType === 'inventory') {
                result = await processInventoryCSV(csvContent, fileName);
            } else if (fileType === 'sales') {
                // Only clear data on V1 (first file of a split batch)
                // V2, V3, etc. should append without clearing
                // This handles Felix's split files: PO-SO_Query_V1_date, PO-SO_Query_V2_date
                var versionMatch = fileName.match(/_v(\d+)/i);
                var fileVersion = versionMatch ? parseInt(versionMatch[1]) : 1;
                var shouldClear = (fileVersion === 1) && !salesFilesCleared;
                console.log('Processing sales file:', fileName, '- version:', fileVersion, '- shouldClear:', shouldClear);
                result = await processSalesCSV(csvContent, fileName, shouldClear);
                if (result.success && shouldClear) {
                    salesFilesCleared = true; // Track that we've cleared for this batch
                }
            } else {
                continue;
            }

            if (result.success) {
                // Use upsert to handle re-processing files (avoids duplicate key error)
                await pool.query(`INSERT INTO workdrive_imports (file_id, file_name, file_type, status, records_imported, processed_at)
                    VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
                    ON CONFLICT (file_id) DO UPDATE SET
                    file_name = $2, status = $4, records_imported = $5, processed_at = CURRENT_TIMESTAMP`,
                    [fileId, fileName, fileType, 'success', result.imported]);
                processed++;
                console.log('Successfully imported ' + result.imported + ' records from ' + fileName);
            } else {
                await pool.query(`INSERT INTO workdrive_imports (file_id, file_name, file_type, status, error_message, processed_at)
                    VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
                    ON CONFLICT (file_id) DO UPDATE SET
                    file_name = $2, status = $4, error_message = $5, processed_at = CURRENT_TIMESTAMP`,
                    [fileId, fileName, fileType, 'error', result.error]);
                console.error('Import failed for', fileName, ':', result.error);
            }
        }

        return { success: true, processed: processed };
    } catch (err) {
        console.error('Error processing folder:', err);
        return { success: false, processed: 0, error: err.message };
    }
}

// Start WorkDrive folder polling job - runs at specific times (2 AM and 6 AM EST)
function startWorkDriveImportJob() {
    console.log('Starting WorkDrive auto-import job (runs at 2 AM and 6 AM EST)');

    // Check every 15 minutes if it's time to run
    setInterval(function() {
        var now = new Date();
        var estHour = (now.getUTCHours() - 5 + 24) % 24; // Convert UTC to EST
        var minutes = now.getMinutes();

        // Run at 2:00 AM EST or 6:00 AM EST (within first 15 minutes of the hour)
        if ((estHour === 2 || estHour === 6) && minutes < 15) {
            var todayKey = now.toISOString().split('T')[0] + '-' + estHour;
            if (!global.lastAutoImportRun || global.lastAutoImportRun !== todayKey) {
                global.lastAutoImportRun = todayKey;
                console.log('Scheduled auto-import starting at ' + estHour + ':00 EST');
                checkWorkDriveFolderForImports();
            }
        }
    }, 15 * 60 * 1000); // Check every 15 minutes

    // Also do initial check after 1 minute (for testing/deployment)
    setTimeout(function() {
        checkWorkDriveFolderForImports();
    }, 60000);
}

// Nightly image cache refresh - checks for stale images and refreshes them
var IMAGE_CACHE_MAX_AGE_DAYS = 7;
async function refreshStaleImageCache() {
    try {
        if (!fs.existsSync(IMAGE_CACHE_DIR)) {
            console.log('Image cache directory not available, skipping refresh');
            return;
        }
        
        console.log('Starting nightly image cache refresh...');
        var files = fs.readdirSync(IMAGE_CACHE_DIR).filter(f => f.endsWith('.meta'));
        var refreshed = 0;
        var skipped = 0;
        var errors = 0;
        var maxAgeMs = IMAGE_CACHE_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
        var now = Date.now();
        
        for (var i = 0; i < files.length; i++) {
            try {
                var metaPath = path.join(IMAGE_CACHE_DIR, files[i]);
                var meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
                var cachedAt = new Date(meta.cachedAt).getTime();
                
                // Skip if cached less than max age days ago
                if (now - cachedAt < maxAgeMs) {
                    skipped++;
                    continue;
                }
                
                // Refresh this image
                var fileId = meta.fileId;
                if (!fileId) {
                    skipped++;
                    continue;
                }
                
                if (!zohoAccessToken) await refreshZohoToken();
                var imageUrl = 'https://workdrive.zoho.com/api/v1/download/' + fileId;
                var response = await fetch(imageUrl, { 
                    headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken } 
                });
                
                if (response.ok) {
                    var contentType = response.headers.get('content-type') || 'image/jpeg';
                    var imageBuffer = Buffer.from(await response.arrayBuffer());
                    var cachePath = path.join(IMAGE_CACHE_DIR, fileId);
                    fs.writeFileSync(cachePath, imageBuffer);
                    fs.writeFileSync(metaPath, JSON.stringify({
                        contentType: contentType,
                        cachedAt: new Date().toISOString(),
                        fileId: fileId
                    }));
                    refreshed++;
                } else {
                    errors++;
                }
                
                // Rate limit - wait 200ms between API calls
                await new Promise(resolve => setTimeout(resolve, 200));
                
            } catch (err) {
                errors++;
            }
        }
        
        console.log('Nightly image cache refresh complete: ' + refreshed + ' refreshed, ' + skipped + ' skipped (< ' + IMAGE_CACHE_MAX_AGE_DAYS + ' days old), ' + errors + ' errors');
    } catch (err) {
        console.log('Error in nightly image cache refresh:', err.message);
    }
}

// Start nightly image refresh job (runs at 2 AM server time, checks every hour if it's time)
var lastImageRefreshDate = null;
setInterval(function() {
    var now = new Date();
    var hour = now.getUTCHours();
    var dateStr = now.toISOString().split('T')[0];
    
    // Run at 7 UTC (2 AM EST) if we haven't run today
    if (hour === 7 && lastImageRefreshDate !== dateStr) {
        lastImageRefreshDate = dateStr;
        refreshStaleImageCache();
    }
}, 60 * 60 * 1000); // Check every hour
console.log('Started nightly image cache refresh job (runs at 2 AM EST, refreshes images older than ' + IMAGE_CACHE_MAX_AGE_DAYS + ' days)');

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
        await reportDataFreshness('Product Catalog', recordCount, 'Zoho sync');
        res.json({ success: true, message: 'Synced ' + recordCount + ' records' });
    } catch (err) { console.error('Sync error:', err); res.json({ success: false, error: err.message }); }
});

app.get('/api/zoho/sync-history', requireAuth, async function(req, res) { try { var result = await pool.query('SELECT * FROM sync_history ORDER BY created_at DESC LIMIT 20'); res.json(result.rows); } catch (err) { res.status(500).json({ error: err.message }); } });

// =============================================
// ZOHO FLOW WEBHOOK INTEGRATION
// =============================================

// Zoho Flow webhook URL - triggers export in Zoho Analytics
var ZOHO_FLOW_WEBHOOK_URL = process.env.ZOHO_FLOW_WEBHOOK_URL || 'https://flow.zoho.com/691122364/flow/webhook/incoming?zapikey=1001.e31d40549cda427ea3bc24543a0525c5.77f014125de41156e64d1b960d9d8c9b&isdebug=false';

// Trigger export via Zoho Flow webhook
app.post('/api/trigger-export', requireAuth, requireAdmin, async function(req, res) {
    try {
        var exportType = req.body.exportType || 'sales'; // 'sales' or 'inventory'
        var jobId = 'export_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);

        // Determine the callback URL based on the request host
        var protocol = req.headers['x-forwarded-proto'] || req.protocol || 'https';
        var host = req.headers['x-forwarded-host'] || req.headers.host;
        var callbackUrl = protocol + '://' + host + '/api/zoho-export-callback';

        console.log('Triggering export via Zoho Flow webhook...');
        console.log('Export type:', exportType);
        console.log('Job ID:', jobId);
        console.log('Callback URL:', callbackUrl);

        // Create job record
        await pool.query(
            'INSERT INTO export_jobs (job_id, export_type, status) VALUES ($1, $2, $3)',
            [jobId, exportType, 'pending']
        );

        // POST to Zoho Flow webhook
        var webhookResponse = await fetch(ZOHO_FLOW_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                callbackUrl: callbackUrl,
                exportType: exportType,
                jobId: jobId
            })
        });

        if (!webhookResponse.ok) {
            var errorText = await webhookResponse.text();
            console.error('Zoho Flow webhook error:', webhookResponse.status, errorText);
            await pool.query(
                'UPDATE export_jobs SET status = $1, error_message = $2, completed_at = NOW() WHERE job_id = $3',
                ['failed', 'Webhook error: ' + webhookResponse.status, jobId]
            );
            return res.json({ success: false, error: 'Failed to trigger export: ' + webhookResponse.status });
        }

        var responseData = await webhookResponse.text();
        console.log('Zoho Flow webhook response:', responseData);

        // Update job status to processing
        await pool.query(
            'UPDATE export_jobs SET status = $1 WHERE job_id = $2',
            ['processing', jobId]
        );

        res.json({
            success: true,
            message: 'Export triggered successfully',
            jobId: jobId,
            callbackUrl: callbackUrl
        });
    } catch (err) {
        console.error('Trigger export error:', err);
        res.json({ success: false, error: err.message });
    }
});

// Callback endpoint for Zoho Flow to report export completion
// NOTE: No auth required - this is called by Zoho Flow
app.post('/api/zoho-export-callback', async function(req, res) {
    try {
        var payload = req.body;
        console.log('Received Zoho export callback:', JSON.stringify(payload, null, 2));

        var status = payload.status || 'unknown';
        var fileName = payload.fileName || null;
        var fileId = payload.fileId || null;
        var jobId = payload.jobId || null;
        var message = payload.message || null;
        var finalStatus = (status === 'success' || status === 'completed') ? 'completed' : 'failed';

        var updated = false;

        // First, try to update the exact jobId if provided
        if (jobId) {
            var result = await pool.query(
                'UPDATE export_jobs SET status = $1, file_name = $2, file_id = $3, error_message = $4, completed_at = NOW() WHERE job_id = $5',
                [finalStatus, fileName, fileId, message, jobId]
            );
            updated = result.rowCount > 0;
            console.log('Tried exact jobId match:', jobId, 'Updated:', updated);
        }

        // If no match, try to find the most recent "processing" job and update it
        if (!updated) {
            var result = await pool.query(
                "UPDATE export_jobs SET status = $1, file_name = $2, file_id = $3, error_message = $4, completed_at = NOW() WHERE id = (SELECT id FROM export_jobs WHERE status = 'processing' ORDER BY triggered_at DESC LIMIT 1)",
                [finalStatus, fileName, fileId, message || 'Updated via callback (jobId mismatch)']
            );
            updated = result.rowCount > 0;
            console.log('Tried most recent processing job. Updated:', updated);
        }

        // If still no match, log a record for tracking
        if (!updated) {
            var newJobId = 'callback_' + Date.now();
            await pool.query(
                'INSERT INTO export_jobs (job_id, export_type, status, file_name, file_id, error_message, completed_at) VALUES ($1, $2, $3, $4, $5, $6, NOW())',
                [newJobId, 'unknown', finalStatus, fileName, fileId, message || 'Orphan callback - no matching job']
            );
            console.log('Created new callback record:', newJobId);
        }

        console.log('Export callback processed - Status:', finalStatus, 'File:', fileName);

        res.json({ success: true, message: 'Callback received' });
    } catch (err) {
        console.error('Export callback error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Get export job status for frontend polling
app.get('/api/export-status', requireAuth, async function(req, res) {
    try {
        var jobId = req.query.jobId;

        if (jobId) {
            // Get specific job status
            var result = await pool.query(
                'SELECT * FROM export_jobs WHERE job_id = $1',
                [jobId]
            );
            if (result.rows.length === 0) {
                return res.json({ success: false, error: 'Job not found' });
            }
            res.json({ success: true, job: result.rows[0] });
        } else {
            // Get recent export jobs
            var result = await pool.query(
                'SELECT * FROM export_jobs ORDER BY triggered_at DESC LIMIT 10'
            );
            res.json({ success: true, jobs: result.rows });
        }
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// Get all export jobs for display in admin panel
app.get('/api/export-jobs', requireAuth, async function(req, res) {
    try {
        var result = await pool.query(
            'SELECT * FROM export_jobs ORDER BY triggered_at DESC LIMIT 20'
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Clear stuck processing jobs (mark as cancelled)
app.post('/api/clear-stuck-jobs', requireAuth, async function(req, res) {
    try {
        var result = await pool.query(
            "UPDATE export_jobs SET status = 'cancelled', completed_at = NOW(), error_message = 'Manually cancelled' WHERE status = 'processing'"
        );
        res.json({ success: true, cleared: result.rowCount });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// =============================================
// END ZOHO FLOW WEBHOOK INTEGRATION
// =============================================

// Data freshness endpoint - get last CSV import date
app.get('/api/data-freshness', requireAuth, async function(req, res) {
    try {
        var result = await pool.query("SELECT created_at, records_synced FROM sync_history WHERE sync_type = 'csv_import' AND status = 'success' ORDER BY created_at DESC LIMIT 1");
        // Also get detailed freshness
        var detail = await pool.query("SELECT data_type, last_updated, record_count, file_name, has_sizes FROM data_freshness_detail ORDER BY data_type");
        var sizeStats = await pool.query("SELECT COUNT(*) as total_rows FROM product_sizes");
        if (result.rows.length > 0) {
            res.json({ lastUpdate: result.rows[0].created_at, recordCount: result.rows[0].records_synced, detail: detail.rows, sizeRows: parseInt(sizeStats.rows[0].total_rows) });
        } else {
            res.json({ lastUpdate: null, recordCount: 0, detail: detail.rows, sizeRows: parseInt(sizeStats.rows[0].total_rows) });
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
            'SELECT document_type, document_number, doc_date, in_warehouse_date, customer_vendor, status, SUM(quantity) as total_qty, SUM(amount) as total_amount FROM sales_data WHERE base_style = $1 GROUP BY document_type, document_number, doc_date, in_warehouse_date, customer_vendor, status ORDER BY doc_date DESC',
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
                inWarehouseDate: row.in_warehouse_date,
                customerName: row.customer_vendor,
                status: row.status,
                quantity: qty,
                amount: amt,
                isOpen: status !== 'invoiced' && status !== 'closed' && status !== 'fulfilled' && status !== 'paid'
            });
            
            // Categorize for summary
            if (docType.indexOf('purchase') !== -1) {
                // Purchase Orders - only count open POs in tile summary
                if (status === 'open') {
                    totalPO += qty;
                    totalPOAmount += amt;
                    poCount++;
                }
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

// Sales Search API - Search orders by customer, style, or type
app.get('/api/sales-search', requireAuth, async function(req, res) {
    try {
        var customer = req.query.customer;
        var style = req.query.style;
        var type = req.query.type; // 'po', 'salesorder', 'invoice', or 'all'
        var limit = parseInt(req.query.limit) || 100;
        
        var conditions = [];
        var params = [];
        var paramIndex = 1;
        
        if (customer) {
            // Clean up customer name - remove special chars that might cause issues
            var cleanCustomer = customer.replace(/[\/\\'"]/g, '%');
            // Also try just the first word if it's a multi-word name
            var firstWord = customer.split(/[\s,\/\\]+/)[0];
            if (firstWord.length >= 3 && firstWord !== cleanCustomer) {
                // Search for either the full name OR just the first word
                conditions.push('(LOWER(customer_vendor) LIKE LOWER($' + paramIndex + ') OR LOWER(customer_vendor) LIKE LOWER($' + (paramIndex + 1) + '))');
                params.push('%' + cleanCustomer + '%');
                params.push('%' + firstWord + '%');
                paramIndex += 2;
            } else {
                conditions.push('LOWER(customer_vendor) LIKE LOWER($' + paramIndex + ')');
                params.push('%' + cleanCustomer + '%');
                paramIndex++;
            }
        }
        
        if (style) {
            conditions.push('(LOWER(base_style) LIKE LOWER($' + paramIndex + ') OR LOWER(line_item_sku) LIKE LOWER($' + paramIndex + '))');
            params.push('%' + style + '%');
            paramIndex++;
        }
        
        if (type === 'po') {
            conditions.push("LOWER(document_type) LIKE '%purchase%'");
        } else if (type === 'salesorder') {
            conditions.push("LOWER(document_type) LIKE '%sales%'");
        } else if (type === 'invoice') {
            conditions.push("LOWER(document_type) LIKE '%invoice%'");
        }
        
        var whereClause = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
        
        var query = `
            SELECT 
                document_type, 
                document_number, 
                doc_date, 
                customer_vendor, 
                base_style,
                status, 
                SUM(quantity) as total_qty, 
                SUM(amount) as total_amount
            FROM sales_data 
            ${whereClause}
            GROUP BY document_type, document_number, doc_date, customer_vendor, base_style, status
            ORDER BY doc_date DESC
            LIMIT $${paramIndex}
        `;
        params.push(limit);
        
        var result = await pool.query(query, params);
        
        // Also get summary stats
        var summaryQuery = `
            SELECT 
                COUNT(DISTINCT document_number) as doc_count,
                COUNT(DISTINCT customer_vendor) as customer_count,
                COUNT(DISTINCT base_style) as style_count,
                COALESCE(SUM(quantity), 0) as total_qty,
                COALESCE(SUM(amount), 0) as total_amount
            FROM sales_data
            ${whereClause}
        `;
        var summaryResult = await pool.query(summaryQuery, params.slice(0, -1)); // Remove limit param
        
        // Get unique base styles that were ordered
        var stylesQuery = `
            SELECT DISTINCT base_style 
            FROM sales_data 
            ${whereClause}
        `;
        var stylesResult = await pool.query(stylesQuery, params.slice(0, -1));
        var orderedStyles = stylesResult.rows.map(function(r) { return r.base_style; }).filter(function(s) { return s; });
        
        res.json({
            success: true,
            results: result.rows.map(function(row) {
                return {
                    documentType: row.document_type,
                    documentNumber: row.document_number,
                    date: row.doc_date,
                    customer: row.customer_vendor,
                    style: row.base_style,
                    status: row.status,
                    quantity: parseFloat(row.total_qty) || 0,
                    amount: parseFloat(row.total_amount) || 0
                };
            }),
            summary: {
                documentCount: parseInt(summaryResult.rows[0].doc_count) || 0,
                customerCount: parseInt(summaryResult.rows[0].customer_count) || 0,
                styleCount: parseInt(summaryResult.rows[0].style_count) || 0,
                totalQty: parseFloat(summaryResult.rows[0].total_qty) || 0,
                totalAmount: parseFloat(summaryResult.rows[0].total_amount) || 0
            },
            orderedStyles: orderedStyles,
            filters: { customer: customer, style: style, type: type }
        });
        
    } catch (err) {
        console.error('Sales search error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Get unique customers (from SO and Invoice)
app.get('/api/customers', async function(req, res) {
    try {
        var result = await pool.query(`
            SELECT customer_vendor, 
                   COUNT(DISTINCT base_style) as style_count,
                   SUM(quantity) as total_qty
            FROM sales_data 
            WHERE document_type IN ('Sales Order', 'SO', 'Invoice') 
              AND customer_vendor IS NOT NULL 
              AND customer_vendor != ''
            GROUP BY customer_vendor
            HAVING COUNT(DISTINCT base_style) > 0
            ORDER BY SUM(quantity) DESC
            LIMIT 200
        `);
        res.json({
            success: true,
            customers: result.rows.map(function(r) {
                return {
                    name: r.customer_vendor,
                    styleCount: parseInt(r.style_count) || 0,
                    totalQty: parseFloat(r.total_qty) || 0
                };
            })
        });
    } catch (err) {
        console.error('Customers list error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Get unique suppliers (from PO)
app.get('/api/suppliers', async function(req, res) {
    try {
        var result = await pool.query(`
            SELECT customer_vendor, 
                   COUNT(DISTINCT base_style) as style_count,
                   SUM(quantity) as total_qty
            FROM sales_data 
            WHERE document_type IN ('Purchase Order', 'PO', 'Bill') 
              AND customer_vendor IS NOT NULL 
              AND customer_vendor != ''
            GROUP BY customer_vendor
            HAVING COUNT(DISTINCT base_style) > 0
            ORDER BY SUM(quantity) DESC
            LIMIT 100
        `);
        res.json({
            success: true,
            suppliers: result.rows.map(function(r) {
                return {
                    name: r.customer_vendor,
                    styleCount: parseInt(r.style_count) || 0,
                    totalQty: parseFloat(r.total_qty) || 0
                };
            })
        });
    } catch (err) {
        console.error('Suppliers list error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});


// ============================================
// ORDER REQUESTS API
// ============================================

// Store CSS and JS as strings to serve them
var orderRequestsCSS = "/* Order Requests Styles */\n\n/* Order mode button */\n#orderModeBtn.active {\n    background: #34a853 !important;\n    color: white !important;\n    border-color: #34a853 !important;\n}\n\n/* Order selection indicators on cards */\n.order-mode .product-card { cursor: pointer; }\n.order-mode .product-card.order-selected {\n    outline: 3px solid #34a853;\n    outline-offset: -3px;\n    background: #f0fff4;\n}\n.order-mode .product-card .order-check {\n    display: flex;\n    position: absolute;\n    top: 8px;\n    right: 8px;\n    width: 28px;\n    height: 28px;\n    border-radius: 50%;\n    background: #34a853;\n    color: white;\n    align-items: center;\n    justify-content: center;\n    font-size: 16px;\n    font-weight: bold;\n    z-index: 5;\n    box-shadow: 0 2px 6px rgba(0,0,0,0.2);\n}\n\n/* Order bar (bottom) */\n.order-bar {\n    position: fixed;\n    bottom: 0;\n    left: 0;\n    right: 0;\n    background: #34a853;\n    color: white;\n    padding: 1rem 2rem;\n    padding-right: 10rem;\n    display: flex;\n    justify-content: space-between;\n    align-items: center;\n    z-index: 1001;\n    transform: translateY(100%);\n    transition: transform 0.3s;\n    box-shadow: 0 -4px 20px rgba(0,0,0,0.15);\n}\n.order-bar.visible { transform: translateY(0); }\n.order-bar .order-bar-count { font-weight: 700; font-size: 1rem; }\n.order-bar .order-bar-actions { display: flex; gap: 0.75rem; }\n.order-bar .order-bar-actions .btn {\n    padding: 0.5rem 1.25rem;\n    border-radius: 980px;\n    font-weight: 600;\n    font-size: 0.875rem;\n    cursor: pointer;\n    border: none;\n}\n.order-bar .btn-review {\n    background: white;\n    color: #34a853;\n}\n.order-bar .btn-clear-order {\n    background: rgba(255,255,255,0.2);\n    color: white;\n}\n.order-bar .btn-exit-order {\n    background: rgba(255,255,255,0.2);\n    color: white;\n}\n\n/* Order Review Overlay */\n.or-review-overlay {\n    position: fixed;\n    top: 0; left: 0; right: 0; bottom: 0;\n    background: rgba(0,0,0,0.5);\n    display: none;\n    align-items: flex-start;\n    justify-content: center;\n    z-index: 1002;\n    overflow-y: auto;\n    padding: 2rem;\n}\n.or-review-overlay.active { display: flex; }\n\n.or-review-box {\n    background: white;\n    border-radius: 18px;\n    padding: 2rem;\n    max-width: 700px;\n    width: 100%;\n    box-shadow: 0 20px 60px rgba(0,0,0,0.2);\n    margin: auto;\n}\n\n.or-review-header {\n    margin-bottom: 1.5rem;\n    padding-bottom: 1rem;\n    border-bottom: 1px solid #eee;\n}\n.or-review-header h2 {\n    margin: 0 0 0.25rem;\n    font-weight: 700;\n    color: #1e3a5f;\n    font-size: 1.5rem;\n}\n.or-review-header p {\n    margin: 0;\n    color: #666;\n    font-size: 0.9rem;\n}\n\n/* Product rows in review */\n.or-products-list {\n    max-height: 300px;\n    overflow-y: auto;\n    margin-bottom: 1.5rem;\n    border: 1px solid #eee;\n    border-radius: 12px;\n}\n.or-product-row {\n    display: flex;\n    align-items: center;\n    gap: 0.75rem;\n    padding: 0.75rem 1rem;\n    border-bottom: 1px solid #f0f0f0;\n}\n.or-product-row:last-child { border-bottom: none; }\n.or-product-thumb {\n    width: 50px;\n    height: 50px;\n    object-fit: contain;\n    border-radius: 8px;\n    background: #f8f8f8;\n    flex-shrink: 0;\n}\n.or-product-info { flex: 1; min-width: 0; }\n.or-product-style { font-size: 0.75rem; color: #0088c2; font-weight: 600; }\n.or-product-name { font-size: 0.85rem; font-weight: 500; color: #1e3a5f; }\n.or-product-colors { font-size: 0.75rem; color: #999; }\n.or-product-qty { font-size: 0.85rem; font-weight: 600; color: #1e3a5f; white-space: nowrap; }\n.or-remove-btn {\n    width: 28px; height: 28px;\n    border: none; background: #f5f5f5;\n    border-radius: 50%; cursor: pointer;\n    font-size: 14px; color: #999;\n    display: flex; align-items: center; justify-content: center;\n    flex-shrink: 0;\n}\n.or-remove-btn:hover { background: #fee; color: #d33; }\n\n/* Form section */\n.or-form-section {\n    padding-top: 1rem;\n    border-top: 1px solid #eee;\n}\n.or-form-section h3 {\n    margin: 0 0 1rem;\n    font-weight: 600;\n    color: #1e3a5f;\n    font-size: 1.1rem;\n}\n.or-field {\n    margin-bottom: 1rem;\n}\n.or-field label {\n    display: block;\n    font-size: 0.8rem;\n    font-weight: 600;\n    color: #666;\n    margin-bottom: 0.35rem;\n}\n.or-field select,\n.or-field input,\n.or-field textarea {\n    width: 100%;\n    padding: 0.75rem 1rem;\n    border: 1.5px solid #e0e0e0;\n    border-radius: 10px;\n    font-family: inherit;\n    font-size: 0.9rem;\n    box-sizing: border-box;\n}\n.or-field select:focus,\n.or-field input:focus,\n.or-field textarea:focus {\n    outline: none;\n    border-color: #0088c2;\n}\n.or-field textarea {\n    resize: vertical;\n    min-height: 120px;\n}\n\n/* Review actions */\n.or-review-actions {\n    display: flex;\n    gap: 0.75rem;\n    justify-content: flex-end;\n    margin-top: 1.5rem;\n    padding-top: 1rem;\n    border-top: 1px solid #eee;\n}\n\n/* Success screen */\n.or-success {\n    text-align: center;\n    padding: 2rem;\n}\n.or-success-icon { font-size: 3.5rem; margin-bottom: 1rem; }\n.or-success h2 { color: #34a853; margin: 0 0 0.5rem; }\n.or-success-number {\n    font-size: 1.75rem;\n    font-weight: 700;\n    color: #1e3a5f;\n    margin: 0.5rem 0;\n}\n.or-success p { color: #666; margin: 0.75rem 0; }\n.or-detail-link {\n    color: #0088c2;\n    text-decoration: none;\n    font-weight: 600;\n}\n.or-detail-link:hover { text-decoration: underline; }\n\n/* Orders List Panel */\n.orders-list-panel {\n    background: white;\n    padding: 1.5rem;\n    border-radius: 18px;\n    margin-bottom: 2rem;\n    border: 1px solid rgba(0,0,0,0.04);\n    box-shadow: 0 2px 12px rgba(0,0,0,0.04);\n}\n.orders-list-header {\n    display: flex;\n    justify-content: space-between;\n    align-items: center;\n    margin-bottom: 1rem;\n}\n.orders-list-header h2 {\n    margin: 0;\n    font-weight: 600;\n    color: #1e3a5f;\n    font-size: 1.25rem;\n}\n.orders-list-filters {\n    margin-bottom: 1rem;\n    display: flex;\n    align-items: center;\n    gap: 0.75rem;\n    flex-wrap: wrap;\n}\n.orders-list-filters select {\n    padding: 0.5rem 0.75rem;\n    border-radius: 8px;\n    border: 1px solid #ddd;\n    font-size: 0.85rem;\n}\n\n/* Order cards in list */\n.or-list-card {\n    border: 1px solid #e8e8e8;\n    border-radius: 12px;\n    padding: 1rem;\n    margin-bottom: 0.75rem;\n    transition: border-color 0.2s;\n}\n.or-list-card:hover { border-color: #0088c2; }\n.or-list-card-header {\n    display: flex;\n    justify-content: space-between;\n    align-items: center;\n    margin-bottom: 0.5rem;\n}\n.or-list-num { font-weight: 700; color: #1e3a5f; }\n.or-status {\n    display: inline-block;\n    padding: 2px 10px;\n    border-radius: 12px;\n    font-size: 0.75rem;\n    font-weight: 600;\n    text-transform: uppercase;\n}\n.or-status.pending { background: #fff3cd; color: #856404; }\n.or-status.processing { background: #cce5ff; color: #004085; }\n.or-status.completed { background: #d4edda; color: #155724; }\n.or-status.cancelled { background: #f8d7da; color: #721c24; }\n\n.or-list-card-body { font-size: 0.85rem; color: #555; }\n.or-list-row {\n    display: flex;\n    justify-content: space-between;\n    padding: 0.2rem 0;\n}\n.or-list-label { color: #999; font-size: 0.8rem; }\n.or-list-val { font-weight: 500; }\n.or-list-notes {\n    margin-top: 0.5rem;\n    padding: 0.5rem 0.75rem;\n    background: #f8f9fa;\n    border-radius: 8px;\n    font-size: 0.8rem;\n    color: #555;\n    white-space: pre-wrap;\n}\n.or-list-so {\n    margin-top: 0.5rem;\n    padding: 0.5rem 0.75rem;\n    background: #e8f5e9;\n    border-radius: 8px;\n    font-size: 0.85rem;\n    color: #2e7d32;\n    font-weight: 600;\n}\n.or-empty {\n    color: #999;\n    font-style: italic;\n    padding: 1rem;\n    text-align: center;\n}\n\n/* Admin controls */\n.or-admin-controls {\n    margin-top: 0.75rem;\n    padding-top: 0.75rem;\n    border-top: 1px solid #eee;\n    display: flex;\n    gap: 0.5rem;\n    flex-wrap: wrap;\n    align-items: center;\n}\n.or-admin-input {\n    padding: 5px 8px;\n    border: 1px solid #ddd;\n    border-radius: 6px;\n    font-size: 0.8rem;\n    width: 110px;\n}\n.or-admin-btn {\n    padding: 5px 12px;\n    font-size: 0.75rem;\n    color: white;\n    border: none;\n    border-radius: 980px;\n    cursor: pointer;\n    font-weight: 600;\n}\n.or-admin-btn.processing { background: #0088c2; }\n.or-admin-btn.complete { background: #34a853; }\n.or-admin-btn.cancel { background: #dc3545; }\n\n/* Order list action buttons */\n.or-list-actions {\n    display: flex;\n    gap: 0.75rem;\n    align-items: center;\n    margin-top: 0.75rem;\n    padding-top: 0.5rem;\n    border-top: 1px solid #f0f0f0;\n}\n.or-action-link {\n    color: #0088c2;\n    text-decoration: none;\n    font-weight: 600;\n    font-size: 0.85rem;\n}\n.or-action-link:hover { text-decoration: underline; }\n.or-action-btn {\n    background: none;\n    border: 1px solid #ddd;\n    border-radius: 8px;\n    padding: 4px 12px;\n    font-size: 0.8rem;\n    cursor: pointer;\n    color: #555;\n}\n.or-action-btn:hover { background: #f5f5f5; border-color: #0088c2; color: #0088c2; }\n\n/* Mobile */\n@media (max-width: 768px) {\n    .or-review-overlay { padding: 1rem; }\n    .or-review-box { padding: 1.25rem; }\n    .or-review-actions { flex-direction: column; }\n    .order-bar { padding: 0.75rem 1rem; flex-wrap: wrap; gap: 0.5rem; }\n    .order-bar .order-bar-count { width: 100%; text-align: center; font-size: 0.875rem; }\n    .order-bar .order-bar-actions { width: 100%; justify-content: center; }\n}\n";
var orderRequestsJS = "// ==========================================\n// ORDER REQUESTS - Frontend Module\n// ==========================================\n// Loaded via <script src=\"/order-requests.js\">\n// Depends on: allProducts, qtyMode, getImageUrl, userPicks, userNotes (from main app)\n\n(function() {\n    // State\n    var orderMode = false;\n    var orderSelectedProducts = [];\n\n    // ---- Order Selection Mode ----\n\n    window.toggleOrderMode = function() {\n        orderMode = !orderMode;\n        var btn = document.getElementById('orderModeBtn');\n        if (orderMode) {\n            btn.textContent = '✕ Exit Order Mode';\n            btn.classList.add('active');\n            // Show order bar\n            updateOrderBar();\n        } else {\n            btn.textContent = '📋 Create Order';\n            btn.classList.remove('active');\n            orderSelectedProducts = [];\n            updateOrderBar();\n        }\n        renderProducts(); // re-render to show/hide selection indicators\n    };\n\n    window.isOrderMode = function() {\n        return orderMode;\n    };\n\n    window.getOrderSelectedProducts = function() {\n        return orderSelectedProducts;\n    };\n\n    window.handleOrderCardClick = function(id) {\n        if (!orderMode) return false; // not in order mode, let normal click handle it\n        var idx = orderSelectedProducts.indexOf(id);\n        if (idx === -1) {\n            orderSelectedProducts.push(id);\n        } else {\n            orderSelectedProducts.splice(idx, 1);\n        }\n        updateOrderBar();\n        renderProducts();\n        return true; // handled\n    };\n\n    window.handleOrderGroupClick = function(baseStyle) {\n        if (!orderMode) return false;\n        var variants = allProducts.filter(function(p) { return p.style_id.split('-')[0] === baseStyle; });\n        var variantIds = variants.map(function(v) { return v.id; });\n        var allSelected = variantIds.every(function(id) { return orderSelectedProducts.indexOf(id) !== -1; });\n        if (allSelected) {\n            variantIds.forEach(function(id) {\n                var idx = orderSelectedProducts.indexOf(id);\n                if (idx !== -1) orderSelectedProducts.splice(idx, 1);\n            });\n        } else {\n            variantIds.forEach(function(id) {\n                if (orderSelectedProducts.indexOf(id) === -1) orderSelectedProducts.push(id);\n            });\n        }\n        updateOrderBar();\n        renderProducts();\n        return true;\n    };\n\n    window.isOrderSelected = function(id) {\n        return orderSelectedProducts.indexOf(id) !== -1;\n    };\n\n    window.isOrderGroupSelected = function(baseStyle) {\n        var variants = allProducts.filter(function(p) { return p.style_id.split('-')[0] === baseStyle; });\n        return variants.length > 0 && variants.every(function(v) { return orderSelectedProducts.indexOf(v.id) !== -1; });\n    };\n\n    window.removeFromOrder = function(id) {\n        var idx = orderSelectedProducts.indexOf(id);\n        if (idx !== -1) {\n            orderSelectedProducts.splice(idx, 1);\n            updateOrderBar();\n            renderProducts();\n            showOrderReview(); // refresh the review if open\n        }\n    };\n\n    function updateOrderBar() {\n        var bar = document.getElementById('orderBar');\n        var count = document.getElementById('orderSelectedCount');\n        if (!bar || !count) return;\n        count.textContent = orderSelectedProducts.length;\n        if (orderSelectedProducts.length > 0 && orderMode) {\n            bar.classList.add('visible');\n        } else {\n            bar.classList.remove('visible');\n        }\n    }\n\n    window.clearOrderSelection = function() {\n        orderSelectedProducts = [];\n        updateOrderBar();\n        renderProducts();\n    };\n\n    // ---- Order Review Screen ----\n\n    window.showOrderReview = function() {\n        var overlay = document.getElementById('orderReviewOverlay');\n        var content = document.getElementById('orderReviewContent');\n        if (!overlay || !content) return;\n\n        // Build product list\n        var styles = {};\n        var totalQty = 0;\n        orderSelectedProducts.forEach(function(id) {\n            var pr = allProducts.find(function(p) { return p.id === id; });\n            if (!pr) return;\n            var baseStyle = pr.style_id.split('-')[0];\n            if (!styles[baseStyle]) {\n                styles[baseStyle] = { name: pr.name, variants: [], image: pr.image_url };\n            }\n            var qty = 0;\n            (pr.colors || []).forEach(function(c) {\n                qty += (qtyMode === 'left_to_sell' ? (c.left_to_sell || 0) : (c.available_now || c.available_qty || 0));\n            });\n            totalQty += qty;\n            styles[baseStyle].variants.push({\n                id: pr.id,\n                style_id: pr.style_id,\n                name: pr.name,\n                qty: qty,\n                colors: (pr.colors || []).map(function(c) { return c.color_name; }).join(', '),\n                image: pr.image_url\n            });\n        });\n\n        var styleKeys = Object.keys(styles);\n\n        // Build HTML\n        var h = '';\n        h += '<div class=\"or-review-header\">';\n        h += '<h2>Review Order Request</h2>';\n        h += '<p>' + styleKeys.length + ' style' + (styleKeys.length !== 1 ? 's' : '') + ' • ' + orderSelectedProducts.length + ' SKU' + (orderSelectedProducts.length !== 1 ? 's' : '') + ' • ' + totalQty.toLocaleString() + ' total units</p>';\n        h += '</div>';\n\n        // Selected products list\n        h += '<div class=\"or-products-list\">';\n        styleKeys.forEach(function(bs) {\n            var s = styles[bs];\n            s.variants.forEach(function(v) {\n                var imgUrl = typeof getImageUrl === 'function' ? getImageUrl(v.image) : v.image;\n                h += '<div class=\"or-product-row\">';\n                h += '<img src=\"' + (imgUrl || '') + '\" onerror=\"this.style.display=\\'none\\'\" class=\"or-product-thumb\">';\n                h += '<div class=\"or-product-info\">';\n                h += '<div class=\"or-product-style\">' + v.style_id + '</div>';\n                h += '<div class=\"or-product-name\">' + v.name + '</div>';\n                if (v.colors) h += '<div class=\"or-product-colors\">' + v.colors + '</div>';\n                h += '</div>';\n                h += '<div class=\"or-product-qty\">' + v.qty.toLocaleString() + ' units</div>';\n                h += '<button class=\"or-remove-btn\" onclick=\"removeFromOrder(' + v.id + ')\">✕</button>';\n                h += '</div>';\n            });\n        });\n        h += '</div>';\n\n        // Order details form\n        h += '<div class=\"or-form-section\">';\n        h += '<h3>Order Details</h3>';\n\n        // Customer dropdown\n        h += '<div class=\"or-field\"><label>Customer / Retailer *</label>';\n        h += '<select id=\"orCustomerSelect\"><option value=\"\">Select a customer...</option></select></div>';\n\n        // Cancel date\n        h += '<div class=\"or-field\"><label>Cancel Date</label>';\n        h += '<input type=\"date\" id=\"orCancelDate\"></div>';\n\n        // Notes\n        h += '<div class=\"or-field\"><label>Notes / Instructions (size breakdowns, ship dates, pricing, etc.)</label>';\n        h += '<textarea id=\"orNotes\" rows=\"6\" placeholder=\"Enter detailed order instructions here...\\n\\nExample:\\nSize breakdown: S-100, M-200, L-200, XL-100\\nShip to DC by March 15\\nFOB pricing per agreement\"></textarea></div>';\n\n        h += '</div>';\n\n        // Actions\n        h += '<div class=\"or-review-actions\">';\n        h += '<button class=\"btn btn-secondary\" onclick=\"closeOrderReview()\">Back to Selection</button>';\n        h += '<button class=\"btn btn-primary\" id=\"orSubmitOrderBtn\" onclick=\"submitOrder()\" style=\"background:#34a853;border-color:#34a853\">Submit Order Request</button>';\n        h += '</div>';\n\n        content.innerHTML = h;\n        overlay.classList.add('active');\n\n        // Load customers\n        loadOrderCustomers();\n    };\n\n    var orderCustomersLoaded = false;\n    var orderCustomerList = [];\n\n    function loadOrderCustomers() {\n        if (orderCustomersLoaded && orderCustomerList.length > 0) {\n            populateCustomerDropdown();\n            return;\n        }\n        fetch('/api/customers').then(function(r) { return r.json(); }).then(function(d) {\n            if (d.success) {\n                orderCustomerList = d.customers.map(function(c) { return c.name; });\n                orderCustomersLoaded = true;\n                populateCustomerDropdown();\n            }\n        }).catch(function(e) { console.error('Error loading customers:', e); });\n    }\n\n    function populateCustomerDropdown() {\n        var sel = document.getElementById('orCustomerSelect');\n        if (!sel) return;\n        var current = sel.value;\n        sel.innerHTML = '<option value=\"\">Select a customer...</option>';\n        orderCustomerList.forEach(function(name) {\n            var opt = document.createElement('option');\n            opt.value = name;\n            opt.textContent = name;\n            sel.appendChild(opt);\n        });\n        if (current) sel.value = current;\n    }\n\n    window.closeOrderReview = function() {\n        var overlay = document.getElementById('orderReviewOverlay');\n        if (overlay) overlay.classList.remove('active');\n    };\n\n    // ---- Submit Order ----\n\n    window.submitOrder = function() {\n        var customer = document.getElementById('orCustomerSelect').value;\n        if (!customer) {\n            alert('Please select a customer');\n            return;\n        }\n        if (orderSelectedProducts.length === 0) {\n            alert('No products selected');\n            return;\n        }\n\n        var cancelDate = document.getElementById('orCancelDate').value || null;\n        var notes = document.getElementById('orNotes').value.trim();\n\n        var btn = document.getElementById('orSubmitOrderBtn');\n        btn.disabled = true;\n        btn.textContent = 'Submitting...';\n\n        fetch('/api/order-requests', {\n            method: 'POST',\n            headers: { 'Content-Type': 'application/json' },\n            body: JSON.stringify({\n                customer_name: customer,\n                product_ids: orderSelectedProducts,\n                cancel_date: cancelDate,\n                notes: notes\n            })\n        }).then(function(r) { return r.json(); }).then(function(d) {\n            btn.disabled = false;\n            btn.textContent = 'Submit Order Request';\n            if (d.success) {\n                showOrderSuccess(d.order);\n            } else {\n                alert('Error: ' + (d.error || 'Unknown error'));\n            }\n        }).catch(function(e) {\n            btn.disabled = false;\n            btn.textContent = 'Submit Order Request';\n            alert('Error: ' + e.message);\n        });\n    };\n\n    function showOrderSuccess(order) {\n        var content = document.getElementById('orderReviewContent');\n        if (!content) return;\n\n        // Build mailto link\n        var detailFullUrl = (order.app_url || window.location.origin) + order.detail_url;\n        var subject = 'Order Request ' + order.request_number + ' - ' + order.customer_name;\n        var body = 'New Order Request: ' + order.request_number + '\\n\\n';\n        body += 'Customer: ' + order.customer_name + '\\n';\n        body += 'Products: ' + (order.product_count || 'N/A') + ' items\\n';\n        if (order.cancel_date) body += 'Cancel Date: ' + order.cancel_date + '\\n';\n        body += 'Submitted by: ' + (order.user_name || 'Unknown') + '\\n';\n        if (order.notes) body += '\\nNotes:\\n' + order.notes + '\\n';\n        body += '\\nView full order details:\\n' + detailFullUrl + '\\n';\n\n        var toEmail = order.notify_email || '';\n        var mailtoUrl = 'mailto:' + encodeURIComponent(toEmail) + '?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body);\n\n        var h = '<div class=\"or-success\">';\n        h += '<div class=\"or-success-icon\">✅</div>';\n        h += '<h2>Order Request Saved!</h2>';\n        h += '<div class=\"or-success-number\">' + order.request_number + '</div>';\n        h += '<p style=\"color:#666;margin:0.5rem 0 1.5rem\">Your order has been saved. Send the details to your order entry team:</p>';\n        h += '<div style=\"display:flex;flex-direction:column;gap:0.75rem;align-items:center\">';\n        h += '<a href=\"' + mailtoUrl + '\" class=\"btn btn-primary\" style=\"background:#0088c2;border-color:#0088c2;text-decoration:none;padding:0.75rem 2rem;font-size:1rem;display:inline-block\">📧 Email Order Details</a>';\n        h += '<a href=\"' + detailFullUrl + '\" target=\"_blank\" class=\"or-detail-link\">View Order Details →</a>';\n        h += '</div>';\n        h += '<button class=\"btn btn-secondary\" onclick=\"finishOrder()\" style=\"margin-top:1.5rem\">Done</button>';\n        h += '</div>';\n        content.innerHTML = h;\n    }\n\n    window.finishOrder = function() {\n        orderMode = false;\n        orderSelectedProducts = [];\n        var btn = document.getElementById('orderModeBtn');\n        if (btn) {\n            btn.textContent = '📋 Create Order';\n            btn.classList.remove('active');\n        }\n        updateOrderBar();\n        closeOrderReview();\n        renderProducts();\n    };\n\n    // ---- Orders List (for viewing past orders) ----\n\n    var ordersCustomersLoaded = false;\n\n    window.toggleOrdersList = function() {\n        var panel = document.getElementById('ordersListPanel');\n        if (!panel) {\n            var main = document.querySelector('.main');\n            if (!main) return;\n            var div = document.createElement('div');\n            div.id = 'ordersListPanel';\n            div.className = 'orders-list-panel';\n            div.innerHTML = '<div class=\"orders-list-header\"><h2>📋 Order Requests</h2><button class=\"btn btn-secondary btn-sm\" onclick=\"closeOrdersList()\">✕ Close</button></div>' +\n                '<div class=\"orders-list-filters\">' +\n                '<select id=\"ordersStatusFilter\" onchange=\"loadOrdersList()\"><option value=\"all\">All Status</option><option value=\"pending\">Pending</option><option value=\"processing\">Processing</option><option value=\"completed\">Completed</option><option value=\"cancelled\">Cancelled</option></select>' +\n                '<select id=\"ordersCustomerFilter\" onchange=\"loadOrdersList()\"><option value=\"all\">All Customers</option></select>' +\n                '<span id=\"ordersResultCount\" style=\"font-size:0.8rem;color:#999;margin-left:0.5rem\"></span>' +\n                '</div>' +\n                '<div id=\"ordersListContent\">Loading...</div>';\n            main.insertBefore(div, main.firstChild);\n            loadOrdersCustomerFilter();\n            loadOrdersList();\n        } else {\n            panel.style.display = panel.style.display === 'none' ? '' : 'none';\n            if (panel.style.display !== 'none') loadOrdersList();\n        }\n    };\n\n    function loadOrdersCustomerFilter() {\n        if (ordersCustomersLoaded) return;\n        fetch('/api/order-requests/customers')\n            .then(function(r) { return r.json(); })\n            .then(function(d) {\n                if (d.success && d.customers) {\n                    var sel = document.getElementById('ordersCustomerFilter');\n                    if (!sel) return;\n                    d.customers.forEach(function(c) {\n                        var opt = document.createElement('option');\n                        opt.value = c;\n                        opt.textContent = c;\n                        sel.appendChild(opt);\n                    });\n                    ordersCustomersLoaded = true;\n                }\n            }).catch(function() {});\n    }\n\n    window.closeOrdersList = function() {\n        var panel = document.getElementById('ordersListPanel');\n        if (panel) panel.style.display = 'none';\n    };\n\n    window.loadOrdersList = function() {\n        var statusEl = document.getElementById('ordersStatusFilter');\n        var customerEl = document.getElementById('ordersCustomerFilter');\n        var status = statusEl ? statusEl.value : 'all';\n        var customer = customerEl ? customerEl.value : 'all';\n        var url = '/api/order-requests?status=' + encodeURIComponent(status);\n        if (customer !== 'all') url += '&customer=' + encodeURIComponent(customer);\n\n        fetch(url)\n            .then(function(r) { return r.json(); })\n            .then(function(d) {\n                var container = document.getElementById('ordersListContent');\n                var countEl = document.getElementById('ordersResultCount');\n                if (!container) return;\n                if (!d.success || !d.orders || d.orders.length === 0) {\n                    container.innerHTML = '<p class=\"or-empty\">No order requests found.</p>';\n                    if (countEl) countEl.textContent = '0 orders';\n                    return;\n                }\n                if (countEl) countEl.textContent = d.orders.length + ' order' + (d.orders.length !== 1 ? 's' : '');\n\n                var h = '';\n                d.orders.forEach(function(o) {\n                    var dt = new Date(o.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' });\n                    h += '<div class=\"or-list-card\">';\n                    h += '<div class=\"or-list-card-header\">';\n                    h += '<span class=\"or-list-num\">' + o.request_number + '</span>';\n                    h += '<span class=\"or-status ' + o.status + '\">' + o.status + '</span>';\n                    h += '</div>';\n                    h += '<div class=\"or-list-card-body\">';\n                    h += '<div class=\"or-list-row\"><span class=\"or-list-label\">Customer</span><span class=\"or-list-val\" style=\"font-weight:700\">' + o.customer_name + '</span></div>';\n                    h += '<div class=\"or-list-row\"><span class=\"or-list-label\">Products</span><span class=\"or-list-val\">' + (o.product_count || 0) + ' items</span></div>';\n                    if (o.cancel_date) {\n                        h += '<div class=\"or-list-row\"><span class=\"or-list-label\">Cancel Date</span><span class=\"or-list-val\">' + new Date(o.cancel_date).toLocaleDateString() + '</span></div>';\n                    }\n                    h += '<div class=\"or-list-row\"><span class=\"or-list-label\">Submitted</span><span class=\"or-list-val\">' + dt + '</span></div>';\n                    h += '<div class=\"or-list-row\"><span class=\"or-list-label\">Rep</span><span class=\"or-list-val\">' + (o.user_name || 'Unknown') + '</span></div>';\n                    if (o.notes) {\n                        var truncNotes = o.notes.length > 150 ? o.notes.substring(0, 150) + '...' : o.notes;\n                        h += '<div class=\"or-list-notes\">' + truncNotes.replace(/</g, '&lt;').replace(/\\n/g, '<br>') + '</div>';\n                    }\n                    if (o.zoho_so_number) {\n                        h += '<div class=\"or-list-so\">Zoho SO: ' + o.zoho_so_number + '</div>';\n                    }\n\n                    // Action buttons row\n                    h += '<div class=\"or-list-actions\">';\n                    if (o.detail_id) {\n                        h += '<a href=\"/order/' + o.detail_id + '\" target=\"_blank\" class=\"or-action-link\">View Details →</a>';\n                        h += '<button class=\"or-action-btn\" onclick=\"reEmailOrder(\\'' + o.request_number + '\\',\\'' + o.customer_name.replace(/'/g, \"\\\\'\") + '\\',' + (o.product_count || 0) + ',\\'' + (o.cancel_date || '').replace(/'/g, \"\\\\'\") + '\\',\\'' + (o.notes || '').replace(/'/g, \"\\\\'\").replace(/\\n/g, '\\\\n') + '\\',\\'/order/' + o.detail_id + '\\')\">📧 Re-send Email</button>';\n                    }\n                    h += '</div>';\n\n                    h += '</div>';\n\n                    // Admin controls\n                    if (o.can_admin && (o.status === 'pending' || o.status === 'processing')) {\n                        h += '<div class=\"or-admin-controls\">';\n                        h += '<input type=\"text\" placeholder=\"Zoho SO #\" id=\"soInput' + o.id + '\" value=\"' + (o.zoho_so_number || '') + '\" class=\"or-admin-input\">';\n                        h += '<input type=\"text\" placeholder=\"Admin note\" id=\"noteInput' + o.id + '\" value=\"' + (o.admin_notes || '') + '\" class=\"or-admin-input\" style=\"flex:1\">';\n                        if (o.status === 'pending') {\n                            h += '<button class=\"or-admin-btn processing\" onclick=\"updateOrderStatus(' + o.id + ',\\'processing\\')\">Processing</button>';\n                        }\n                        h += '<button class=\"or-admin-btn complete\" onclick=\"completeOrderAdmin(' + o.id + ')\">Complete</button>';\n                        h += '<button class=\"or-admin-btn cancel\" onclick=\"updateOrderStatus(' + o.id + ',\\'cancelled\\')\">Cancel</button>';\n                        h += '</div>';\n                    }\n\n                    h += '</div>';\n                });\n                container.innerHTML = h;\n            })\n            .catch(function(e) {\n                console.error('Error loading orders:', e);\n                var container = document.getElementById('ordersListContent');\n                if (container) container.innerHTML = '<p class=\"or-empty\">Error loading orders.</p>';\n            });\n    };\n\n    window.reEmailOrder = function(reqNum, customer, count, cancelDate, notes, detailPath) {\n        var detailFullUrl = window.location.origin + detailPath;\n        var subject = 'Order Request ' + reqNum + ' - ' + customer;\n        var body = 'Order Request: ' + reqNum + '\\n\\n';\n        body += 'Customer: ' + customer + '\\n';\n        body += 'Products: ' + count + ' items\\n';\n        if (cancelDate) body += 'Cancel Date: ' + cancelDate + '\\n';\n        if (notes) body += '\\nNotes:\\n' + notes + '\\n';\n        body += '\\nView full order details:\\n' + detailFullUrl + '\\n';\n        var toEmail = '';\n        try { toEmail = document.querySelector('meta[name=\"notify-email\"]').content; } catch(e) {}\n        window.location.href = 'mailto:' + encodeURIComponent(toEmail) + '?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body);\n    };\n\n    window.updateOrderStatus = function(id, status) {\n        fetch('/api/order-requests/' + id, {\n            method: 'PUT',\n            headers: { 'Content-Type': 'application/json' },\n            body: JSON.stringify({ status: status })\n        }).then(function(r) { return r.json(); }).then(function(d) {\n            if (d.success) loadOrdersList();\n            else alert('Error: ' + d.error);\n        }).catch(function(e) { alert(e.message); });\n    };\n\n    window.completeOrderAdmin = function(id) {\n        var so = document.getElementById('soInput' + id);\n        var note = document.getElementById('noteInput' + id);\n        var soVal = so ? so.value.trim() : '';\n        var noteVal = note ? note.value.trim() : '';\n\n        fetch('/api/order-requests/' + id, {\n            method: 'PUT',\n            headers: { 'Content-Type': 'application/json' },\n            body: JSON.stringify({\n                status: 'completed',\n                zoho_so_number: soVal || null,\n                admin_notes: noteVal || null\n            })\n        }).then(function(r) { return r.json(); }).then(function(d) {\n            if (d.success) loadOrdersList();\n            else alert('Error: ' + d.error);\n        }).catch(function(e) { alert(e.message); });\n    };\n})();\n";

app.get('/order-requests.css', function(req, res) {
    res.setHeader('Content-Type', 'text/css');
    res.send(orderRequestsCSS);
});

app.get('/order-requests.js', function(req, res) {
    res.setHeader('Content-Type', 'application/javascript');
    res.send(orderRequestsJS);
});

// ═══ ENHANCED SIDEBAR FILES ═══
app.get('/sidebar-enhanced.css', function(req, res) {
    res.setHeader('Content-Type', 'text/css');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.sendFile(require('path').join(__dirname, 'sidebar-enhanced.css'));
});

app.get('/sidebar-enhanced.js', function(req, res) {
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.sendFile(require('path').join(__dirname, 'sidebar-enhanced.js'));
});

async function getNextRequestNumber() {
    var result = await pool.query("SELECT request_number FROM order_requests ORDER BY id DESC LIMIT 1");
    if (result.rows.length === 0) return 'OR-0001';
    var last = result.rows[0].request_number;
    var num = parseInt(last.replace('OR-', '')) + 1;
    return 'OR-' + num.toString().padStart(4, '0');
}

function generateOrderDetailId() {
    return 'ord_' + Math.random().toString(36).substr(2, 12);
}

// Create order request
app.post('/api/order-requests', requireAuth, async function(req, res) {
    try {
        var requestNumber = await getNextRequestNumber();
        var b = req.body;
        if (!b.customer_name || !b.product_ids || b.product_ids.length === 0) {
            return res.json({ success: false, error: 'Customer and products are required' });
        }
        var detailId = generateOrderDetailId();

        // Look up style_ids from product IDs so orders survive CSV reimports
        var styleResult = await pool.query(
            "SELECT id, style_id FROM products WHERE id = ANY($1)",
            [b.product_ids]
        );
        var styleIds = styleResult.rows.map(function(r) { return r.style_id; });

        var result = await pool.query(
            "INSERT INTO order_requests (request_number, detail_id, user_id, user_name, customer_name, product_ids, product_count, cancel_date, notes, status, style_ids) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10) RETURNING *",
            [requestNumber, detailId, req.session.userId, req.session.userName || 'Unknown',
             b.customer_name, JSON.stringify(b.product_ids), b.product_ids.length,
             b.cancel_date || null, b.notes || null, JSON.stringify(styleIds)]
        );
        var order = result.rows[0];
        order.detail_url = '/order/' + detailId;
        order.notify_email = process.env.ORDER_NOTIFY_EMAIL || '';
        order.app_url = (process.env.APP_URL || 'https://product-catalog-production-682f.up.railway.app');

        res.json({ success: true, order: order });
    } catch (err) {
        console.error('Create order request error:', err);
        res.json({ success: false, error: err.message });
    }
});

// Get distinct customers from order requests (for filter dropdown)
app.get('/api/order-requests/customers', requireAuth, async function(req, res) {
    try {
        var isAdmin = req.session.role === 'admin';
        var query = "SELECT DISTINCT customer_name FROM order_requests";
        var params = [];
        if (!isAdmin) {
            query += " WHERE user_id = $1";
            params.push(req.session.userId);
        }
        query += " ORDER BY customer_name";
        var result = await pool.query(query, params);
        res.json({ success: true, customers: result.rows.map(function(r) { return r.customer_name; }) });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// Get order requests
app.get('/api/order-requests', requireAuth, async function(req, res) {
    try {
        var status = req.query.status || 'all';
        var isAdmin = req.session.role === 'admin';
        var query = "SELECT * FROM order_requests";
        var params = [];
        var conditions = [];

        if (!isAdmin) {
            conditions.push("user_id = $" + (params.length + 1));
            params.push(req.session.userId);
        }
        if (status !== 'all') {
            conditions.push("status = $" + (params.length + 1));
            params.push(status);
        }
        if (req.query.customer && req.query.customer !== 'all') {
            conditions.push("customer_name = $" + (params.length + 1));
            params.push(req.query.customer);
        }
        if (conditions.length > 0) query += " WHERE " + conditions.join(" AND ");
        query += " ORDER BY created_at DESC";

        var result = await pool.query(query, params);
        var orders = result.rows.map(function(o) {
            o.can_admin = isAdmin;
            o.product_ids = typeof o.product_ids === 'string' ? JSON.parse(o.product_ids) : o.product_ids;
            return o;
        });
        res.json({ success: true, orders: orders });
    } catch (err) {
        console.error('Get order requests error:', err);
        res.json({ success: false, error: err.message });
    }
});

// Update order request (admin)
app.put('/api/order-requests/:id', requireAuth, async function(req, res) {
    try {
        if (req.session.role !== 'admin') return res.json({ success: false, error: 'Admin required' });
        var b = req.body;
        var updates = ["updated_at = CURRENT_TIMESTAMP"];
        var params = [];
        var idx = 1;

        if (b.status) { updates.push("status = $" + idx); params.push(b.status); idx++; }
        if (b.zoho_so_number !== undefined) { updates.push("zoho_so_number = $" + idx); params.push(b.zoho_so_number); idx++; }
        if (b.admin_notes !== undefined) { updates.push("admin_notes = $" + idx); params.push(b.admin_notes); idx++; }

        params.push(parseInt(req.params.id));
        var result = await pool.query("UPDATE order_requests SET " + updates.join(", ") + " WHERE id = $" + idx + " RETURNING *", params);
        if (result.rows.length === 0) return res.json({ success: false, error: 'Not found' });
        res.json({ success: true, order: result.rows[0] });
    } catch (err) {
        console.error('Update order request error:', err);
        res.json({ success: false, error: err.message });
    }
});

// Order detail page (public - accessed via link from email)
app.get('/order/:detailId', async function(req, res) {
    try {
        var result = await pool.query("SELECT * FROM order_requests WHERE detail_id = $1", [req.params.detailId]);
        if (result.rows.length === 0) return res.status(404).send('Order not found');
        var order = result.rows[0];
        var products = [];

        // Try style_ids first (stable across CSV reimports), then fall back to product_ids
        var styleIds = order.style_ids ? (typeof order.style_ids === 'string' ? JSON.parse(order.style_ids) : order.style_ids) : null;
        if (styleIds && styleIds.length > 0) {
            var productsResult = await pool.query(
                "SELECT p.id, p.style_id, p.base_style, p.name, p.category, p.image_url, json_agg(json_build_object('color_name', pc.color_name, 'available_qty', pc.available_qty, 'available_now', pc.available_now, 'left_to_sell', pc.left_to_sell)) FILTER (WHERE pc.id IS NOT NULL) as colors FROM products p LEFT JOIN product_colors pc ON p.id = pc.product_id WHERE p.style_id = ANY($1) GROUP BY p.id ORDER BY p.name",
                [styleIds]
            );
            products = productsResult.rows;
        }

        // Fall back to product_ids if style_ids didn't work
        if (products.length === 0) {
            var productIds = typeof order.product_ids === 'string' ? JSON.parse(order.product_ids) : order.product_ids;
            if (productIds && productIds.length > 0) {
                var productsResult = await pool.query(
                    "SELECT p.id, p.style_id, p.base_style, p.name, p.category, p.image_url, json_agg(json_build_object('color_name', pc.color_name, 'available_qty', pc.available_qty, 'available_now', pc.available_now, 'left_to_sell', pc.left_to_sell)) FILTER (WHERE pc.id IS NOT NULL) as colors FROM products p LEFT JOIN product_colors pc ON p.id = pc.product_id WHERE p.id = ANY($1) GROUP BY p.id ORDER BY p.name",
                    [productIds]
                );
                products = productsResult.rows;
            }
        }

        res.send(getOrderDetailHTML(order, products));
    } catch (err) {
        console.error('Order detail page error:', err);
        res.status(500).send('Error loading order');
    }
});

// Email notification
async function sendOrderRequestEmail(order) {
    if (!process.env.RESEND_API_KEY) {
        console.log('ORDER EMAIL WOULD SEND:', order.request_number);
        return { success: true, simulated: true };
    }
    var notifyEmail = process.env.ORDER_NOTIFY_EMAIL;
    if (!notifyEmail) {
        console.log('ORDER_NOTIFY_EMAIL not configured');
        return { success: false, error: 'not configured' };
    }
    try {
        var detailUrl = (process.env.APP_URL || 'https://product-catalog-production-682f.up.railway.app') + '/order/' + order.detail_id;

        var emailHtml = '<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">' +
            '<div style="background:#1a1a2e;color:white;padding:30px;text-align:center;border-radius:10px 10px 0 0;">' +
            '<h1 style="margin:0;font-size:24px;">New Order Request</h1>' +
            '<p style="margin:10px 0 0;opacity:0.8;">' + order.request_number + '</p></div>' +
            '<div style="background:#f9f9f9;padding:30px;border:1px solid #ddd;">' +
            '<table style="width:100%;border-collapse:collapse;font-size:15px;">' +
            '<tr><td style="padding:10px 0;color:#666;font-weight:bold;width:140px">Sales Rep:</td><td>' + (order.user_name || 'Unknown') + '</td></tr>' +
            '<tr><td style="padding:10px 0;color:#666;font-weight:bold">Customer:</td><td style="font-weight:bold;font-size:17px">' + order.customer_name + '</td></tr>' +
            '<tr><td style="padding:10px 0;color:#666;font-weight:bold">Products:</td><td>' + order.product_count + ' items</td></tr>' +
            (order.cancel_date ? '<tr><td style="padding:10px 0;color:#666;font-weight:bold">Cancel Date:</td><td>' + new Date(order.cancel_date).toLocaleDateString() + '</td></tr>' : '') +
            (order.notes ? '<tr><td style="padding:10px 0;color:#666;font-weight:bold;vertical-align:top">Notes:</td><td style="background:#fff8e1;border-radius:4px;padding:10px;white-space:pre-wrap">' + order.notes.replace(/</g, '&lt;') + '</td></tr>' : '') +
            '</table>' +
            '<div style="text-align:center;margin-top:20px"><a href="' + detailUrl + '" style="display:inline-block;background:#34a853;color:white;padding:12px 30px;text-decoration:none;border-radius:6px;font-weight:bold">View Full Order Details →</a></div>' +
            '</div>' +
            '<div style="text-align:center;padding:15px;color:#999;font-size:12px"><p>Mark Edwards Apparel | Order Request System</p></div><script src="https://monitor.markedwards.cloud/tracker.js" defer><\/script></body></html>';

        var response = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + process.env.RESEND_API_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                from: process.env.EMAIL_FROM || 'Mark Edwards Apparel <catalog@markedwardsapparel.com>',
                to: notifyEmail.split(',').map(function(e) { return e.trim(); }),
                subject: 'New Order Request ' + order.request_number + ' - ' + order.customer_name + ' (' + order.product_count + ' items)',
                html: emailHtml
            })
        });
        var result = await response.json();
        console.log('Order email:', order.request_number, response.ok ? 'OK' : 'FAILED');
        return { success: response.ok, data: result };
    } catch (err) {
        console.error('Order email error:', err);
        return { success: false, error: err.message };
    }
}

// Order detail page HTML
function getOrderDetailHTML(order, products) {
    var statusColors = { pending: '#856404', processing: '#004085', completed: '#155724', cancelled: '#721c24' };
    var statusBgs = { pending: '#fff3cd', processing: '#cce5ff', completed: '#d4edda', cancelled: '#f8d7da' };

    var html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Order ' + order.request_number + ' - Mark Edwards Apparel</title>';
    html += '<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f7;color:#1d1d1f}';
    html += '.container{max-width:900px;margin:0 auto;padding:2rem 1rem}';
    html += '.header{background:#1a1a2e;color:white;padding:2rem;border-radius:16px 16px 0 0;text-align:center}';
    html += '.header h1{font-size:1.5rem;margin-bottom:0.5rem}';
    html += '.header .order-num{font-size:2rem;font-weight:700;letter-spacing:1px}';
    html += '.status-badge{display:inline-block;padding:4px 16px;border-radius:20px;font-size:0.85rem;font-weight:600;text-transform:uppercase;margin-top:0.75rem}';
    html += '.details{background:white;padding:2rem;border:1px solid #e0e0e0}';
    html += '.detail-row{display:flex;justify-content:space-between;padding:0.75rem 0;border-bottom:1px solid #f0f0f0}';
    html += '.detail-label{color:#666;font-weight:600}';
    html += '.detail-val{font-weight:500;text-align:right}';
    html += '.notes-box{margin-top:1rem;padding:1rem;background:#fff8e1;border-radius:10px;border:1px solid #ffe082;white-space:pre-wrap;font-size:0.95rem;line-height:1.6}';
    html += '.products-section{background:white;padding:2rem;border:1px solid #e0e0e0;border-radius:0 0 16px 16px}';
    html += '.products-section h2{margin-bottom:1rem;color:#1e3a5f;font-size:1.2rem}';
    html += '.product-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:1rem}';
    html += '.p-card{border:1px solid #eee;border-radius:12px;overflow:hidden;background:white}';
    html += '.p-card img{width:100%;height:180px;object-fit:contain;background:#f8f8f8}';
    html += '.p-card-info{padding:0.75rem}';
    html += '.p-card-style{font-size:0.8rem;color:#0088c2;font-weight:600}';
    html += '.p-card-name{font-size:0.9rem;font-weight:500;color:#1e3a5f;margin:0.25rem 0}';
    html += '.p-card-colors{font-size:0.75rem;color:#666}';
    html += '.p-card-qty{font-size:0.85rem;font-weight:700;color:#1e3a5f;margin-top:0.5rem}';
    html += '.footer{text-align:center;padding:1.5rem;color:#999;font-size:0.8rem}';
    html += '@media(max-width:600px){.product-grid{grid-template-columns:repeat(auto-fill,minmax(150px,1fr))}}</style><link rel="stylesheet" href="/sidebar-enhanced.css"></head><body>';

    html += '<div class="container">';
    html += '<div class="header"><h1>Order Request</h1>';
    html += '<div class="order-num">' + order.request_number + '</div>';
    html += '<span class="status-badge" style="background:' + (statusBgs[order.status] || '#eee') + ';color:' + (statusColors[order.status] || '#333') + '">' + order.status + '</span>';
    html += '</div>';

    html += '<div class="details">';
    html += '<div class="detail-row"><span class="detail-label">Customer</span><span class="detail-val">' + order.customer_name + '</span></div>';
    html += '<div class="detail-row"><span class="detail-label">Sales Rep</span><span class="detail-val">' + (order.user_name || 'Unknown') + '</span></div>';
    html += '<div class="detail-row"><span class="detail-label">Products</span><span class="detail-val">' + products.length + ' items</span></div>';
    if (order.cancel_date) {
        html += '<div class="detail-row"><span class="detail-label">Cancel Date</span><span class="detail-val">' + new Date(order.cancel_date).toLocaleDateString() + '</span></div>';
    }
    html += '<div class="detail-row"><span class="detail-label">Submitted</span><span class="detail-val">' + new Date(order.created_at).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }) + '</span></div>';
    if (order.zoho_so_number) {
        html += '<div class="detail-row"><span class="detail-label">Zoho SO#</span><span class="detail-val" style="color:#2e7d32;font-weight:700">' + order.zoho_so_number + '</span></div>';
    }
    if (order.notes) {
        html += '<div style="margin-top:1rem"><span class="detail-label">Notes / Instructions:</span>';
        html += '<div class="notes-box">' + order.notes.replace(/</g, '&lt;') + '</div></div>';
    }
    if (order.admin_notes) {
        html += '<div style="margin-top:1rem"><span class="detail-label">Admin Notes:</span>';
        html += '<div style="padding:1rem;background:#e8f5e9;border-radius:10px;border:1px solid #c8e6c9;margin-top:0.5rem">' + order.admin_notes.replace(/</g, '&lt;') + '</div></div>';
    }
    html += '</div>';

    // Products
    html += '<div class="products-section"><h2>Selected Products (' + products.length + ')</h2>';
    html += '<div class="product-grid">';
    products.forEach(function(p) {
        var colors = p.colors || [];
        var totalQty = 0;
        colors.forEach(function(c) { totalQty += (c.left_to_sell || c.available_qty || 0); });
        var colorNames = colors.map(function(c) { return c.color_name; }).filter(Boolean);

        var imgUrl = p.image_url;
        if (imgUrl && imgUrl.indexOf('http') !== 0) {
            imgUrl = '/api/product-image/' + encodeURIComponent(imgUrl);
        }

        html += '<div class="p-card">';
        if (imgUrl) html += '<img src="' + imgUrl + '" onerror="this.style.display=\'none\'">';
        html += '<div class="p-card-info">';
        html += '<div class="p-card-style">' + p.style_id + '</div>';
        html += '<div class="p-card-name">' + p.name + '</div>';
        if (colorNames.length > 0) {
            html += '<div class="p-card-colors">' + colorNames.join(', ') + '</div>';
        }
        html += '<div class="p-card-qty">' + totalQty.toLocaleString() + ' units available</div>';
        html += '</div></div>';
    });
    html += '</div></div>';

    html += '<div class="footer"><p>Mark Edwards Apparel • Order Request System</p></div>';
    html += '</div></body></html>';
    return html;
}

// Get styles for selected customers
app.get('/api/styles-by-customers', async function(req, res) {
    try {
        var customers = req.query.customers; // comma-separated list
        if (!customers) {
            return res.json({ success: true, styles: [] });
        }
        var customerList = customers.split(',').map(function(c) { return c.trim(); });
        var placeholders = customerList.map(function(_, i) { return '$' + (i + 1); }).join(',');
        var result = await pool.query(`
            SELECT DISTINCT base_style 
            FROM sales_data 
            WHERE document_type IN ('Sales Order', 'SO', 'Invoice') 
              AND customer_vendor IN (${placeholders})
              AND base_style IS NOT NULL
        `, customerList);
        res.json({
            success: true,
            styles: result.rows.map(function(r) { return r.base_style; })
        });
    } catch (err) {
        console.error('Styles by customers error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Get customer scorecard for merchandising tab
app.get('/api/merchandising/customer-scorecard/:customer', async function(req, res) {
    try {
        var customerName = decodeURIComponent(req.params.customer);

        // Get total categories available
        var totalCatsResult = await pool.query(`
            SELECT COUNT(DISTINCT category) as total FROM products WHERE category IS NOT NULL
        `);
        var totalCategories = parseInt(totalCatsResult.rows[0].total) || 0;

        // Get customer's order data with category breakdown
        var orderData = await pool.query(`
            SELECT
                p.category,
                COUNT(DISTINCT p.base_style) as styles,
                COUNT(DISTINCT sd.line_item_sku) as colors,
                COALESCE(SUM(sd.quantity), 0) as total_units,
                COALESCE(SUM(sd.amount), 0) as total_dollars
            FROM sales_data sd
            JOIN products p ON p.base_style = sd.base_style
            WHERE sd.customer_vendor = $1
              AND sd.document_type IN ('Sales Order', 'SO', 'Invoice')
            GROUP BY p.category
            ORDER BY total_dollars DESC
        `, [customerName]);

        var categoriesRepresented = orderData.rows.length;
        var totalStyles = 0;
        var totalColors = 0;
        var totalUnits = 0;
        var totalDollars = 0;
        var topCategories = [];

        orderData.rows.forEach(function(row) {
            totalStyles += parseInt(row.styles) || 0;
            totalColors += parseInt(row.colors) || 0;
            totalUnits += parseInt(row.total_units) || 0;
            totalDollars += parseFloat(row.total_dollars) || 0;
            topCategories.push({
                category: row.category,
                styles: parseInt(row.styles) || 0,
                units: parseInt(row.total_units) || 0,
                dollars: parseFloat(row.total_dollars) || 0
            });
        });

        var breadthScore = totalCategories > 0 ? Math.round((categoriesRepresented / totalCategories) * 100) : 0;
        var healthIndicator = breadthScore >= 60 ? 'strong' : (breadthScore >= 30 ? 'moderate' : 'opportunity');

        res.json({
            success: true,
            customer: customerName,
            categoriesRepresented: categoriesRepresented,
            totalCategories: totalCategories,
            totalStyles: totalStyles,
            totalColors: totalColors,
            totalUnits: totalUnits,
            totalDollars: totalDollars,
            breadthScore: breadthScore,
            healthIndicator: healthIndicator,
            topCategories: topCategories.slice(0, 5)
        });
    } catch (err) {
        console.error('Customer scorecard error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Get styles for selected suppliers
app.get('/api/styles-by-suppliers', async function(req, res) {
    try {
        var suppliers = req.query.suppliers; // comma-separated list
        if (!suppliers) {
            return res.json({ success: true, styles: [] });
        }
        var supplierList = suppliers.split(',').map(function(s) { return s.trim(); });
        var placeholders = supplierList.map(function(_, i) { return '$' + (i + 1); }).join(',');
        var result = await pool.query(`
            SELECT DISTINCT base_style 
            FROM sales_data 
            WHERE document_type IN ('Purchase Order', 'PO', 'Bill') 
              AND customer_vendor IN (${placeholders})
              AND base_style IS NOT NULL
        `, supplierList);
        res.json({
            success: true,
            styles: result.rows.map(function(r) { return r.base_style; })
        });
    } catch (err) {
        console.error('Styles by suppliers error:', err);
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
                                    documentId: inv.invoice_id,
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
                                    documentId: inv2.invoice_id,
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
                                    documentId: so.salesorder_id,
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
                                    documentId: so2.salesorder_id,
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
                                    documentId: po.purchaseorder_id,
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
                                    documentId: po2.purchaseorder_id,
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
                // Only count open POs in tile summary
                if (results[n].isOpen) {
                    totalPOQty += results[n].quantity;
                    totalPODollars += results[n].amount || 0;
                    poCount++;
                }
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

// Zoho document deep link - looks up document by number and redirects to Zoho Books
app.get('/api/zoho-link/:type/:docNumber', requireAuth, async function(req, res) {
    try {
        var type = req.params.type; // purchaseorder, salesorder, invoice
        var docNumber = req.params.docNumber;
        var orgId = process.env.ZOHO_BOOKS_ORG_ID || '677681121';
        
        if (!zohoAccessToken) await refreshZohoToken();
        if (!zohoAccessToken) return res.json({ success: false, error: 'No Zoho token' });
        
        var apiPath, idField, numberField;
        if (type === 'purchaseorder') {
            apiPath = 'purchaseorders';
            idField = 'purchaseorder_id';
            numberField = 'purchaseorder_number';
        } else if (type === 'salesorder') {
            apiPath = 'salesorders';
            idField = 'salesorder_id';
            numberField = 'salesorder_number';
        } else if (type === 'invoice') {
            apiPath = 'invoices';
            idField = 'invoice_id';
            numberField = 'invoice_number';
        } else {
            return res.json({ success: false, error: 'Invalid type' });
        }
        
        // Search by document number
        var searchUrl = 'https://www.zohoapis.com/books/v3/' + apiPath + '?organization_id=' + orgId + '&search_text=' + encodeURIComponent(docNumber);
        var response = await fetch(searchUrl, {
            headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken }
        });
        
        if (response.status === 401) {
            await refreshZohoToken();
            response = await fetch(searchUrl, {
                headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken }
            });
        }
        
        var data = await response.json();
        var docs = data[apiPath] || [];
        
        // Find exact match by document number
        var match = docs.find(function(d) { return d[numberField] === docNumber; });
        
        if (match) {
            var zohoUrl = 'https://inventory.zoho.com/app/' + orgId + '#/' + apiPath + '/' + match[idField];
            return res.json({ success: true, url: zohoUrl });
        }
        
        // Fallback: return list page
        return res.json({ success: false, url: 'https://inventory.zoho.com/app/' + orgId + '#/' + apiPath, error: 'Document not found' });
    } catch (err) {
        console.error('Zoho link error:', err.message);
        res.json({ success: false, error: err.message, url: 'https://inventory.zoho.com/app/677681121#/' + (req.params.type === 'purchaseorder' ? 'purchaseorders' : req.params.type === 'salesorder' ? 'salesorders' : 'invoices') });
    }
});

function parseCSVLine(line) { var result = []; var current = ''; var inQuotes = false; for (var i = 0; i < line.length; i++) { var char = line[i]; if (char === '"') { inQuotes = !inQuotes; } else if (char === ',' && !inQuotes) { result.push(current.trim()); current = ''; } else { current += char; } } result.push(current.trim()); return result; }
function parseNumber(val) { if (!val) return 0; return parseInt(val.toString().replace(/,/g, '').replace(/"/g, '').trim()) || 0; }

app.post('/api/import', requireAuth, requireAdmin, upload.single('file'), async function(req, res) {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

        var content = req.file.buffer.toString('utf-8');
        var filename = req.file.originalname || 'uploaded.csv';

        console.log('Manual CSV import - filename:', filename, 'size:', content.length, 'bytes');

        // Use the same processInventoryCSV function as auto-import
        var result = await processInventoryCSV(content, filename);

        if (result.success) {
            console.log('Import successful:', result.imported, 'records, fileType:', result.fileType);
            res.json({
                success: true,
                imported: result.imported,
                skipped: result.skipped,
                newArrivals: result.newArrivals,
                fileType: result.fileType
            });
        } else {
            console.log('Import failed:', result.error);
            res.status(400).json({ error: result.error || 'Unknown import error' });
        }
    } catch (err) {
        console.error('Import error:', err.message, err.stack);
        res.status(500).json({ error: err.message || 'Server error during import' });
    }
});

app.post('/api/products/clear', requireAuth, requireAdmin, async function(req, res) { try { await pool.query('DELETE FROM product_sizes'); await pool.query('DELETE FROM product_colors'); await pool.query('DELETE FROM products'); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); } });

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
        var inWarehouseIdx = colMap['in_warehouse_date'];
        var custIdx = colMap['customer_vendor'];
        var skuIdx = colMap['line_item_sku'];
        var styleIdx = colMap['line_item_style'];
        var statusIdx = colMap['status'];
        var qtyIdx = colMap['quantity'];
        var amtIdx = colMap['amount'];
        
        if (docTypeIdx === undefined || docNumIdx === undefined) {
            return res.json({ success: false, error: 'Missing required columns: document_type, document_number' });
        }
        
        // Load existing document_number + line_item_sku combos to skip duplicates
        console.log('Loading existing records to check for duplicates...');
        var existingResult = await pool.query('SELECT document_number, line_item_sku FROM sales_data');
        var existingKeys = new Set();
        existingResult.rows.forEach(function(row) {
            existingKeys.add(row.document_number + '|' + row.line_item_sku);
        });
        console.log('Found', existingKeys.size, 'existing records');
        
        // NO DELETE - we append instead of replacing
        // Skip records that already exist
        
        var imported = 0;
        var skipped = 0;
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
                var inWarehouseRaw = inWarehouseIdx !== undefined ? row[inWarehouseIdx] || '' : '';
                // Parse in_warehouse_date - format is "11 May, 2025 00:00:00"
                var inWarehouseDate = null;
                if (inWarehouseRaw) {
                    try {
                        var parsed = new Date(inWarehouseRaw.replace(/,/g, ''));
                        if (!isNaN(parsed.getTime())) {
                            inWarehouseDate = parsed.toISOString().split('T')[0];
                        }
                    } catch (e) { }
                }
                var customer = row[custIdx] || '';
                var sku = skuIdx !== undefined ? row[skuIdx] || '' : '';
                var style = styleIdx !== undefined ? row[styleIdx] || '' : '';
                var status = statusIdx !== undefined ? row[statusIdx] || '' : '';
                var qty = qtyIdx !== undefined ? parseFloat((row[qtyIdx] || '0').replace(/,/g, '')) || 0 : 0;
                var amt = amtIdx !== undefined ? parseFloat((row[amtIdx] || '0').replace(/,/g, '')) || 0 : 0;
                
                // Extract base style (e.g., "80414J-AA" -> "80414J")
                var baseStyle = style ? style.split('-')[0] : (sku ? sku.split('-')[0] : '');
                
                if (docType && docNum && baseStyle) {
                    // Check if this record already exists
                    var key = docNum + '|' + sku;
                    if (existingKeys.has(key)) {
                        skipped++;
                    } else {
                        batch.push([docType, docNum, docDate, inWarehouseDate, customer, sku, baseStyle, status, qty, amt]);
                        existingKeys.add(key); // Add to set so we don't duplicate within same file
                    
                        if (batch.length >= batchSize) {
                            // Batch insert
                            var values = [];
                            var placeholders = [];
                            var paramIdx = 1;
                            for (var b = 0; b < batch.length; b++) {
                                var item = batch[b];
                                placeholders.push('($' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ')');
                                values = values.concat(item);
                            }
                            await pool.query('INSERT INTO sales_data (document_type, document_number, doc_date, in_warehouse_date, customer_vendor, line_item_sku, base_style, status, quantity, amount) VALUES ' + placeholders.join(','), values);
                            imported += batch.length;
                            batch = [];
                        }
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
                placeholders.push('($' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ',$' + paramIdx++ + ')');
                values = values.concat(item);
            }
            await pool.query('INSERT INTO sales_data (document_type, document_number, doc_date, in_warehouse_date, customer_vendor, line_item_sku, base_style, status, quantity, amount) VALUES ' + placeholders.join(','), values);
            imported += batch.length;
        }
        
        // Log to sync history
        await pool.query('INSERT INTO sync_history (sync_type, status, records_synced) VALUES ($1, $2, $3)', ['sales_import', 'success', imported]);

        // Report freshness to admin panel
        await reportDataFreshness('Sales Data', imported, 'Sales CSV import');

        // Track granular freshness
        try {
            await pool.query("INSERT INTO data_freshness_detail (data_type, last_updated, record_count, file_name) VALUES ('sales_orders_pos', CURRENT_TIMESTAMP, $1, 'manual upload') ON CONFLICT (data_type) DO UPDATE SET last_updated = CURRENT_TIMESTAMP, record_count = $1, file_name = 'manual upload'", [imported]);
        } catch (freshErr) { console.error('Error tracking sales freshness detail:', freshErr.message); }

        console.log('Sales data import complete:', imported, 'new records imported,', skipped, 'duplicates skipped,', errors, 'errors');
        res.json({ success: true, imported: imported, skipped: skipped, errors: errors });
    } catch (err) {
        console.error('Sales import error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users', requireAuth, requireAdmin, async function(req, res) { try { var result = await pool.query('SELECT id, username, display_name, pin, role, created_at FROM users ORDER BY display_name'); res.json(result.rows); } catch (err) { res.status(500).json({ error: err.message }); } });

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

app.post('/api/sales-data/clear', requireAuth, requireAdmin, async function(req, res) {
    try {
        // Drop unique index if exists
        try { await pool.query('DROP INDEX IF EXISTS idx_sales_data_unique'); } catch (e) {}
        // Clear all sales data
        await pool.query('DELETE FROM sales_data');
        // Recreate unique index
        await pool.query('CREATE UNIQUE INDEX idx_sales_data_unique ON sales_data(document_number, line_item_sku)');
        console.log('Sales data cleared and unique index created');
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// Get open sales orders and import POs by style for Supply vs Demand calculation
app.get('/api/open-orders-by-style', requireAuth, async function(req, res) {
    try {
        // Get all sales data grouped by style, document type, and status
        var result = await pool.query(`
            SELECT
                base_style,
                document_type,
                LOWER(status) as status,
                SUM(quantity) as total_qty
            FROM sales_data
            GROUP BY base_style, document_type, LOWER(status)
        `);

        var openOrdersByStyle = {};
        var importPOsByStyle = {};

        result.rows.forEach(function(row) {
            if (!row.base_style) return;

            var docType = (row.document_type || '').toLowerCase();
            var status = row.status || '';
            var qty = parseInt(row.total_qty) || 0;

            if (docType.indexOf('purchase') !== -1) {
                // Purchase Orders - only count OPEN ones
                if (status === 'open') {
                    if (!importPOsByStyle[row.base_style]) importPOsByStyle[row.base_style] = 0;
                    importPOsByStyle[row.base_style] += qty;
                }
            } else if (docType.indexOf('sales') !== -1) {
                // Sales Orders - only count OPEN ones
                if (status === 'open') {
                    if (!openOrdersByStyle[row.base_style]) openOrdersByStyle[row.base_style] = 0;
                    openOrdersByStyle[row.base_style] += qty;
                }
            }
        });

        console.log('Loaded open orders for', Object.keys(openOrdersByStyle).length, 'styles');
        console.log('Loaded import POs for', Object.keys(importPOsByStyle).length, 'styles');
        res.json({ success: true, openOrders: openOrdersByStyle, importPOs: importPOsByStyle });
    } catch (err) {
        console.error('Error fetching open orders:', err);
        res.json({ success: false, error: err.message });
    }
});

// Get category mix data for merchandising tab
app.get('/api/merchandising/category-mix', async function(req, res) {
    try {
        // Get category data with inventory and sales metrics
        var result = await pool.query(`
            SELECT
                p.category,
                COUNT(DISTINCT p.base_style) as style_count,
                COALESCE(SUM(c.left_to_sell), 0) as total_left_to_sell,
                COALESCE(SUM(c.available_now), 0) as total_available_now
            FROM products p
            LEFT JOIN product_colors c ON c.product_id = p.id
            WHERE p.category IS NOT NULL
            GROUP BY p.category
            ORDER BY total_left_to_sell DESC
        `);

        // Get sales data per category
        var salesResult = await pool.query(`
            SELECT
                p.category,
                COALESCE(SUM(CASE WHEN sd.document_type IN ('Sales Order', 'SO') THEN sd.quantity ELSE 0 END), 0) as open_orders,
                COALESCE(SUM(CASE WHEN sd.document_type IN ('Sales Order', 'SO') THEN sd.amount ELSE 0 END), 0) as open_orders_dollars,
                COALESCE(SUM(CASE WHEN sd.document_type IN ('Purchase Order', 'PO', 'Bill') THEN sd.quantity ELSE 0 END), 0) as import_pos,
                COALESCE(SUM(CASE WHEN sd.document_type IN ('Purchase Order', 'PO', 'Bill') THEN sd.amount ELSE 0 END), 0) as import_pos_dollars
            FROM sales_data sd
            JOIN products p ON p.base_style = sd.base_style
            WHERE p.category IS NOT NULL
            GROUP BY p.category
        `);

        var salesByCategory = {};
        salesResult.rows.forEach(function(row) {
            salesByCategory[row.category] = {
                openOrders: parseInt(row.open_orders) || 0,
                openOrdersDollars: parseFloat(row.open_orders_dollars) || 0,
                importPOs: parseInt(row.import_pos) || 0,
                importPOsDollars: parseFloat(row.import_pos_dollars) || 0
            };
        });

        // Calculate totals for percentages
        var totalLeftToSell = 0;
        result.rows.forEach(function(row) {
            totalLeftToSell += parseInt(row.total_left_to_sell) || 0;
        });

        var categories = result.rows.map(function(row) {
            var leftToSell = parseInt(row.total_left_to_sell) || 0;
            var sales = salesByCategory[row.category] || { openOrders: 0, openOrdersDollars: 0, importPOs: 0, importPOsDollars: 0 };
            var mixPercentage = totalLeftToSell > 0 ? (leftToSell / totalLeftToSell * 100) : 0;

            return {
                category: row.category,
                styleCount: parseInt(row.style_count) || 0,
                leftToSell: leftToSell,
                availableNow: parseInt(row.total_available_now) || 0,
                openOrders: sales.openOrders,
                openOrdersDollars: sales.openOrdersDollars,
                importPOs: sales.importPOs,
                importPOsDollars: sales.importPOsDollars,
                mixPercentage: Math.round(mixPercentage * 10) / 10,
                overIndexed: mixPercentage > 15
            };
        });

        res.json({
            success: true,
            categories: categories,
            totalLeftToSell: totalLeftToSell
        });
    } catch (err) {
        console.error('Error fetching category mix:', err);
        res.json({ success: false, error: err.message });
    }
});

// Fix duplicate sales data and recreate unique index
app.post('/api/sales-data/fix-duplicates', requireAuth, requireAdmin, async function(req, res) {
    try {
        console.log('Starting sales data duplicate fix...');
        
        // Count duplicates first
        var dupCount = await pool.query(`
            SELECT COUNT(*) as count FROM (
                SELECT document_number, line_item_sku, COUNT(*) as cnt 
                FROM sales_data 
                GROUP BY document_number, line_item_sku 
                HAVING COUNT(*) > 1
            ) as dups
        `);
        var duplicatesFound = parseInt(dupCount.rows[0].count);
        console.log('Found ' + duplicatesFound + ' duplicate key combinations');
        
        // Drop the index if it exists
        try { await pool.query('DROP INDEX IF EXISTS idx_sales_data_unique'); } catch (e) {}
        
        // Delete duplicates keeping only the one with the highest id
        var deleteResult = await pool.query(`
            DELETE FROM sales_data a USING sales_data b 
            WHERE a.id < b.id 
            AND a.document_number = b.document_number 
            AND a.line_item_sku = b.line_item_sku
        `);
        var rowsDeleted = deleteResult.rowCount;
        console.log('Deleted ' + rowsDeleted + ' duplicate rows');
        
        // Recreate the unique index
        await pool.query('CREATE UNIQUE INDEX idx_sales_data_unique ON sales_data(document_number, line_item_sku)');
        console.log('Unique index created successfully');
        
        res.json({ 
            success: true, 
            duplicatesFound: duplicatesFound,
            rowsDeleted: rowsDeleted,
            message: 'Fixed ' + rowsDeleted + ' duplicate rows and recreated unique index'
        });
    } catch (err) {
        console.log('Error fixing duplicates:', err.message);
        res.json({ success: false, error: err.message });
    }
});

// Image cache management endpoints
app.get('/api/image-cache/stats', requireAuth, requireAdmin, async function(req, res) {
    try {
        var stats = { cached: 0, totalSize: 0, cacheDir: IMAGE_CACHE_DIR, available: false, staleCount: 0 };
        if (fs.existsSync(IMAGE_CACHE_DIR)) {
            stats.available = true;
            var files = fs.readdirSync(IMAGE_CACHE_DIR).filter(f => !f.endsWith('.meta'));
            stats.cached = files.length;
            var maxAgeMs = IMAGE_CACHE_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
            var now = Date.now();
            files.forEach(function(f) {
                try {
                    var filePath = path.join(IMAGE_CACHE_DIR, f);
                    stats.totalSize += fs.statSync(filePath).size;
                    // Check if stale
                    var metaPath = filePath + '.meta';
                    if (fs.existsSync(metaPath)) {
                        var meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
                        var cachedAt = new Date(meta.cachedAt).getTime();
                        if (now - cachedAt >= maxAgeMs) {
                            stats.staleCount++;
                        }
                    }
                } catch (e) {}
            });
            stats.totalSizeMB = (stats.totalSize / (1024 * 1024)).toFixed(2);
            stats.maxAgeDays = IMAGE_CACHE_MAX_AGE_DAYS;
        }
        // Get total products with images
        var productCount = await pool.query("SELECT COUNT(*) FROM products WHERE image_url IS NOT NULL AND image_url != ''");
        stats.totalProducts = parseInt(productCount.rows[0].count);
        res.json(stats);
    } catch (err) {
        res.json({ error: err.message });
    }
});

app.post('/api/image-cache/clear', requireAuth, requireAdmin, async function(req, res) {
    try {
        if (!fs.existsSync(IMAGE_CACHE_DIR)) {
            return res.json({ success: false, error: 'Cache directory not available' });
        }
        var files = fs.readdirSync(IMAGE_CACHE_DIR);
        var deleted = 0;
        files.forEach(function(f) {
            try {
                fs.unlinkSync(path.join(IMAGE_CACHE_DIR, f));
                deleted++;
            } catch (e) {}
        });
        res.json({ success: true, deleted: deleted });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.post('/api/image-cache/refresh', requireAuth, requireAdmin, async function(req, res) {
    try {
        if (!fs.existsSync(IMAGE_CACHE_DIR)) {
            return res.json({ success: false, error: 'Cache directory not available' });
        }
        
        // Get all products with WorkDrive images
        var products = await pool.query("SELECT id, style_id, image_url FROM products WHERE image_url LIKE '%download-accl.zoho.com%'");
        var total = products.rows.length;
        var refreshed = 0;
        var errors = 0;
        
        // Refresh token first
        if (!zohoAccessToken) await refreshZohoToken();
        
        // Process in batches to avoid overwhelming Zoho API
        for (var i = 0; i < products.rows.length; i++) {
            try {
                var product = products.rows[i];
                var fileId = product.image_url.split('/').pop();
                var cachePath = path.join(IMAGE_CACHE_DIR, fileId);
                var metaPath = cachePath + '.meta';
                
                // Fetch from Zoho
                var imageUrl = 'https://workdrive.zoho.com/api/v1/download/' + fileId;
                var response = await fetch(imageUrl, { 
                    headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken } 
                });
                
                if (response.ok) {
                    var contentType = response.headers.get('content-type') || 'image/jpeg';
                    var imageBuffer = Buffer.from(await response.arrayBuffer());
                    fs.writeFileSync(cachePath, imageBuffer);
                    fs.writeFileSync(metaPath, JSON.stringify({ 
                        contentType: contentType, 
                        cachedAt: new Date().toISOString(),
                        fileId: fileId,
                        styleId: product.style_id
                    }));
                    refreshed++;
                } else {
                    errors++;
                }
                
                // Small delay to avoid rate limiting
                if (i % 10 === 0 && i > 0) {
                    await new Promise(r => setTimeout(r, 100));
                }
            } catch (err) {
                errors++;
            }
        }
        
        res.json({ success: true, total: total, refreshed: refreshed, errors: errors });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// WorkDrive Auto-Import API endpoints
app.get('/api/workdrive-import/status', requireAuth, requireAdmin, async function(req, res) {
    try {
        var recentImports = await pool.query('SELECT * FROM workdrive_imports ORDER BY processed_at DESC LIMIT 10');
        var stats = await pool.query('SELECT COUNT(*) as total, SUM(records_imported) as total_records FROM workdrive_imports WHERE status = $1', ['success']);
        var inventoryStats = await pool.query('SELECT COUNT(*) as total, SUM(records_imported) as records FROM workdrive_imports WHERE status = $1 AND file_type = $2', ['success', 'inventory']);
        var salesStats = await pool.query('SELECT COUNT(*) as total, SUM(records_imported) as records FROM workdrive_imports WHERE status = $1 AND file_type = $2', ['success', 'sales']);
        res.json({
            inventoryFolderId: WORKDRIVE_INVENTORY_FOLDER_ID,
            salesFolderId: WORKDRIVE_SALES_FOLDER_ID,
            checkIntervalHours: WORKDRIVE_CHECK_INTERVAL / 3600000,
            recentImports: recentImports.rows,
            totalFilesProcessed: parseInt(stats.rows[0].total) || 0,
            totalRecordsImported: parseInt(stats.rows[0].total_records) || 0,
            inventoryFiles: parseInt(inventoryStats.rows[0].total) || 0,
            inventoryRecords: parseInt(inventoryStats.rows[0].records) || 0,
            salesFiles: parseInt(salesStats.rows[0].total) || 0,
            salesRecords: parseInt(salesStats.rows[0].records) || 0
        });
    } catch (err) {
        res.json({ error: err.message });
    }
});

app.post('/api/workdrive-import/check-now', requireAuth, requireAdmin, async function(req, res) {
    try {
        var result = await checkWorkDriveFolderForImports();
        res.json(result);
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// Check ONLY the sales folder (for testing split files)
app.post('/api/workdrive-import/check-sales-only', requireAuth, requireAdmin, async function(req, res) {
    try {
        console.log('Checking ONLY Sales-PO folder...');
        var salesResult = await processWorkDriveFolder(WORKDRIVE_SALES_FOLDER_ID, 'sales');
        console.log('Sales-only check complete. Processed ' + salesResult.processed + ' files.');
        res.json({ success: true, processed: salesResult.processed, sales: salesResult.processed });
    } catch (err) {
        console.error('Error checking sales folder:', err);
        res.json({ success: false, error: err.message });
    }
});

app.post('/api/workdrive-import/clear-history', requireAuth, requireAdmin, async function(req, res) {
    try {
        await pool.query('DELETE FROM workdrive_imports');
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// Debug endpoint to see what files WorkDrive API returns
app.get('/api/workdrive-import/debug', requireAuth, requireAdmin, async function(req, res) {
    try {
        var inventoryFiles = await listWorkDriveFiles(WORKDRIVE_INVENTORY_FOLDER_ID);
        var salesFiles = await listWorkDriveFiles(WORKDRIVE_SALES_FOLDER_ID);

        // Get recent import history
        var recentImports = await pool.query(
            "SELECT file_id, file_name, file_type, status, records_imported, processed_at FROM workdrive_imports ORDER BY processed_at DESC LIMIT 20"
        );

        res.json({
            success: true,
            inventoryFolderId: WORKDRIVE_INVENTORY_FOLDER_ID,
            salesFolderId: WORKDRIVE_SALES_FOLDER_ID,
            inventoryFilesFound: inventoryFiles.length,
            inventoryFiles: inventoryFiles.map(function(f) {
                return {
                    id: f.id,
                    name: f.attributes ? f.attributes.name : f.name,
                    modified: f.attributes ? f.attributes.modified_time : null
                };
            }),
            salesFilesFound: salesFiles.length,
            salesFiles: salesFiles.map(function(f) {
                return {
                    id: f.id,
                    name: f.attributes ? f.attributes.name : f.name,
                    modified: f.attributes ? f.attributes.modified_time : null
                };
            }),
            recentImports: recentImports.rows
        });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.post('/api/users', requireAuth, requireAdmin, async function(req, res) { 
    try { 
        var pin = req.body.pin || String(Math.floor(1000 + Math.random() * 9000));
        var displayName = req.body.displayName || req.body.username;
        var username = req.body.username.toLowerCase().replace(/\s+/g, '_');
        await pool.query('INSERT INTO users (username, display_name, pin, role) VALUES ($1,$2,$3,$4)', [username, displayName, pin, req.body.role || 'sales_rep']); 
        res.json({ success: true, pin: pin }); 
    } catch (err) { res.status(500).json({ error: err.message }); } 
});

app.put('/api/users/:id/reset-pin', requireAuth, requireAdmin, async function(req, res) {
    try {
        var newPin = String(Math.floor(1000 + Math.random() * 9000));
        await pool.query('UPDATE users SET pin = $1 WHERE id = $2', [newPin, req.params.id]);
        res.json({ success: true, pin: newPin });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/users/:id/role', requireAuth, requireAdmin, async function(req, res) {
    try {
        await pool.query('UPDATE users SET role = $1 WHERE id = $2', [req.body.role, req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async function(req, res) { try { await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); } });

// Create shareable selection
app.post('/api/selections', requireAuth, async function(req, res) {
    try {
        var productIds = req.body.productIds;
        var name = req.body.name || 'Selection';
        var shareType = req.body.shareType || 'link';
        var hideQuantities = req.body.hideQuantities || false;
        var notes = req.body.notes || {}; // Object with productId -> note text
        if (!productIds || productIds.length === 0) return res.json({ success: false, error: 'No products selected' });
        var shareId = Math.random().toString(36).substring(2, 10) + Date.now().toString(36);
        var options = JSON.stringify({ hideQuantities: hideQuantities, notes: notes });
        await pool.query('INSERT INTO selections (share_id, name, product_ids, created_by, share_type, options, expires_at) VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL \'60 days\')', [shareId, name, productIds, req.session.username || 'anonymous', shareType, options]);
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
        if (selection.expires_at && new Date(selection.expires_at) < new Date()) return res.status(410).json({ error: 'This link has expired' });
        var productsResult = await pool.query('SELECT p.id, p.style_id, p.base_style, p.name, p.category, p.image_url, json_agg(json_build_object(\'color_name\', pc.color_name, \'available_qty\', pc.available_qty, \'available_now\', COALESCE(pc.available_now, pc.available_qty, 0), \'left_to_sell\', COALESCE(pc.left_to_sell, pc.available_qty, 0), \'on_hand\', pc.on_hand, \'open_order\', COALESCE(pc.open_order, 0), \'to_come\', COALESCE(pc.to_come, 0))) FILTER (WHERE pc.id IS NOT NULL) as colors FROM products p LEFT JOIN product_colors pc ON p.id = pc.product_id WHERE p.id = ANY($1) GROUP BY p.id', [selection.product_ids]);
        // Get earliest ETA from open POs for each base_style
        var baseStyles = [...new Set(productsResult.rows.map(function(p) { return p.base_style; }).filter(Boolean))];
        var etaMap = {};
        if (baseStyles.length > 0) {
            var etaResult = await pool.query("SELECT base_style, MIN(in_warehouse_date) as earliest_eta FROM sales_data WHERE base_style = ANY($1) AND document_type IN ('Purchase Order', 'PO', 'Bill') AND (LOWER(status) = 'open' OR LOWER(status) = 'draft' OR LOWER(status) = 'issued') AND in_warehouse_date IS NOT NULL AND in_warehouse_date >= CURRENT_DATE GROUP BY base_style", [baseStyles]);
            etaResult.rows.forEach(function(r) { etaMap[r.base_style] = r.earliest_eta; });
        }
        var products = productsResult.rows.map(function(p) { p.eta = etaMap[p.base_style] || null; return p; });
        res.json({ selection: selection, products: products });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/image/:fileId', async function(req, res) {
    var fileId = req.params.fileId;
    var cachePath = path.join(IMAGE_CACHE_DIR, fileId);
    var metaPath = cachePath + '.meta';
    
    // Check if cached image exists
    try {
        if (fs.existsSync(cachePath) && fs.existsSync(metaPath)) {
            var meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
            res.setHeader('Content-Type', meta.contentType || 'image/jpeg');
            res.setHeader('Cache-Control', 'public, max-age=86400');
            res.setHeader('X-Image-Source', 'cache');
            return res.send(fs.readFileSync(cachePath));
        }
    } catch (cacheErr) {
        console.log('Cache read error:', cacheErr.message);
    }
    
    // Not cached, fetch from Zoho
    var retryCount = 0;
    async function fetchImage() {
        try {
            if (!zohoAccessToken) { 
                var tokenResult = await refreshZohoToken(); 
                if (!tokenResult.success) { return res.status(401).send('No valid token'); } 
            }
            var imageUrl = 'https://workdrive.zoho.com/api/v1/download/' + fileId;
            var response = await fetch(imageUrl, { headers: { 'Authorization': 'Zoho-oauthtoken ' + zohoAccessToken, 'Accept': 'application/vnd.api+json' } });
            if (response.status === 401) { 
                if (retryCount === 0) { retryCount++; await refreshZohoToken(); return fetchImage(); } 
                return res.status(401).send('Auth failed'); 
            }
            if (!response.ok) { return res.status(response.status).send('Image not found'); }
            
            var contentType = response.headers.get('content-type') || 'image/jpeg';
            var imageBuffer = Buffer.from(await response.arrayBuffer());
            
            // Try to cache the image
            try {
                if (fs.existsSync(IMAGE_CACHE_DIR)) {
                    fs.writeFileSync(cachePath, imageBuffer);
                    fs.writeFileSync(metaPath, JSON.stringify({ 
                        contentType: contentType, 
                        cachedAt: new Date().toISOString(),
                        fileId: fileId
                    }));
                }
            } catch (writeErr) {
                console.log('Cache write error:', writeErr.message);
            }
            
            res.setHeader('Content-Type', contentType);
            res.setHeader('Cache-Control', 'public, max-age=86400');
            res.setHeader('X-Image-Source', 'zoho');
            res.send(imageBuffer);
        } catch (err) { 
            console.log('Image fetch error:', err.message);
            res.status(500).send('Error'); 
        }
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
        if (selection.expires_at && new Date(selection.expires_at) < new Date()) return res.status(410).send('This link has expired. Please request a new link from your sales representative.');
        var options = {};
        try { options = JSON.parse(selection.options || '{}'); } catch(e) {}
        var productsResult = await pool.query('SELECT p.id, p.style_id, p.base_style, p.name, p.category, p.image_url, json_agg(json_build_object(\'color_name\', pc.color_name, \'available_qty\', pc.available_qty, \'available_now\', pc.available_now, \'left_to_sell\', pc.left_to_sell)) FILTER (WHERE pc.id IS NOT NULL) as colors FROM products p LEFT JOIN product_colors pc ON p.id = pc.product_id WHERE p.id = ANY($1) GROUP BY p.id ORDER BY p.name', [selection.product_ids]);
        var baseStyles = [...new Set(productsResult.rows.map(function(p) { return p.base_style; }).filter(Boolean))];
        var etaMap = {};
        if (baseStyles.length > 0) {
            var etaResult = await pool.query("SELECT base_style, MIN(in_warehouse_date) as earliest_eta FROM sales_data WHERE base_style = ANY($1) AND document_type IN ('Purchase Order', 'PO', 'Bill') AND (LOWER(status) = 'open' OR LOWER(status) = 'draft' OR LOWER(status) = 'issued') AND in_warehouse_date IS NOT NULL AND in_warehouse_date >= CURRENT_DATE GROUP BY base_style", [baseStyles]);
            etaResult.rows.forEach(function(r) { etaMap[r.base_style] = r.earliest_eta; });
        }
        var products = productsResult.rows.map(function(p) { p.eta = etaMap[p.base_style] || null; return p; });
        res.send(getPDFHTML(selection, products, options));
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
        
        // Get sales data context - top customers and document types
        var customersResult = await pool.query(`
            SELECT DISTINCT customer_vendor, COUNT(*) as order_count, SUM(quantity) as total_qty
            FROM sales_data 
            WHERE customer_vendor IS NOT NULL AND customer_vendor != ''
            GROUP BY customer_vendor 
            ORDER BY total_qty DESC 
            LIMIT 50
        `);
        var topCustomers = customersResult.rows.map(function(r) { return r.customer_vendor; });
        
        var salesStatsResult = await pool.query(`
            SELECT 
                COUNT(DISTINCT document_number) as total_documents,
                COUNT(DISTINCT customer_vendor) as total_customers,
                COUNT(DISTINCT base_style) as styles_with_sales
            FROM sales_data
        `);
        var salesStats = salesStatsResult.rows[0];
        
        var systemPrompt = `You are a helpful assistant for the Mark Edwards Apparel Product Catalog. You help sales reps find products, answer inventory questions, AND search sales/order history.

AVAILABLE PRODUCT DATA:
- Categories: ${categories.join(', ')}
- Colors available: ${colors.slice(0, 30).join(', ')}${colors.length > 30 ? '... and more' : ''}
- Total styles: ${stats.total_styles}
- Total groups (base styles): ${stats.total_groups}
- Total Available Now: ${parseInt(stats.total_available_now).toLocaleString()} units
- Total Left to Sell: ${parseInt(stats.total_left_to_sell).toLocaleString()} units

AVAILABLE SALES/ORDER DATA:
- Total documents (orders/invoices/POs): ${salesStats.total_documents}
- Total customers/vendors: ${salesStats.total_customers}
- Styles with sales history: ${salesStats.styles_with_sales}
- Top customers include: ${topCustomers.slice(0, 20).join(', ')}${topCustomers.length > 20 ? '... and more' : ''}

ACTIONS YOU CAN TRIGGER:
You can respond with JSON actions that the app will execute. Include an "actions" array in your response.

Product filter actions:
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

Sales/Order filter actions (these filter the product grid to show styles with inventory that match the criteria):
11. {"action": "filterByCustomerOrders", "value": "customer name"} - Filter products to show styles IN STOCK that this customer has ordered. IMPORTANT: Use simple, short search terms like "Ross", "Amazon", "Walmart" - NOT full company names with Inc, LLC, etc. The search uses partial matching.
12. {"action": "filterByPOStyles"} - Filter products to show styles IN STOCK that have purchase orders

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

User: "What categories do we have?"
Response: {"message": "We have these categories: ${categories.join(', ')}. Which would you like to explore?", "actions": []}

User: "Show me styles that Amazon bought" or "What did Amazon order?" or "What styles does Amazon like?"
Response: {"message": "Filtering to show styles in stock that Amazon has ordered:", "actions": [{"action": "filterByCustomerOrders", "value": "Amazon"}]}

User: "What did Ross order?" or "Show me Ross Stores styles"
Response: {"message": "Filtering to show styles in stock that Ross has ordered:", "actions": [{"action": "filterByCustomerOrders", "value": "Ross"}]}

User: "Show me what we have that Nordstrom ordered"
Response: {"message": "Showing styles in stock that Nordstrom has purchased:", "actions": [{"action": "filterByCustomerOrders", "value": "Nordstrom"}]}

User: "Show me all styles with purchase orders" or "What styles have POs?"
Response: {"message": "Filtering to show styles in stock that have purchase orders:", "actions": [{"action": "filterByPOStyles"}]}

User: "What customers have we sold to?"
Response: {"message": "Here are our top customers: ${topCustomers.slice(0, 10).join(', ')}. Want me to filter products to show what a specific customer ordered?", "actions": []}

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

// ============================================
// CATALOG SUBSCRIPTION ENDPOINTS
// ============================================

// Get all subscriptions
app.get('/api/catalog-subscriptions', requireAuth, requireAdmin, async function(req, res) {
    try {
        var result = await pool.query(
            'SELECT cs.*, ' +
            '(SELECT COUNT(*) FROM catalog_send_log WHERE subscription_id = cs.id) as total_sent, ' +
            '(SELECT sent_at FROM catalog_send_log WHERE subscription_id = cs.id ORDER BY sent_at DESC LIMIT 1) as last_sent ' +
            'FROM catalog_subscriptions cs ORDER BY cs.company, cs.recipient_name'
        );
        res.json({ success: true, subscriptions: result.rows });
    } catch (err) {
        console.error('Error fetching subscriptions:', err);
        res.json({ success: false, error: err.message });
    }
});

// Create new subscription
app.post('/api/catalog-subscriptions', requireAuth, requireAdmin, async function(req, res) {
    try {
        var { recipient_name, recipient_email, company, categories, frequency,
              send_days, send_time, quantity_mode, min_quantity, show_pricing,
              show_images, custom_message } = req.body;

        var result = await pool.query(
            'INSERT INTO catalog_subscriptions (recipient_name, recipient_email, company, categories, frequency, send_days, send_time, quantity_mode, min_quantity, show_pricing, show_images, custom_message, created_by) ' +
            'VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *',
            [recipient_name, recipient_email, company, categories, frequency,
             send_days || ['monday'], send_time || '08:00', quantity_mode || 'available_now',
             min_quantity || 0, show_pricing !== false, show_images !== false,
             custom_message || '', req.session.username || 'admin']
        );
        res.json({ success: true, subscription: result.rows[0] });
    } catch (err) {
        console.error('Error creating subscription:', err);
        res.json({ success: false, error: err.message });
    }
});

// Update subscription
app.put('/api/catalog-subscriptions/:id', requireAuth, requireAdmin, async function(req, res) {
    try {
        var { recipient_name, recipient_email, company, categories, frequency,
              send_days, send_time, quantity_mode, min_quantity, show_pricing,
              show_images, custom_message, is_active } = req.body;

        var result = await pool.query(
            'UPDATE catalog_subscriptions SET recipient_name=$1, recipient_email=$2, company=$3, ' +
            'categories=$4, frequency=$5, send_days=$6, send_time=$7, quantity_mode=$8, ' +
            'min_quantity=$9, show_pricing=$10, show_images=$11, custom_message=$12, ' +
            'is_active=$13, updated_at=CURRENT_TIMESTAMP WHERE id=$14 RETURNING *',
            [recipient_name, recipient_email, company, categories, frequency,
             send_days, send_time, quantity_mode, min_quantity, show_pricing,
             show_images, custom_message, is_active, req.params.id]
        );
        res.json({ success: true, subscription: result.rows[0] });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// Delete subscription
app.delete('/api/catalog-subscriptions/:id', requireAuth, requireAdmin, async function(req, res) {
    try {
        await pool.query('DELETE FROM catalog_subscriptions WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// Toggle active/inactive
app.post('/api/catalog-subscriptions/:id/toggle', requireAuth, requireAdmin, async function(req, res) {
    try {
        var result = await pool.query(
            'UPDATE catalog_subscriptions SET is_active = NOT is_active, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *',
            [req.params.id]
        );
        res.json({ success: true, subscription: result.rows[0] });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// Send now (manual trigger)
app.post('/api/catalog-subscriptions/:id/send-now', requireAuth, requireAdmin, async function(req, res) {
    try {
        var sub = await pool.query('SELECT * FROM catalog_subscriptions WHERE id = $1', [req.params.id]);
        if (sub.rows.length === 0) return res.json({ success: false, error: 'Subscription not found' });

        var subscription = sub.rows[0];
        var shareUrl = await generateCatalogShareUrl(subscription);

        // Send the email
        var emailResult = await sendCatalogEmail(subscription, shareUrl);

        // Log it
        await pool.query(
            'INSERT INTO catalog_send_log (subscription_id, recipient_email, recipient_name, company, categories, share_url, status) ' +
            'VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [subscription.id, subscription.recipient_email, subscription.recipient_name,
             subscription.company, subscription.categories, shareUrl, emailResult.success ? 'sent' : 'failed']
        );

        res.json({ success: true, message: 'Email sent to ' + subscription.recipient_email });
    } catch (err) {
        console.error('Error sending catalog email:', err);
        res.json({ success: false, error: err.message });
    }
});

// Preview - generates the share URL without sending email
app.post('/api/catalog-subscriptions/:id/preview', requireAuth, requireAdmin, async function(req, res) {
    try {
        var sub = await pool.query('SELECT * FROM catalog_subscriptions WHERE id = $1', [req.params.id]);
        if (sub.rows.length === 0) return res.json({ success: false, error: 'Subscription not found' });

        var shareUrl = await generateCatalogShareUrl(sub.rows[0]);
        res.json({ success: true, url: shareUrl });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// Get send history
app.get('/api/catalog-send-log', requireAuth, requireAdmin, async function(req, res) {
    try {
        var result = await pool.query(
            'SELECT * FROM catalog_send_log ORDER BY sent_at DESC LIMIT 100'
        );
        res.json({ success: true, logs: result.rows });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// Get available categories for the subscription form
app.get('/api/catalog-categories', requireAuth, async function(req, res) {
    try {
        var result = await pool.query(
            'SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != \'\' ORDER BY category'
        );
        res.json({ success: true, categories: result.rows.map(function(r) { return r.category; }) });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});


// ============================================
// CATALOG SHARING HELPER FUNCTIONS
// ============================================

// Generate a catalog share URL with filters baked in
async function generateCatalogShareUrl(subscription) {
    var query = 'SELECT p.id FROM products p LEFT JOIN product_colors pc ON p.id = pc.product_id WHERE 1=1';
    var params = [];
    var paramIdx = 1;

    if (subscription.categories && subscription.categories.length > 0) {
        query += ' AND p.category = ANY($' + paramIdx + ')';
        params.push(subscription.categories);
        paramIdx++;
    }

    if (subscription.min_quantity > 0) {
        if (subscription.quantity_mode === 'both') {
            query += ' AND (COALESCE(pc.available_qty, 0) >= $' + paramIdx + ' OR (COALESCE(pc.available_qty, 0) + COALESCE(pc.to_come, 0)) >= $' + paramIdx + ')';
        } else if (subscription.quantity_mode === 'left_to_sell') {
            query += ' AND (COALESCE(pc.available_qty, 0) + COALESCE(pc.to_come, 0)) >= $' + paramIdx;
        } else {
            query += ' AND COALESCE(pc.available_qty, 0) >= $' + paramIdx;
        }
        params.push(subscription.min_quantity);
        paramIdx++;
    }

    query += ' GROUP BY p.id';

    var result = await pool.query(query, params);
    var productIds = result.rows.map(function(r) { return r.id; });

    var shareId = 'auto_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
    var selectionName = (subscription.company || 'Catalog') + ' - ' +
                        (subscription.categories ? subscription.categories.join(', ') : 'All') +
                        ' - ' + new Date().toLocaleDateString();

    await pool.query(
        'INSERT INTO selections (share_id, name, product_ids, created_by, share_type) VALUES ($1, $2, $3, $4, $5)',
        [shareId, selectionName, productIds, 'auto-share', 'email']
    );

    var baseUrl = process.env.APP_URL || ('https://' + (process.env.RAILWAY_PUBLIC_DOMAIN || 'localhost:' + PORT));
    return baseUrl + '/share/' + shareId;
}

// Send email via Resend (or placeholder for other providers)
async function sendCatalogEmail(subscription, shareUrl) {
    if (!process.env.RESEND_API_KEY) {
        console.log('EMAIL WOULD SEND TO:', subscription.recipient_email);
        console.log('SHARE URL:', shareUrl);
        return { success: true, simulated: true };
    }

    try {
        var emailBody = buildEmailBody(subscription, shareUrl);

        var response = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer ' + process.env.RESEND_API_KEY,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                from: process.env.EMAIL_FROM || 'Mark Edwards Apparel <catalog@markedwardsapparel.com>',
                to: [subscription.recipient_email],
                subject: 'Updated Product Catalog - ' + (subscription.company || 'Mark Edwards Apparel'),
                html: emailBody
            })
        });

        var result = await response.json();
        return { success: response.ok, data: result };
    } catch (err) {
        console.error('Email send error:', err);
        return { success: false, error: err.message };
    }
}

// Build the HTML email body
function buildEmailBody(subscription, shareUrl) {
    var categories = subscription.categories ? subscription.categories.join(', ') : 'All Categories';
    var customMsg = subscription.custom_message ? '<p style="font-size:16px;color:#333;margin-bottom:20px;">' + subscription.custom_message + '</p>' : '';

    return '<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">' +
        '<div style="background:#1a1a2e;color:white;padding:30px;text-align:center;border-radius:10px 10px 0 0;">' +
            '<h1 style="margin:0;font-size:24px;">Mark Edwards Apparel</h1>' +
            '<p style="margin:10px 0 0;opacity:0.8;">Product Catalog Update</p>' +
        '</div>' +
        '<div style="background:#f9f9f9;padding:30px;border:1px solid #ddd;">' +
            (customMsg) +
            '<p style="font-size:16px;color:#333;">Hi ' + subscription.recipient_name + ',</p>' +
            '<p style="font-size:16px;color:#333;">Your updated product catalog is ready to view.</p>' +
            '<div style="background:white;border:1px solid #e0e0e0;border-radius:8px;padding:20px;margin:20px 0;">' +
                '<p style="margin:0 0 5px;color:#666;font-size:14px;"><strong>Categories:</strong> ' + categories + '</p>' +
                '<p style="margin:0 0 5px;color:#666;font-size:14px;"><strong>View Mode:</strong> ' +
                    (subscription.quantity_mode === 'both' ? 'Available Now & Left to Sell' : subscription.quantity_mode === 'left_to_sell' ? 'Left to Sell' : 'Available Now') + '</p>' +
                (subscription.min_quantity > 0 ? '<p style="margin:0;color:#666;font-size:14px;"><strong>Min Qty:</strong> ' + subscription.min_quantity + '+ units</p>' : '') +
            '</div>' +
            '<div style="text-align:center;margin:30px 0;">' +
                '<a href="' + shareUrl + '" style="background:#2196f3;color:white;text-decoration:none;padding:15px 40px;border-radius:8px;font-size:18px;font-weight:bold;">View Catalog →</a>' +
            '</div>' +
            '<p style="font-size:13px;color:#999;text-align:center;">This link shows live inventory data updated every 6 hours.</p>' +
        '</div>' +
        '<div style="text-align:center;padding:15px;color:#999;font-size:12px;">' +
            '<p>Mark Edwards Apparel | Product Catalog</p>' +
        '</div>' +
    '</body></html>';
}


// ============================================
// CRON: Scheduled Catalog Email Sender
// ============================================
function startCatalogEmailScheduler() {
    console.log('Catalog email scheduler started');

    setInterval(async function() {
        try {
            var now = new Date();
            var currentDay = ['sunday','monday','tuesday','wednesday','thursday','friday','saturday'][now.getDay()];
            var currentHour = now.getHours().toString().padStart(2, '0') + ':00';

            var subs = await pool.query('SELECT * FROM catalog_subscriptions WHERE is_active = true');

            for (var i = 0; i < subs.rows.length; i++) {
                var sub = subs.rows[i];
                var shouldSend = false;

                var subDays = sub.send_days || (sub.send_day ? [sub.send_day] : ['monday']);
                var isDayMatch = subDays.indexOf(currentDay) !== -1;

                if (sub.frequency === 'daily' && sub.send_time === currentHour) {
                    shouldSend = true;
                } else if (sub.frequency === 'weekly' && isDayMatch && sub.send_time === currentHour) {
                    shouldSend = true;
                } else if (sub.frequency === 'biweekly' && isDayMatch && sub.send_time === currentHour) {
                    var lastLog = await pool.query(
                        'SELECT sent_at FROM catalog_send_log WHERE subscription_id = $1 ORDER BY sent_at DESC LIMIT 1',
                        [sub.id]
                    );
                    if (lastLog.rows.length === 0 || (now - new Date(lastLog.rows[0].sent_at)) >= 13 * 24 * 60 * 60 * 1000) {
                        shouldSend = true;
                    }
                } else if (sub.frequency === 'monthly' && now.getDate() === 1 && sub.send_time === currentHour) {
                    shouldSend = true;
                }

                if (shouldSend) {
                    console.log('Sending scheduled catalog email to:', sub.recipient_email);
                    var shareUrl = await generateCatalogShareUrl(sub);
                    var emailResult = await sendCatalogEmail(sub, shareUrl);

                    await pool.query(
                        'INSERT INTO catalog_send_log (subscription_id, recipient_email, recipient_name, company, categories, share_url, status) VALUES ($1, $2, $3, $4, $5, $6, $7)',
                        [sub.id, sub.recipient_email, sub.recipient_name, sub.company, sub.categories, shareUrl, emailResult.success ? 'sent' : 'failed']
                    );
                }
            }
        } catch (err) {
            console.error('Catalog scheduler error:', err);
        }
    }, 30 * 60 * 1000);
}


// Catch-all routes - MUST BE LAST
app.get('/', function(req, res) { res.send(getHTML()); });
app.get('*', function(req, res) { res.send(getHTML()); });

function getShareHTML(shareId) {
    var css = '*{margin:0;padding:0;box-sizing:border-box}';
    css += 'body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display",sans-serif;background:#f5f5f7;padding:0}';
    css += '.top-bar{background:#1e3a5f;color:white;text-align:center;padding:0.75rem 2rem;font-size:0.9rem;font-weight:600;letter-spacing:0.05em}';
    css += '.header{text-align:center;padding:1.5rem 2rem 0.5rem;background:white;border-bottom:1px solid #e5e5e7}';
    css += '.header h1{font-size:1.5rem;color:#1e3a5f;font-weight:700;letter-spacing:-0.02em}';
    css += '.header p{color:#86868b;margin-top:0.25rem;font-size:0.85rem}';
    css += '.legend{max-width:1200px;margin:1.25rem auto;padding:0.6rem 1rem;background:white;border-radius:10px;display:flex;gap:2rem;justify-content:center;font-size:0.8rem;box-shadow:0 1px 3px rgba(0,0,0,0.06)}';
    css += '.legend-item{display:flex;align-items:center;gap:0.4rem}';
    css += '.legend-dot{width:8px;height:8px;border-radius:50%}.legend-dot.dc{background:#059669}.legend-dot.coming{background:#0088c2}';
    css += '.product-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:1.25rem;max-width:1200px;margin:0 auto;padding:0 1.25rem}';
    css += '.product-card{background:white;border-radius:12px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.08);transition:box-shadow 0.2s}';
    css += '.product-card:hover{box-shadow:0 4px 16px rgba(0,0,0,0.12)}';
    css += '.product-image{height:280px;background:#fafafa;display:flex;align-items:center;justify-content:center}';
    css += '.product-image img{max-width:100%;max-height:100%;object-fit:contain}';
    css += '.product-info{padding:0.75rem 1rem 1rem}';
    css += '.product-name{font-size:1rem;font-weight:700;color:#1e3a5f;margin-bottom:0.125rem}';
    css += '.product-style{font-size:0.7rem;color:#86868b;margin-bottom:0.6rem;letter-spacing:0.02em}';
    // Merch table styles - proper table layout
    css += '.merch-table{width:100%;border-collapse:collapse;font-size:0.78rem}';
    css += '.merch-table thead th{padding:0.35rem 0.5rem;text-align:right;font-weight:600;font-size:0.7rem;text-transform:uppercase;letter-spacing:0.04em;border-bottom:2px solid #e5e5e7;background:#f8f9fa}';
    css += '.merch-table thead th:first-child{text-align:left;width:auto}';
    css += '.merch-table thead th.col-dc{color:#059669;width:65px}';
    css += '.merch-table thead th.col-coming{color:#0088c2;width:75px}';
    css += '.merch-table tbody td{padding:0.3rem 0.5rem;border-bottom:1px solid #f0f0f2}';
    css += '.merch-table tbody td:first-child{font-weight:500;color:#333;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:160px}';
    css += '.merch-table tbody td.val-dc{text-align:right;color:#059669;font-weight:600;font-variant-numeric:tabular-nums}';
    css += '.merch-table tbody td.val-coming{text-align:right;color:#0088c2;font-weight:600;font-variant-numeric:tabular-nums}';
    css += '.merch-table tbody tr:last-child td{border-bottom:none}';
    css += '.merch-table tfoot td{padding:0.4rem 0.5rem;font-weight:700;border-top:2px solid #1e3a5f;font-size:0.8rem}';
    css += '.merch-table tfoot td:first-child{color:#1e3a5f}';
    css += '.merch-table tfoot td.val-dc{text-align:right;color:#059669;font-variant-numeric:tabular-nums}';
    css += '.merch-table tfoot td.val-coming{text-align:right;color:#0088c2;font-variant-numeric:tabular-nums}';
    css += '.eta-line{margin-top:0.4rem;font-size:0.72rem;color:#1565c0;font-weight:600;display:flex;align-items:center;gap:0.3rem}';
    css += '.eta-line::before{content:"";display:inline-block;width:6px;height:6px;background:#1565c0;border-radius:50%}';
    css += '.actions{text-align:center;padding:2rem 0 3rem}';
    css += '.btn{padding:0.75rem 2rem;border:none;border-radius:980px;cursor:pointer;font-size:0.9rem;font-weight:500;text-decoration:none;display:inline-block;margin:0.5rem;transition:all 0.2s}';
    css += '.btn-primary{background:#1e3a5f;color:white}.btn-primary:hover{background:#2a4a6f}';
    css += '.loading{text-align:center;padding:3rem;color:#86868b}';
    css += '.footer{text-align:center;padding:1rem;color:#86868b;font-size:0.75rem;border-top:1px solid #e5e5e7;margin-top:1rem}';

    var html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Product Selection - Mark Edwards Apparel</title>';
    html += '<style>' + css + '</style></head><body>';
    html += '<div class="top-bar">MARK EDWARDS APPAREL</div>';
    html += '<div class="header"><h1 id="selectionName">Product Selection</h1><p id="selectionInfo"></p></div>';
    html += '<div class="legend"><div class="legend-item"><span class="legend-dot dc"></span><span><strong>In DC</strong> - Ready to ship</span></div><div class="legend-item"><span class="legend-dot coming"></span><span><strong>Coming Soon</strong> - On order</span></div></div>';
    html += '<div class="product-grid" id="productGrid"><div class="loading">Loading products...</div></div>';
    html += '<div class="actions"><a class="btn btn-primary" id="pdfBtn" href="/api/selections/' + shareId + '/pdf" target="_blank">Download / Print PDF</a></div>';
    html += '<div class="footer">Mark Edwards Apparel &bull; Product availability subject to change</div>';
    html += '<script>';
    html += 'fetch("/api/selections/' + shareId + '").then(function(r){return r.json()}).then(function(d){';
    html += 'if(d.error){document.getElementById("productGrid").innerHTML=d.error.indexOf("expired")!==-1?"<p style=\\"text-align:center;padding:2rem;color:#666;font-size:1.1rem\\">This selection link has expired. Please request a new link from your sales representative.</p>":"<p>Selection not found</p>";document.getElementById("pdfBtn").style.display="none";return}';
    html += 'document.getElementById("selectionName").textContent=d.selection.name||"Product Selection";';
    html += 'document.getElementById("selectionInfo").textContent="Created "+new Date(d.selection.created_at).toLocaleDateString()+" \\u2022 "+d.products.length+" items";';
    html += 'var h="";for(var i=0;i<d.products.length;i++){var p=d.products[i];var cols=p.colors||[];var totDC=0;var totCS=0;';
    html += 'var rows="";for(var j=0;j<cols.length;j++){var inDC=cols[j].available_now||cols[j].available_qty||0;var comingSoon=cols[j].left_to_sell||0;totDC+=inDC;totCS+=comingSoon;';
    html += 'rows+="<tr><td>"+cols[j].color_name+"</td><td class=\\"val-dc\\">"+inDC.toLocaleString()+"</td><td class=\\"val-coming\\">"+comingSoon.toLocaleString()+"</td></tr>"}';
    html += 'var imgUrl=p.image_url;if(imgUrl&&imgUrl.indexOf("download-accl.zoho.com")!==-1){var parts=imgUrl.split("/");imgUrl="/api/image/"+parts[parts.length-1]}';
    html += 'var im=imgUrl?"<img src=\\""+imgUrl+"\\" onerror=\\"this.parentElement.innerHTML=\'No Image\'\\">":"No Image";';
    html += 'var etaHtml=p.eta?"<div class=\\"eta-line\\">Expected "+new Date(p.eta).toLocaleDateString("en-US",{month:"short",day:"numeric",year:"numeric"})+"</div>":"";';
    html += 'h+="<div class=\\"product-card\\"><div class=\\"product-image\\">"+im+"</div><div class=\\"product-info\\"><div class=\\"product-name\\">"+p.name+"</div><div class=\\"product-style\\">"+p.style_id+"</div>";';
    html += 'h+="<table class=\\"merch-table\\"><thead><tr><th>Color</th><th class=\\"col-dc\\">In DC</th><th class=\\"col-coming\\">Coming</th></tr></thead>";';
    html += 'h+="<tbody>"+rows+"</tbody>";';
    html += 'h+="<tfoot><tr><td>TOTAL</td><td class=\\"val-dc\\">"+totDC.toLocaleString()+"</td><td class=\\"val-coming\\">"+totCS.toLocaleString()+"</td></tr></tfoot></table>";';
    html += 'h+=etaHtml+"</div></div>"}';
    html += 'document.getElementById("productGrid").innerHTML=h';
    html += '}).catch(function(e){document.getElementById("productGrid").innerHTML="<p>Error loading selection</p>"});';
    html += '</script></body></html>';
    return html;
}

function getPDFHTML(selection, products, options) {
    options = options || {};
    var hideQuantities = options.hideQuantities || false;
    var notes = options.notes || {};
    var html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>' + (selection.name || 'Product Selection') + ' - Mark Edwards Apparel</title><style>@media print{@page{margin:0.5in;size:letter}body{-webkit-print-color-adjust:exact;print-color-adjust:exact}}*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial,sans-serif;padding:20px;background:white}.header{text-align:center;margin-bottom:20px;padding-bottom:20px;border-bottom:2px solid #1e3a5f}.header h1{font-size:24px;margin-bottom:5px;color:#1e3a5f}.header p{color:#666}.legend{display:flex;justify-content:center;gap:30px;margin-bottom:25px;padding:10px;background:#f8f9fa;border-radius:6px}.legend-item{display:flex;align-items:center;gap:6px;font-size:11px}.legend-dot{width:8px;height:8px;border-radius:50%}.legend-dot.dc{background:#059669}.legend-dot.coming{background:#0088c2}.product-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:20px;max-width:1200px;margin:0 auto}.product-card{border:1px solid #ddd;border-radius:8px;overflow:hidden;page-break-inside:avoid;background:white}.product-image{height:240px;background:#f5f5f5;display:flex;align-items:center;justify-content:center;padding:10px}.product-image img{max-width:100%;max-height:100%;object-fit:contain}.product-info{padding:12px}.product-name{font-size:13px;font-weight:bold;margin-bottom:2px;color:#1e3a5f}.product-style{font-size:10px;color:#666;margin-bottom:6px}.qty-header{display:grid;grid-template-columns:1fr 45px 60px;font-size:8px;color:#666;padding:2px 0;border-bottom:1px solid #eee;margin-bottom:2px}.qty-header .dc{color:#059669;text-align:right}.qty-header .coming{color:#0088c2;text-align:right}.color-grid{display:grid;grid-template-columns:1fr 1fr;gap:0 8px}.color-grid.single-col{grid-template-columns:1fr}.qty-row{display:grid;grid-template-columns:1fr 45px 60px;font-size:9px;padding:2px 0;border-bottom:1px solid #f5f5f5}.qty-row:last-child{border-bottom:none}.qty-row .color-name{font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.qty-row .dc{color:#059669;font-weight:600;text-align:right}.qty-row .coming{color:#0088c2;font-weight:600;text-align:right}.total-row{display:grid;grid-template-columns:1fr 45px 60px;font-size:10px;padding:4px 0 0;border-top:2px solid #1e3a5f;margin-top:4px;font-weight:700}.total-row .label{color:#1e3a5f}.total-row .dc{color:#059669;text-align:right}.total-row .coming{color:#0088c2;text-align:right}.note-box{margin-top:6px;padding:6px;background:#f0f7ff;border-radius:4px;border-left:2px solid #0088c2;font-size:9px;color:#333}.note-label{font-weight:bold;color:#0088c2;margin-bottom:2px}.footer{margin-top:30px;text-align:center;color:#666;font-size:12px}.print-btn{position:fixed;top:20px;right:20px;padding:10px 20px;background:#1e3a5f;color:white;border:none;border-radius:4px;cursor:pointer;font-size:14px}@media print{.print-btn{display:none}}</style></head><body>';
    html += '<button class="print-btn" onclick="window.print()">Print / Save PDF</button>';
    html += '<div class="header"><h1>' + (selection.name || 'Product Selection') + '</h1><p>Mark Edwards Apparel • Generated ' + new Date().toLocaleDateString() + ' • ' + products.length + ' items</p></div>';
    if (!hideQuantities) {
        html += '<div class="legend"><div class="legend-item"><span class="legend-dot dc"></span><strong>In DC</strong> - Ready to ship</div><div class="legend-item"><span class="legend-dot coming"></span><strong>Coming Soon</strong> - On order</div></div>';
    }
    html += '<div class="product-grid">';
    for (var i = 0; i < products.length; i++) {
        var p = products[i];
        var cols = p.colors || [];
        var totAvailNow = 0, totLts = 0;
        var colHtml = '';
        if (!hideQuantities) {
            var useGrid = cols.length >= 4;
            var col1 = '', col2 = '';
            for (var j = 0; j < cols.length; j++) {
                var availNow = cols[j].available_now || cols[j].available_qty || 0;
                var lts = cols[j].left_to_sell || 0;
                totAvailNow += availNow;
                totLts += lts;
                var row = '<div class="qty-row"><span class="color-name">' + cols[j].color_name + '</span><span class="dc">' + availNow.toLocaleString() + '</span><span class="coming">' + lts.toLocaleString() + '</span></div>';
                if (useGrid) {
                    if (j % 2 === 0) { col1 += row; } else { col2 += row; }
                } else {
                    col1 += row;
                }
            }
            var gridClass = useGrid ? 'color-grid' : 'color-grid single-col';
            colHtml = '<div class="qty-header"><span></span><span class="dc">In DC</span><span class="coming">Coming</span></div>';
            if (useGrid) {
                colHtml += '<div class="' + gridClass + '"><div class="color-col">' + col1 + '</div><div class="color-col">' + col2 + '</div></div>';
            } else {
                colHtml += '<div class="' + gridClass + '"><div class="color-col">' + col1 + '</div></div>';
            }
            colHtml += '<div class="total-row"><span class="label">TOTAL</span><span class="dc">' + totAvailNow.toLocaleString() + '</span><span class="coming">' + totLts.toLocaleString() + '</span></div>';
        }
        var imgUrl = p.image_url;
        if (imgUrl && imgUrl.indexOf('download-accl.zoho.com') !== -1) {
            var parts = imgUrl.split('/');
            imgUrl = '/api/image/' + parts[parts.length - 1];
        }
        var imgHtml = imgUrl ? '<img src="' + imgUrl + '" onerror="this.parentElement.innerHTML=\'No Image\'">' : 'No Image';
        var noteHtml = '';
        var etaHtml = '';
        if (p.eta && !hideQuantities) {
            var etaDate = new Date(p.eta);
            etaHtml = '<div style="margin-top:4px;font-size:9px;color:#1565c0;font-weight:500">ETA: ' + etaDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) + '</div>';
        }
        var productNote = notes[p.id] || notes[String(p.id)];
        if (productNote && productNote.trim()) {
            noteHtml = '<div class="note-box"><div class="note-label">Notes:</div>' + productNote.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '<br>') + '</div>';
        }
        html += '<div class="product-card"><div class="product-image">' + imgHtml + '</div><div class="product-info"><div class="product-name">' + p.name + '</div><div class="product-style">' + p.style_id + '</div>' + colHtml + etaHtml + noteHtml + '</div></div>';
    }
    html += '</div><div class="footer">Mark Edwards Apparel • Product availability subject to change</div></body></html>';
    return html;
}

function getHTML() {
    var html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Mark Edwards Apparel - Product Catalog</title><style>';
    // Apple-style base
    html += '*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","SF Pro Text",sans-serif;background:#fff;color:#1e3a5f;font-weight:400;-webkit-font-smoothing:antialiased}';
    // ANTI-FLASH: Hide old treemap content inline so it never renders before sidebar-enhanced loads
    html += '.treemap-shelf-content,.treemap-shelf-controls,.treemap-shelf-total,.treemap-shelf .treemap-mode-btn{display:none!important}.treemap-shelf-inner{visibility:hidden}body.sidebar-ready .treemap-shelf-inner{visibility:visible}';
    html += '.login-page{display:none}.login-box{background:white;padding:3rem;border-radius:18px;box-shadow:0 4px 40px rgba(0,0,0,0.06);width:100%;max-width:380px}.login-box h1{margin-bottom:2rem;font-size:1.75rem;text-align:center;font-weight:600;color:#1e3a5f;letter-spacing:-0.02em}';
    html += '.form-group{margin-bottom:1.25rem}.form-group label{display:block;margin-bottom:0.5rem;font-weight:400;color:#86868b;font-size:0.875rem}.form-group input{width:100%;padding:0.875rem 1rem;border:none;border-radius:12px;font-size:1rem;background:#f5f5f7;transition:all 0.2s}.form-group input:focus{outline:none;background:#ebebed;box-shadow:0 0 0 4px rgba(0,125,250,0.1)}';
    // Apple-style buttons
    html += '.btn{padding:0.75rem 1.5rem;border:none;border-radius:980px;cursor:pointer;font-size:0.875rem;font-weight:400;transition:all 0.2s;letter-spacing:-0.01em}.btn-primary{background:#1e3a5f;color:white}.btn-primary:hover{background:#2a4a6f}.btn-secondary{background:transparent;color:#0088c2;padding:0.5rem 1rem}.btn-secondary:hover{background:rgba(0,136,194,0.08)}.btn-danger{background:#ff3b30;color:white}.btn-danger:hover{background:#ff453a}.btn-success{background:#0088c2;color:white}.btn-success:hover{background:#007ab8}';
    html += '.error{color:#ff3b30;margin-top:1rem;text-align:center}.success{color:#34c759}.hidden{display:none!important}';
    // Apple-style header - clean, minimal
    html += '.header{background:white;padding:0 2rem;height:48px;border-bottom:1px solid rgba(0,0,0,0.06);display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100}.header.compact{height:44px}.header h1{font-size:1rem;font-weight:600;color:#1e3a5f;letter-spacing:-0.01em}.header-right{display:flex;gap:1.5rem;align-items:center}';
    // Header buttons - Apple style text links
    html += '.header-right .btn-secondary{background:none;border:none;color:#1e3a5f;font-size:0.75rem;font-weight:400;padding:0.5rem 0;letter-spacing:0}.header-right .btn-secondary:hover{color:#1e3a5f}';
    html += '.user-menu{position:absolute;top:100%;right:0;background:white;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,0.12);padding:0.5rem;min-width:160px;z-index:200}.user-menu.hidden{display:none}.user-menu-item{display:block;width:100%;padding:0.75rem 1rem;border:none;background:none;text-align:left;cursor:pointer;border-radius:8px;font-size:0.875rem;color:#1e3a5f}.user-menu-item:hover{background:#f5f5f7}';
    html += '.pin-modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:none;align-items:center;justify-content:center;z-index:1001}.pin-modal.active{display:flex}.pin-modal-content{background:white;border-radius:18px;padding:2rem;max-width:360px;width:90%}.pin-modal h3{margin-bottom:1.5rem;font-weight:600;color:#1e3a5f}.pin-modal input{width:100%;padding:1rem;border:none;border-radius:12px;margin-bottom:1rem;background:#f5f5f7;text-align:center;font-size:1.5rem;letter-spacing:0.5rem}.pin-modal-actions{display:flex;gap:0.5rem;justify-content:flex-end}';
    html += '.pin-display{font-family:monospace;font-size:1.1rem;background:#f5f5f7;padding:0.25rem 0.75rem;border-radius:6px;letter-spacing:0.2rem}';
    // Search box - Apple style
    html += '.search-box{position:relative}.search-box input{padding:0.5rem 1rem;border:none;border-radius:8px;width:200px;background:#f5f5f7;font-size:0.875rem;transition:all 0.2s}.search-box input:focus{outline:none;width:260px;background:#ebebed}';
    html += '.ai-search-indicator{position:absolute;top:100%;left:0;font-size:0.7rem;color:#0088c2;margin-top:0.25rem;white-space:nowrap}.ai-search-indicator.hidden{display:none}';
    html += '.main{max-width:1600px;margin:0 auto;padding:2rem}';
    // Admin panel
    html += '.admin-panel{background:#fff;padding:2rem;border-radius:18px;margin-bottom:2rem;border:1px solid rgba(0,0,0,0.04)}.admin-panel h2{margin-bottom:1.5rem;font-weight:600;color:#1e3a5f;font-size:1.25rem;letter-spacing:-0.02em}';
    html += '.tabs{display:flex;gap:0.25rem;margin-bottom:1.5rem;flex-wrap:wrap}.tab{padding:0.625rem 1rem;border:none;background:transparent;cursor:pointer;border-radius:980px;color:#4a5568;font-size:0.875rem;font-weight:500;transition:all 0.2s}.tab:hover{background:rgba(0,136,194,0.1);color:#0088c2}.tab.active{background:#0088c2;color:white}.tab-content{display:none}.tab-content.active{display:block}';
    html += '.upload-area{border:1px dashed #d2d2d7;padding:3rem;text-align:center;border-radius:12px;margin-bottom:1rem;background:#fbfbfd}.upload-area input{display:none}.upload-area label{color:#1e3a5f;cursor:pointer;font-weight:400}';
    // Stats bar - Apple minimal style but punchier
    html += '.stats{display:flex;gap:3rem;margin-bottom:0;padding:1.5rem 2.5rem;background:#fff;align-items:center;flex-wrap:wrap;border-bottom:1px solid rgba(0,0,0,0.06)}.stats.compact{padding:0.75rem 2.5rem}.stat-value{font-size:2rem;font-weight:600;color:#1e3a5f;letter-spacing:-0.03em}.stat-label{color:#6e6e73;font-size:0.75rem;font-weight:500;text-transform:uppercase;letter-spacing:0.02em;margin-top:0.125rem}.stat-box{padding:0;transition:all 0.2s ease}.stat-box.stat-active .stat-value{color:#1e3a5f}.stat-box:not(.stat-active){opacity:0.35}.feature-toggle.active-indicator{background:transparent}';
    // Qty toggle - light blue active state
    html += '.qty-toggle{display:flex;background:#f0f4f8;border-radius:980px;padding:3px;margin-left:auto}.qty-toggle-btn{padding:0.5rem 1.25rem;border:none;background:transparent;cursor:pointer;font-size:0.8125rem;font-weight:500;border-radius:980px;transition:all 0.2s;color:#6e6e73}.qty-toggle-btn.active{background:#0088c2;color:white;box-shadow:0 2px 8px rgba(0,136,194,0.3)}.qty-toggle-btn:hover:not(.active){color:#0088c2}';
    // Filters container - better hierarchy
    html += '.filters{display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap;align-items:center;padding:0 2.5rem}';
    // Special filters (New Arrivals, My Picks, Has Notes) - BOLDER, light blue accent
    html += '.filter-btn.special{padding:0.5rem 1.25rem;border:none;background:transparent;border-radius:980px;cursor:pointer;color:#1e3a5f;font-size:0.9375rem;font-weight:600;transition:all 0.2s;margin-right:0.25rem}.filter-btn.special:hover{background:rgba(0,136,194,0.1);color:#0088c2}.filter-btn.special.active{background:#0088c2;color:white}';
    // Divider between special filters and categories
    html += '.filter-divider{width:1px;height:24px;background:#d2d2d7;margin:0 1.25rem}';
    // Category filters - medium weight, light blue hover
    html += '.filter-btn{padding:0.4rem 0.9rem;border:none;background:transparent;border-radius:980px;cursor:pointer;color:#4a5568;font-size:0.8125rem;font-weight:500;transition:all 0.2s}.filter-btn:hover{background:rgba(0,136,194,0.1);color:#0088c2}.filter-btn.active{background:#1e3a5f;color:white;font-weight:600}';
    // Active state for Customer/Supplier dropdown filters
    html += '#customerFilterBtn.active,#supplierFilterBtn.active{background:rgba(0,136,194,0.12);color:#0088c2;font-weight:600;border:1px solid #0088c2}';
    // Color dropdown - Apple clean style with light blue
    html += '.multi-dropdown{position:absolute;top:100%;left:0;background:white;border:none;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,0.15);padding:0.75rem;z-index:100;min-width:280px}.multi-dropdown.hidden{display:none}.multi-dropdown-header{margin-bottom:0.5rem}.multi-dropdown-list{max-height:250px;overflow-y:auto}.multi-option{display:flex;align-items:center;padding:0.5rem 0.75rem;cursor:pointer;border-radius:6px;font-size:0.8125rem;color:#1e3a5f;gap:0.5rem}.multi-option:hover{background:rgba(0,136,194,0.08)}.multi-option input[type="checkbox"]{width:16px;height:16px;cursor:pointer}.multi-option.selected{background:rgba(0,136,194,0.12)}.multi-option .option-count{margin-left:auto;font-size:0.75rem;color:#86868b}';
    html += '.multi-dropdown-item{display:flex;align-items:center;padding:0.4rem 0.75rem;cursor:pointer;border-radius:6px;font-size:0.8125rem;color:#1e3a5f;gap:0.5rem}.multi-dropdown-item:hover{background:rgba(0,136,194,0.08)}.multi-dropdown-item input[type="checkbox"]{width:16px;height:16px;cursor:pointer}.multi-item-name{flex:1}.multi-item-count{font-size:0.75rem;color:#86868b;font-weight:600}';
    html += '.fd-row{display:flex;align-items:center;padding:0.35rem 0;border-bottom:1px solid #f0f0f0;gap:0.5rem}.fd-label{color:#1e3a5f;font-weight:500;flex:1}.fd-count{color:#999;font-size:0.7rem}.fd-dot{width:6px;height:6px;border-radius:50%;display:inline-block}.fd-time{color:#666;font-size:0.7rem;min-width:100px;text-align:right}.fd-size{margin-top:0.5rem;padding-top:0.5rem;border-top:1px solid #ddd;font-weight:600}';
    // Filter summary badge and panel - badge now inline with filters
    html += '.filter-summary-badge{display:none;align-items:center;gap:0.5rem;padding:0.5rem 1rem;background:#0088c2;color:white;border-radius:980px;cursor:pointer;font-size:0.8125rem;font-weight:600;margin-left:0.5rem;transition:all 0.2s}.filter-summary-badge:hover{background:#006fa0;transform:translateY(-1px)}.filter-summary-badge.visible{display:inline-flex}.filter-count-badge{background:#ff4444;color:white;border-radius:12px;padding:2px 8px;font-size:0.75rem;font-weight:700;min-width:20px;text-align:center}';
    html += '.filter-summary-panel{position:fixed;top:0;right:-380px;width:380px;height:100vh;background:white;box-shadow:-2px 0 12px rgba(0,0,0,0.15);transition:right 0.3s ease;z-index:1000;display:flex;flex-direction:column}.filter-summary-panel.active{right:0}.filter-summary-header{padding:1.25rem;border-bottom:1px solid #e0e0e0;display:flex;justify-content:space-between;align-items:center}.filter-summary-title{font-size:1.125rem;font-weight:700;color:#1e3a5f}.filter-summary-close{background:none;border:none;font-size:1.5rem;cursor:pointer;color:#666;padding:0;width:30px;height:30px;display:flex;align-items:center;justify-content:center;border-radius:4px}.filter-summary-close:hover{background:#f0f0f0}.filter-summary-body{padding:1.25rem;flex:1;overflow-y:auto}.filter-summary-footer{padding:1.25rem;border-top:1px solid #e0e0e0}.filter-group{margin-bottom:1.5rem}.filter-group-title{font-weight:700;color:#1e3a5f;margin-bottom:0.625rem;font-size:0.8125rem;text-transform:uppercase;letter-spacing:0.5px}.filter-item{padding:0.75rem;border-bottom:1px solid #f0f0f0;display:flex;justify-content:space-between;align-items:center}.filter-item:last-child{border-bottom:none}.filter-item-label{font-size:0.875rem;color:#666}.filter-item-value{font-weight:600;color:#0088c2;font-size:0.875rem;margin-top:0.25rem}.filter-item-remove{background:#ff4444;color:white;border:none;padding:0.25rem 0.75rem;border-radius:4px;font-size:0.75rem;cursor:pointer;font-weight:600}.filter-item-remove:hover{background:#cc0000}.clear-all-filters-btn{width:100%;padding:0.75rem;background:#0088c2;color:white;border:none;border-radius:6px;font-size:0.875rem;font-weight:600;cursor:pointer}.clear-all-filters-btn:hover{background:#006fa0}';
    // Product grid - Apple spacing, wider
    html += '.product-grid{display:grid;gap:1.5rem;padding:1.5rem 2.5rem}.product-grid.size-small{grid-template-columns:repeat(auto-fill,minmax(220px,1fr))}.product-grid.size-medium{grid-template-columns:repeat(auto-fill,minmax(300px,1fr))}.product-grid.size-large{grid-template-columns:repeat(auto-fill,minmax(400px,1fr))}.product-grid.size-list{display:block;padding:0.5rem 2.5rem}.list-table{width:100%;border-collapse:collapse;font-size:0.875rem}.list-table th{text-align:left;padding:0.75rem 1rem;background:#f5f5f7;border-bottom:1px solid #e0e0e0;font-weight:600;color:#1e3a5f;position:sticky;top:0}.list-table th.right{text-align:right}.list-table td{padding:0.625rem 1rem;border-bottom:1px solid #f0f0f0;vertical-align:middle}.list-table td.right{text-align:right;font-weight:500}.list-table tr{cursor:pointer;transition:background 0.15s}.list-table tr:hover{background:rgba(0,136,194,0.04)}.list-table tr.selected{background:rgba(0,136,194,0.1)}.list-table .thumb{width:50px;height:50px;object-fit:contain;border-radius:4px;background:#f5f5f7}.list-table .style-cell{font-weight:600;color:#0088c2}.list-table .name-cell{color:#1e3a5f}.list-table .cat-cell{color:#86868b;font-size:0.8rem}.list-table .colors-cell{color:#666;font-size:0.8rem;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.list-table .qty-now{color:#1e3a5f;font-weight:600}.list-table .qty-lts{color:#86868b}';
    html += '.product-card.list-view{display:flex;flex-direction:row;height:auto}.product-card.list-view .product-image{width:80px;height:80px;min-height:80px}.product-card.list-view .product-info{flex:1;padding:0.75rem;display:flex;align-items:center;gap:1rem}.product-card.list-view .product-name{margin:0}.product-card.list-view .product-style{margin:0}.product-card.list-view .color-list{display:none}.product-card.list-view .total-row{margin:0;padding:0;border:none}.product-card.list-view .list-colors{display:flex;gap:0.5rem;flex-wrap:wrap;font-size:0.8rem;color:#86868b}';
    // Product card - Apple clean, borderless
    html += '.product-card{background:#fff;border-radius:18px;overflow:hidden;cursor:pointer;transition:all 0.3s ease;position:relative;border:none}.product-card:hover{transform:scale(1.02)}';
    html += '.product-card.selected{box-shadow:0 0 0 2px #1e3a5f}.product-card.grouped.group-selected{box-shadow:0 0 0 2px #1e3a5f}.product-card.grouped.group-selected .select-badge{opacity:1}';
    html += '.product-card.selection-mode:hover{box-shadow:0 0 0 2px rgba(0,113,227,0.3)}';
    html += '.product-card.focused{box-shadow:0 0 0 2px #1e3a5f}';
    html += '.select-badge{position:absolute;top:12px;right:12px;width:24px;height:24px;background:#1e3a5f;color:white;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;opacity:0;transition:opacity 0.2s;z-index:5}.product-card.selection-mode:hover .select-badge{opacity:0.6}.product-card.selected .select-badge{opacity:1}';
    html += '.pick-badge{position:absolute;top:12px;left:12px;width:24px;height:24px;background:#ff9500;color:white;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;cursor:pointer;opacity:0;transition:opacity 0.2s;z-index:5}.product-card:hover .pick-badge{opacity:0.6}.product-card .pick-badge.active{opacity:1}';
    html += '.note-badge{position:absolute;top:12px;left:42px;width:24px;height:24px;background:#5ac8fa;color:white;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;z-index:5;opacity:0}.product-card .note-badge.has-note{opacity:1}';
    html += '.color-count-badge{position:absolute;top:12px;right:12px;background:#0088c2;color:white;padding:0.25rem 0.625rem;border-radius:980px;font-size:0.7rem;font-weight:600;z-index:5}';
    html += '.product-card.grouped{border:none}.product-card.grouped:hover{transform:scale(1.02)}';
    // Product image - Apple style light gray bg
    html += '.product-image{height:240px;background:#f5f5f7;display:flex;align-items:center;justify-content:center;overflow:hidden}.product-image img{max-width:90%;max-height:90%;object-fit:contain}';
    // Product info - Punchier typography
    html += '.product-info{padding:1rem 1.25rem;text-align:center}.product-style{font-size:0.6875rem;color:#86868b;text-transform:uppercase;letter-spacing:0.05em;font-weight:500}.product-name{font-size:0.9375rem;font-weight:600;margin:0.25rem 0;color:#1e3a5f;letter-spacing:-0.01em}.color-list{margin-top:0.625rem;text-align:left}.color-row{display:flex;justify-content:space-between;padding:0.2rem 0;font-size:0.8125rem;color:#1e3a5f}.total-row{margin-top:0.625rem;padding-top:0.625rem;border-top:1px solid #e8e8ed;font-weight:600;display:flex;justify-content:space-between;color:#1e3a5f;font-size:0.875rem}';
    html += '.empty{text-align:center;padding:4rem;color:#86868b;font-size:1.125rem}';
    // Modal - Apple style
    html += '.modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:none;align-items:center;justify-content:center;z-index:1000}.modal.active{display:flex}.modal-content{background:white;border-radius:18px;max-width:98vw;width:1600px;max-height:98vh;overflow:auto;position:relative;box-shadow:0 20px 60px rgba(0,0,0,0.2)}.modal-body{display:flex;min-height:850px}.modal-image{width:60%;background:#f5f5f7;min-height:850px;display:flex;align-items:center;justify-content:center;padding:2rem}.modal-image img{max-width:100%;max-height:900px;object-fit:contain}.modal-details{width:40%;padding:2.5rem;overflow-y:auto;max-height:850px;background:white}.modal-details h2,.modal-details h3{background:none!important;margin:0;padding:0}.modal-close{position:absolute;top:1rem;right:1rem;background:rgba(0,0,0,0.06);border:none;font-size:1.25rem;cursor:pointer;border-radius:50%;width:32px;height:32px;z-index:10;color:#1e3a5f;transition:background 0.2s}.modal-close:hover{background:rgba(0,0,0,0.1)}';
    html += '.modal-actions{margin-top:1.5rem;padding-top:1rem;border-top:1px solid #f5f5f7;display:flex;gap:0.5rem;flex-wrap:wrap}';
    html += '.note-section{margin-top:1rem;padding-top:1rem;border-top:1px solid #f5f5f7}.note-section textarea{width:100%;height:80px;margin-top:0.5rem;padding:0.875rem;border:none;border-radius:12px;font-family:inherit;resize:vertical;background:#f5f5f7;transition:background 0.2s}.note-section textarea:focus{outline:none;background:#ebebed}';
    html += '.selection-bar{position:fixed;bottom:0;left:0;right:0;background:#1e3a5f;color:white;padding:1rem 2rem;display:flex;justify-content:space-between;align-items:center;z-index:100;transform:translateY(100%);transition:transform 0.3s}.selection-bar.visible{transform:translateY(0)}';
    
    // Help modal styles
    html += '.help-modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.4);display:none;align-items:center;justify-content:center;z-index:1002;overflow-y:auto;padding:2rem}.help-modal.active{display:flex}.help-content{background:white;border-radius:12px;max-width:900px;width:95%;max-height:90vh;overflow-y:auto;padding:2rem;position:relative;box-shadow:0 20px 60px rgba(0,0,0,0.15)}';
    html += '.help-content h2{margin-bottom:1.5rem;color:#555;font-weight:500}.help-sections{display:flex;flex-direction:column;gap:2rem}';
    html += '.help-section{border-bottom:1px solid #f0f0ee;padding-bottom:1.5rem}.help-section:last-child{border-bottom:none}.help-section h3{color:#555;margin-bottom:1rem;font-size:1.1rem;font-weight:500}';
    html += '.help-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem}.help-card{background:#f5f5f7;border-radius:12px;padding:1.5rem;text-align:center}.help-icon{font-size:2rem;margin-bottom:0.5rem}.help-card h4{margin-bottom:0.5rem;color:#1e3a5f;font-weight:600}.help-card p{font-size:0.875rem;color:#86868b;margin:0}';
    html += '.help-table{width:100%;border-collapse:collapse}.help-table td{padding:0.75rem;border-bottom:1px solid #f5f5f7;vertical-align:top}.help-table tr:last-child td{border-bottom:none}.help-feature{width:180px;white-space:nowrap}';
    html += '.help-steps{display:flex;flex-direction:column;gap:1rem}.help-step{display:flex;align-items:flex-start;gap:1rem}.step-num{width:32px;height:32px;background:#1e3a5f;color:white;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:600;flex-shrink:0}.step-content p{margin:0.25rem 0 0;color:#86868b;font-size:0.875rem}';
    html += '.help-section ul{margin:0.5rem 0 0 1.5rem;color:#86868b}.help-section ul li{margin-bottom:0.25rem}';
    html += '.faq-item{margin-bottom:1rem;padding:1rem;background:#f5f5f7;border-radius:12px}.faq-item strong{color:#1e3a5f}.faq-item p{margin:0.5rem 0 0;color:#86868b;font-size:0.875rem}';
    
    // Chat UI CSS - Apple style
    html += '.chat-bubble{position:fixed;bottom:24px;right:24px;background:#1e3a5f;border-radius:28px;display:flex;align-items:center;gap:0.5rem;padding:0.75rem 1.25rem 0.75rem 1rem;cursor:pointer;box-shadow:0 4px 16px rgba(0,0,0,0.16);z-index:999;transition:all 0.3s;animation:pulse-glow 2s ease-in-out infinite}.chat-bubble:hover{transform:scale(1.05);box-shadow:0 6px 24px rgba(0,0,0,0.2)}.chat-bubble svg{width:24px;height:24px;fill:white}.chat-bubble-label{color:white;font-size:0.875rem;font-weight:500;white-space:nowrap}@keyframes pulse-glow{0%,100%{box-shadow:0 4px 16px rgba(0,0,0,0.16)}50%{box-shadow:0 4px 24px rgba(30,58,95,0.4)}}.chat-bubble.selection-active{bottom:90px}';
    html += '.chat-panel{position:fixed;bottom:100px;right:24px;width:380px;max-width:calc(100vw - 48px);height:520px;max-height:calc(100vh - 150px);background:white;border-radius:18px;box-shadow:0 8px 40px rgba(0,0,0,0.16);display:none;flex-direction:column;z-index:998;overflow:hidden}.chat-panel.active{display:flex}';
    html += '.chat-header{background:#1e3a5f;color:white;padding:1rem 1.25rem;display:flex;justify-content:space-between;align-items:center}.chat-header h3{margin:0;font-size:0.9375rem;display:flex;align-items:center;gap:0.5rem;font-weight:600;letter-spacing:-0.01em}.chat-close{background:none;border:none;color:white;font-size:1.25rem;cursor:pointer;padding:0;line-height:1;opacity:0.7}.chat-close:hover{opacity:1}';
    html += '.chat-messages{flex:1;overflow-y:auto;padding:1rem;display:flex;flex-direction:column;gap:0.75rem;background:#f5f5f7}';
    html += '.chat-message{max-width:85%;padding:0.75rem 1rem;border-radius:18px;font-size:0.875rem;line-height:1.4}.chat-message.user{background:#1e3a5f;align-self:flex-end;border-bottom-right-radius:4px;color:white}.chat-message.assistant{background:white;align-self:flex-start;border-bottom-left-radius:4px;color:#1e3a5f}.chat-message.system{background:#fff3cd;align-self:center;font-size:0.8rem;color:#856404}';
    html += '.chat-input-area{padding:1rem;border-top:1px solid #f5f5f7;display:flex;gap:0.5rem;background:white}.chat-input{flex:1;padding:0.75rem 1rem;border:none;border-radius:18px;font-size:0.875rem;resize:none;background:#f5f5f7;transition:background 0.2s}.chat-input:focus{outline:none;background:#ebebed}.chat-send{background:#1e3a5f;color:white;border:none;border-radius:18px;padding:0.75rem 1.25rem;cursor:pointer;font-weight:500;font-size:0.875rem;transition:background 0.2s}.chat-send:hover{background:#0088c2}.chat-send:disabled{background:#d2d2d7;cursor:not-allowed}';
    html += '.chat-typing{display:flex;gap:4px;padding:0.5rem}.chat-typing span{width:8px;height:8px;background:#86868b;border-radius:50%;animation:typing 1.4s infinite}.chat-typing span:nth-child(2){animation-delay:0.2s}.chat-typing span:nth-child(3){animation-delay:0.4s}@keyframes typing{0%,60%,100%{transform:translateY(0)}30%{transform:translateY(-4px)}}';
    
    html += 'kbd{background:#f5f5f7;border:none;border-radius:6px;padding:0.25rem 0.5rem;font-family:SF Mono,monospace;font-size:0.8125rem;color:#1e3a5f}';
    html += 'table{width:100%;border-collapse:collapse}th,td{padding:0.875rem;text-align:left;border-bottom:1px solid #f5f5f7}th{color:#86868b;font-weight:400;font-size:0.75rem;text-transform:none;letter-spacing:0}';
    html += '.add-form{display:flex;gap:0.5rem;margin-top:1rem;flex-wrap:wrap}.add-form input,.add-form select{padding:0.625rem 1rem;border:none;border-radius:8px;background:#f5f5f7}';
    html += '.status-box{padding:1rem;background:#f5f5f7;border-radius:12px;margin-bottom:1rem}.status-item{margin-bottom:0.5rem}.status-label{font-weight:400;color:#86868b}.status-value{color:#1e3a5f}.status-value.connected{color:#34c759}.status-value.disconnected{color:#ff3b30}';
    html += '.system-health-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem}.health-card{background:#f5f5f7;border-radius:12px;padding:1.25rem}.health-card h4{margin:0 0 0.75rem;font-size:0.9375rem;color:#1e3a5f;font-weight:600}.health-stats{display:flex;flex-direction:column;gap:0.5rem}.health-row{display:flex;justify-content:space-between;font-size:0.8125rem}.health-row span{color:#86868b}.health-row strong{color:#1e3a5f}.status-ok{color:#34c759}.status-warn{color:#ff9500}';
    // View controls - Apple style, qty inline
    html += '.view-controls{display:flex;align-items:center;gap:2rem;margin-bottom:0;padding:1rem 2.5rem;background:#fff;flex-wrap:wrap;border-bottom:1px solid rgba(0,0,0,0.06)}.view-controls.compact{padding:0.625rem 2.5rem}.view-controls label{font-weight:500;color:#6e6e73;font-size:0.8125rem}';
    // Qty filter inline group
    html += '.qty-filter-group{display:flex;align-items:center;gap:0.5rem}.qty-filter-group input{width:70px;padding:0.4rem 0.625rem;border:1px solid #d2d2d7;border-radius:8px;font-size:0.8125rem;text-align:center}.qty-filter-group input:focus{outline:none;border-color:#1e3a5f}.qty-filter-group span{color:#86868b;font-size:0.8125rem}';
    html += '.size-btn{padding:0.5rem 1rem;border:none;background:transparent;cursor:pointer;color:#4a5568;font-size:0.8125rem;font-weight:500;transition:all 0.2s;border-radius:6px}.size-btn:hover{background:rgba(0,136,194,0.1);color:#0088c2}.size-btn.active{background:#1e3a5f;color:white}';
    html += '.selection-bar{position:fixed;bottom:0;left:0;right:0;background:white;padding:1rem 2rem;box-shadow:0 -2px 10px rgba(0,0,0,0.1);display:flex;justify-content:space-between;align-items:center;z-index:100;transform:translateY(100%);transition:transform 0.3s}.selection-bar.visible{transform:translateY(0)}';
    html += '.selection-preview{position:fixed;bottom:70px;right:24px;width:320px;max-height:400px;background:white;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.15);z-index:101;display:none;flex-direction:column;overflow:hidden}.selection-preview.visible{display:flex}.selection-preview-header{padding:1rem;border-bottom:1px solid #e5e5e5;display:flex;justify-content:space-between;align-items:center}.selection-preview-header h3{font-size:0.9375rem;font-weight:600;color:#1e3a5f;margin:0}.selection-preview-close{background:none;border:none;font-size:1.25rem;cursor:pointer;color:#86868b;padding:0.25rem}.selection-preview-stats{padding:0.75rem 1rem;background:#f5f5f7;font-size:0.8125rem;color:#666;display:flex;gap:1rem}.selection-preview-stats span{display:flex;align-items:center;gap:0.25rem}.selection-preview-list{flex:1;overflow-y:auto;padding:0.5rem}.selection-preview-item{display:flex;align-items:center;gap:0.75rem;padding:0.5rem;border-radius:8px;transition:background 0.15s}.selection-preview-item:hover{background:#f5f5f7}.selection-preview-item img{width:40px;height:40px;object-fit:contain;border-radius:4px;background:#f5f5f7}.selection-preview-item-info{flex:1;min-width:0}.selection-preview-item-style{font-size:0.75rem;color:#0088c2;font-weight:600}.selection-preview-item-name{font-size:0.8125rem;color:#1e3a5f;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.selection-preview-item-remove{background:none;border:none;color:#dc2626;cursor:pointer;font-size:1rem;padding:0.25rem;opacity:0.6;transition:opacity 0.15s}.selection-preview-item-remove:hover{opacity:1}';
    html += '.selection-count{font-weight:600;font-size:1rem;color:#1e3a5f}.selection-actions{display:flex;gap:0.5rem}';
    html += '.share-modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:none;align-items:center;justify-content:center;z-index:1001}.share-modal.active{display:flex}.share-modal-content{background:white;border-radius:18px;padding:2rem;max-width:500px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,0.2)}.share-modal h3{margin-bottom:1rem;font-weight:600;color:#1e3a5f;font-size:1.25rem}.share-modal input{width:100%;padding:0.875rem 1rem;border:none;border-radius:12px;margin-bottom:1rem;background:#f5f5f7}.share-modal-actions{display:flex;gap:0.5rem;justify-content:flex-end}';
    html += '.share-result{margin-top:1rem;padding:1rem;background:#f5f5f7;border-radius:12px}.share-result a{color:#0088c2;word-break:break-all}';
    html += '.share-buttons{display:flex;flex-direction:column;gap:0.75rem}.share-action-btn{display:block;width:100%;padding:1rem;border:none;background:#f5f5f7;border-radius:12px;font-size:1rem;cursor:pointer;text-align:left;text-decoration:none;color:#1e3a5f;transition:all 0.2s}.share-action-btn:hover{background:#ebebed}';
    html += '.select-mode-btn{padding:0.5rem 1rem;border:none;background:transparent;color:#0088c2;border-radius:980px;cursor:pointer;font-weight:500;font-size:0.875rem;transition:all 0.2s}.select-mode-btn:hover{background:rgba(0,136,194,0.08)}.select-mode-btn.active{background:#1e3a5f;color:white}';
    html += '.reset-all-btn{padding:0.5rem 1rem;border:2px solid #dc2626;background:#dc2626;color:white;border-radius:980px;cursor:pointer;font-weight:600;font-size:0.875rem;transition:all 0.2s;margin-left:1rem}.reset-all-btn:hover{background:#b91c1c;border-color:#b91c1c}';
    html += '.feature-toggle{display:inline-flex;align-items:center;margin:0 1rem;background:#f0f4f8;border-radius:980px;padding:3px;border:none}.feature-toggle input{display:none}.feature-toggle label{padding:0.5rem 1rem;border-radius:980px;cursor:pointer;font-size:0.8125rem;font-weight:500;color:#6e6e73;transition:all 0.2s}.feature-toggle input:checked+label{background:#0088c2;color:white}';
    html += '.freshness-info{padding:1.25rem;background:#f5f5f7;border-radius:12px;margin-bottom:1rem}.freshness-info.stale{background:#fff3cd}';
    html += '.share-history-table{font-size:0.8125rem}.share-history-table td{padding:0.625rem 0.75rem}.share-type-badge{display:inline-block;padding:0.25rem 0.625rem;border-radius:980px;font-size:0.6875rem;font-weight:500}.share-type-badge.link{background:#e3f2fd;color:#1565c0}.share-type-badge.pdf{background:#fce4ec;color:#c62828}';
    
    // Mobile responsive styles
    html += '@media screen and (max-width: 768px) {';
    // Header - fix sticky and disable heavy blur on mobile
    html += '.header{padding:0.75rem 1rem;flex-wrap:wrap;gap:0.5rem;height:auto !important;position:sticky;top:0;z-index:100;backdrop-filter:none;-webkit-backdrop-filter:none;background:white !important}.header.compact{height:auto !important}.header h1{font-size:1.125rem !important}.header-right{gap:0.25rem}.header-right .btn{padding:0.375rem 0.5rem;font-size:0.75rem}';
    // Stats section - NOT sticky on mobile to prevent stacking issues
    html += '.stats{flex-direction:column;align-items:stretch;padding:1rem;gap:0.75rem;position:relative !important;top:auto !important;z-index:auto}.stats.compact{position:relative !important;top:auto !important}.stats>div{display:flex;justify-content:space-between;align-items:center;padding:0.5rem 0;border-bottom:1px solid rgba(0,0,0,0.06)}.stats>div:last-child{border-bottom:none}.stat-value{font-size:1.5rem !important}.stat-label{font-size:0.625rem !important}';
    // Qty toggle
    html += '.qty-toggle{width:100%;justify-content:center;margin:0.75rem 0}.qty-toggle-btn{padding:0.5rem 1rem;font-size:0.8125rem}';
    // View controls - NOT sticky on mobile
    html += '.view-controls{flex-direction:column;padding:0.75rem 1rem;gap:0.75rem;position:relative !important;top:auto !important;z-index:auto}.view-controls.compact{position:relative !important;top:auto !important}.search-box{width:100%;max-width:none;margin:0}.view-controls>div{width:100%;display:flex;flex-wrap:wrap;gap:0.375rem;justify-content:flex-start}';
    // Size and sort buttons
    html += '.size-btn{padding:0.375rem 0.625rem;font-size:0.75rem}.sort-select{padding:0.375rem 0.5rem;font-size:0.75rem}';
    // Filters row
    html += '.filters{padding:0.5rem 1rem;flex-wrap:wrap;gap:0.375rem;justify-content:flex-start}.filter-btn{padding:0.375rem 0.625rem;font-size:0.6875rem}.filter-divider{display:none}';
    // Categories - horizontal scroll
    html += '#categoryFilters{display:flex;flex-wrap:nowrap;overflow-x:auto;-webkit-overflow-scrolling:touch;padding-bottom:0.5rem;gap:0.375rem}#categoryFilters .filter-btn{flex-shrink:0;white-space:nowrap}';
    // Product grid - single column on small phones, 2 columns on larger phones
    html += '.product-grid{padding:0.75rem !important;gap:0.75rem !important}.product-grid.size-medium,.product-grid.size-small,.product-grid.size-large{grid-template-columns:repeat(2,1fr) !important}';
    // Product cards
    html += '.product-card{border-radius:8px}.product-info{padding:0.625rem}.product-style{font-size:0.625rem}.product-name{font-size:0.75rem;margin-bottom:0.25rem}.color-row{font-size:0.625rem;padding:0.125rem 0}.total-row{font-size:0.75rem;margin-top:0.375rem;padding-top:0.375rem}';
    // Color count badge
    html += '.color-count-badge{font-size:0.5625rem;padding:0.125rem 0.375rem;top:6px;left:6px}';
    // Pick badge
    html += '.pick-badge{font-size:1rem;top:6px;right:6px}';
    // Select badge
    html += '.select-badge{width:20px;height:20px;font-size:10px;top:6px;right:6px}';
    // Hide some elements on mobile
    html += '.select-mode-btn{font-size:0.75rem;padding:0.375rem 0.625rem}';
    // Selection bar
    html += '.selection-bar{padding:0.625rem 1rem;flex-wrap:wrap;gap:0.5rem}.selection-count{font-size:0.8125rem;width:100%;text-align:center}.selection-actions{width:100%;justify-content:center;flex-wrap:wrap;gap:0.375rem}.selection-actions .btn{padding:0.375rem 0.625rem;font-size:0.75rem}';
    // Chat bubble
    html += '.chat-bubble{bottom:16px;right:16px;padding:0.625rem 1rem}.chat-bubble-label{font-size:0.8125rem}.chat-bubble svg{width:20px;height:20px}';
    // Chat panel
    html += '.chat-panel{width:calc(100vw - 32px);right:16px;bottom:80px;height:60vh;max-height:400px}';
    // Selection preview
    html += '.selection-preview{width:calc(100vw - 32px);right:16px;max-height:50vh}';
    // Modals
    html += '.modal-content{width:98vw;max-width:none;border-radius:12px}.modal-body{flex-direction:column;min-height:auto}.modal-image{width:100%;min-height:250px;max-height:40vh}.modal-details{width:100%;padding:1rem;max-height:none}';
    // Help modal
    html += '.help-content{width:98%;padding:1rem;max-height:85vh}.help-section h3{font-size:1rem}.help-table td{padding:0.375rem;font-size:0.75rem}';
    // Share modal
    html += '.share-modal-content{width:95%;padding:1.25rem}';
    // Admin panel
    html += '.admin-panel{padding:1rem}.tab-content{padding:1rem}.admin-tabs button{padding:0.5rem 0.75rem;font-size:0.75rem}';
    // List view
    html += '.product-grid.size-list{padding:0.5rem !important}.list-table{font-size:0.6875rem}.list-table th,.list-table td{padding:0.375rem 0.5rem}.list-table .thumb{width:36px;height:36px}';
    // Group modal
    html += '.group-modal-content{width:98vw;padding:1rem}.group-modal-grid{grid-template-columns:repeat(2,1fr);gap:0.5rem}';
    html += '}';
    
    // Extra small screens (iPhone SE, etc)
    html += '@media screen and (max-width: 375px) {';
    html += '.product-grid.size-medium,.product-grid.size-small,.product-grid.size-large{grid-template-columns:1fr !important}';
    html += '.header h1{font-size:1rem !important}.header-right .btn{padding:0.25rem 0.375rem;font-size:0.6875rem}';
    html += '.stats .stat-value{font-size:1.25rem !important}';
    html += '.filter-btn{font-size:0.625rem;padding:0.25rem 0.5rem}';
    html += '}';

    // Merchandising tab styles
    html += '.merch-section{background:#fff;border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;box-shadow:0 1px 3px rgba(0,0,0,0.1)}';
    html += '.merch-section h3{margin:0 0 1rem;font-size:1.1rem;color:#1e3a5f}';
    html += '.merch-chart-row{display:flex;gap:2rem;flex-wrap:wrap}';
    html += '.merch-chart-container{flex:1;min-width:300px;position:relative}';
    html += '.merch-donut-wrapper{position:relative;width:280px;height:280px;margin:0 auto}';
    html += '.merch-donut-center{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}';
    html += '.merch-donut-center .total{font-size:1.5rem;font-weight:700;color:#1e3a5f}';
    html += '.merch-donut-center .label{font-size:0.75rem;color:#86868b}';
    html += '.merch-legend{flex:1;min-width:250px;max-height:320px;overflow-y:auto}';
    html += '.merch-legend-item{display:flex;align-items:center;gap:0.75rem;padding:0.5rem;border-radius:6px;cursor:pointer;transition:background 0.15s}';
    html += '.merch-legend-item:hover{background:#f5f5f7}';
    html += '.merch-legend-color{width:14px;height:14px;border-radius:3px;flex-shrink:0}';
    html += '.merch-legend-info{flex:1;min-width:0}';
    html += '.merch-legend-name{font-size:0.875rem;font-weight:500;color:#1e3a5f;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}';
    html += '.merch-legend-stats{font-size:0.75rem;color:#86868b}';
    html += '.merch-legend-warning{background:#fff3cd;color:#856404;font-size:0.65rem;padding:2px 6px;border-radius:4px;font-weight:600;margin-left:auto;flex-shrink:0}';
    html += '.merch-bubble-container{width:100%;height:350px;position:relative;background:#fafafa;border-radius:8px;overflow:hidden}';
    html += '.merch-bubble-controls{display:flex;gap:1rem;margin-bottom:1rem;flex-wrap:wrap}';
    html += '.merch-radio-group{display:flex;gap:0.5rem;align-items:center}';
    html += '.merch-radio-group label{display:flex;align-items:center;gap:0.35rem;font-size:0.8rem;color:#4a5568;cursor:pointer}';
    html += '.merch-radio-group input{accent-color:#0088c2}';
    html += '.scorecard-section{margin-top:1.5rem;padding-top:1.5rem;border-top:1px solid #e0e0e0}';
    html += '.scorecard-customer-select{display:flex;gap:1rem;align-items:center;margin-bottom:1.25rem}';
    html += '.scorecard-customer-select label{font-weight:500;color:#1e3a5f}';
    html += '.scorecard-customer-select select{padding:0.5rem 1rem;border:1px solid #ddd;border-radius:8px;font-size:0.875rem;min-width:250px}';
    html += '.scorecard-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem}';
    html += '.scorecard-metric{background:#f5f5f7;border-radius:10px;padding:1rem;text-align:center}';
    html += '.scorecard-metric .value{font-size:1.75rem;font-weight:700;color:#1e3a5f}';
    html += '.scorecard-metric .label{font-size:0.75rem;color:#86868b;margin-top:0.25rem}';
    html += '.scorecard-health{padding:0.75rem 1.5rem;border-radius:8px;font-weight:600;display:inline-block;margin-top:0.5rem}';
    html += '.scorecard-health.strong{background:#d4edda;color:#155724}';
    html += '.scorecard-health.moderate{background:#fff3cd;color:#856404}';
    html += '.scorecard-health.opportunity{background:#f8d7da;color:#721c24}';
    html += '.scorecard-top-cats{margin-top:1.25rem}';
    html += '.scorecard-top-cats h4{font-size:0.875rem;color:#1e3a5f;margin:0 0 0.75rem}';
    html += '.scorecard-cat-item{display:flex;justify-content:space-between;padding:0.5rem 0;border-bottom:1px solid #eee;font-size:0.875rem}';
    html += '.scorecard-cat-item:last-child{border-bottom:none}';
    html += '.scorecard-empty{text-align:center;padding:2rem;color:#86868b}';

    // Treemap Shelf - pushes content instead of overlay
    html += '.main-with-shelf{display:flex;min-height:calc(100vh - 60px)}';
    html += '.treemap-shelf{width:0;overflow:hidden;background:#fff;border-right:1px solid #e0e0e0;transition:width 0.3s ease;display:flex;flex-direction:column;flex-shrink:0}';
    html += '.treemap-shelf.open{width:320px}';
    html += '.treemap-shelf-inner{width:320px;display:flex;flex-direction:column;height:100%}';
    html += '.treemap-shelf-header{padding:1rem 1.25rem;border-bottom:1px solid #e0e0e0;display:flex;justify-content:space-between;align-items:center;background:#f8f9fa}';
    html += '.treemap-shelf-title{font-size:1rem;font-weight:600;color:#1e3a5f;display:flex;align-items:center;gap:0.5rem}';
    html += '.treemap-shelf-close{background:none;border:none;font-size:1.5rem;cursor:pointer;color:#86868b;padding:0;line-height:1}';
    html += '.treemap-shelf-close:hover{color:#1e3a5f}';
    html += '.treemap-shelf-controls{padding:0.75rem 1.25rem;border-bottom:1px solid #e0e0e0;display:flex;gap:0.5rem}';
    html += '.treemap-mode-btn{flex:1;padding:0.5rem;border:1px solid #ddd;background:#fff;border-radius:6px;font-size:0.8125rem;font-weight:500;cursor:pointer;transition:all 0.15s}';
    html += '.treemap-mode-btn.active{background:#1e3a5f;color:#fff;border-color:#1e3a5f}';
    html += '.treemap-shelf-total{padding:0.75rem 1.25rem;background:#f0f4f8;font-size:0.9375rem;color:#1e3a5f;font-weight:600;border-bottom:1px solid #e0e0e0}';
    html += '.treemap-shelf-content{flex:1;overflow-y:auto;padding:1rem}';
    html += '.treemap-grid{display:flex;flex-wrap:wrap;gap:5px}';
    html += '.treemap-tile{border-radius:4px;padding:0.625rem;cursor:pointer;color:#fff;text-shadow:0 1px 3px rgba(0,0,0,0.5);display:flex;flex-direction:column;justify-content:center;transition:transform 0.1s,box-shadow 0.1s;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,sans-serif}';
    html += '.treemap-tile:hover{transform:scale(1.03);box-shadow:0 4px 12px rgba(0,0,0,0.3);z-index:1}';
    html += '.treemap-tile.active{outline:3px solid #fff;outline-offset:-3px}';
    html += '.treemap-tile-name{font-weight:700;font-size:0.8125rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:0.01em}';
    html += '.treemap-tile-qty{font-size:1.125rem;font-weight:800}';
    html += '.treemap-tile-pct{font-size:0.6875rem;opacity:0.85;font-weight:600}';
    html += '.treemap-toggle-btn{position:fixed;left:0;top:50%;transform:translateY(-50%);background:#1e3a5f;color:#fff;border:none;padding:0.75rem 0.5rem;border-radius:0 8px 8px 0;cursor:pointer;font-size:0.75rem;font-weight:600;writing-mode:vertical-rl;text-orientation:mixed;box-shadow:2px 0 8px rgba(0,0,0,0.15);z-index:999;transition:opacity 0.3s ease}';
    html += '.treemap-toggle-btn:hover{background:#2d4a6f}';
    html += '.treemap-toggle-btn.shelf-open{opacity:0;pointer-events:none}';
    html += '.main-content-area{flex:1;min-width:0;overflow-x:hidden}';
    html += '.treemap-clear-btn{margin-left:auto;background:#ff3b30;color:#fff;border:none;padding:0.375rem 0.75rem;border-radius:6px;font-size:0.75rem;font-weight:600;cursor:pointer}';
    html += '.treemap-clear-btn:hover{background:#e0352b}';
    html += '.treemap-clear-btn.hidden{display:none}';
    html += '.treemap-shelf-total{display:flex;align-items:center;gap:0.75rem}';
    html += '@media(max-width:900px){.treemap-shelf.open{width:260px}.treemap-shelf-inner{width:260px}}';
    // Stacked bar chart styles
    html += '.stacked-bar-container{padding:0.5rem 0}';
    html += '.stacked-bar{display:flex;width:100%;height:36px;border-radius:4px;overflow:hidden;cursor:pointer}';
    html += '.stacked-bar-segment{height:100%;display:flex;align-items:center;justify-content:center;color:#fff;font-size:0.6875rem;font-weight:700;text-shadow:0 1px 2px rgba(0,0,0,0.5);overflow:hidden;white-space:nowrap;transition:opacity 0.15s;position:relative}';
    html += '.stacked-bar-segment:hover{opacity:0.85}';
    html += '.stacked-bar-segment.active{outline:2px solid #fff;outline-offset:-2px}';
    html += '.stacked-bar-legend{display:flex;flex-direction:column;gap:4px;margin-top:0.75rem}';
    html += '.stacked-bar-legend-item{display:flex;align-items:center;gap:0.5rem;padding:0.375rem 0.5rem;border-radius:4px;cursor:pointer;transition:background 0.15s;font-size:0.8125rem}';
    html += '.stacked-bar-legend-item:hover{background:#f0f4f8}';
    html += '.stacked-bar-legend-item.active{background:#e8f0fe}';
    html += '.stacked-bar-legend-swatch{width:14px;height:14px;border-radius:3px;flex-shrink:0}';
    html += '.stacked-bar-legend-name{flex:1;font-weight:600;color:#1e3a5f}';
    html += '.stacked-bar-legend-qty{font-weight:700;color:#1e3a5f;font-size:0.8125rem}';
    html += '.stacked-bar-legend-pct{color:#86868b;font-size:0.75rem;min-width:40px;text-align:right}';

    html += '</style><link rel="stylesheet" href="/sidebar-enhanced.css"></head><body>';
    
    // Filter summary side panel only (badge is now inline in filters)
    html += '<div class="filter-summary-panel" id="filterSummaryPanel"><div class="filter-summary-header"><span class="filter-summary-title" id="filterPanelTitle">Active Filters (0)</span><button class="filter-summary-close" onclick="closeFilterPanel()">×</button></div><div class="filter-summary-body" id="filterPanelBody"></div><div class="filter-summary-footer"><button class="clear-all-filters-btn" onclick="clearAllFiltersFromPanel()">Clear All Filters</button></div></div>';
    
    html += '<div id="loginPage" class="login-page" style="display:none"><div class="login-box"><h1>Mark Edwards Apparel<br><span style="font-size:0.8em;font-weight:normal">Product Catalog</span></h1><form id="loginForm"><div class="form-group"><label>Select User</label><select id="loginUserSelect" required style="width:100%;padding:0.875rem 1rem;border:none;border-radius:12px;font-size:1rem;background:#f5f5f7;appearance:none;cursor:pointer"><option value="">-- Select your name --</option></select></div><input type="hidden" id="loginPin" value="0000"><button type="submit" class="btn btn-primary" style="width:100%">Sign In</button><div id="loginError" class="error hidden"></div></form></div></div>';
    
    html += '<div id="mainApp">';
    html += '<link rel="stylesheet" href="/order-requests.css">';
    html += '<header class="header"><h1 style="color:#1e3a5f;font-weight:700;font-size:1.5rem">Mark Edwards Apparel</h1><div class="header-right"><div class="user-menu-wrapper" style="position:relative"><button class="btn btn-secondary" id="userMenuBtn" style="display:flex;align-items:center;gap:0.5rem"><span id="userInfo">Welcome</span> ▾</button><div id="userMenu" class="user-menu hidden"><button class="user-menu-item" id="changePinBtn">Change PIN</button><button class="user-menu-item" id="logoutBtn">Sign Out</button></div></div><button class="btn btn-secondary" id="helpBtn">User Guide</button><button class="btn btn-secondary" onclick="toggleOrdersList()">Orders</button><a href="https://orders.markedwards.cloud/" target="_blank" class="btn btn-secondary" style="text-decoration:none">Open Orders ↗</a><button class="btn btn-secondary" id="historyBtn">History</button><button class="btn btn-secondary" id="adminBtn">Admin</button></div></header>';

    // Toggle button for treemap (fixed position)
    html += '<button class="treemap-toggle-btn" id="openTreemapShelf">📊 Merch</button>';

    // Main content wrapper with shelf
    html += '<div class="main-with-shelf">';

    // Treemap Shelf (pushes content)
    html += '<div class="treemap-shelf" id="treemapShelf"><div class="treemap-shelf-inner">';
    html += '<div class="treemap-shelf-header"><span class="treemap-shelf-title">📊 <span id="treemapTitle">By Commodity</span></span><button class="treemap-shelf-close" id="closeTreemapShelf">×</button></div>';
    html += '<div class="treemap-shelf-controls"><button class="treemap-mode-btn active" id="treemapModeCommodity" data-mode="commodity">Commodity</button><button class="treemap-mode-btn" id="treemapModeColor" data-mode="color">Color</button></div>';
    html += '<div class="treemap-shelf-controls" style="padding-top:0;border-bottom:1px solid #e0e0e0"><button class="treemap-mode-btn active" id="treemapViewTiles" data-view="tiles" style="flex:1">▦ Tiles</button><button class="treemap-mode-btn" id="treemapViewBar" data-view="bar" style="flex:1">▬ Bar</button></div>';
    html += '<div class="treemap-shelf-total"><span id="treemapTotal">0</span> units total<button class="treemap-clear-btn hidden" id="treemapClearFilter">✕ Clear Filter</button></div>';
    html += '<div class="treemap-shelf-content"><div class="treemap-grid" id="treemapGrid"></div></div>';
    html += '</div></div>';

    // Main content area
    html += '<div class="main-content-area">';

    // History panel (visible to all users)
    html += '<main class="main"><div id="historyPanel" class="admin-panel hidden"><h2>History & Status</h2><div class="tabs"><button class="tab active" data-tab="shares">Sharing History</button><button class="tab" data-tab="freshness">Data Freshness</button><button class="tab" data-tab="history">Sync History</button></div>';
    html += '<div id="sharesTab" class="tab-content active"><table class="share-history-table"><thead><tr><th>Date</th><th>Name</th><th>Sales Rep</th><th>Type</th><th>Items</th><th>Actions</th></tr></thead><tbody id="sharesTable"></tbody></table></div>';
    html += '<div id="freshnessTab" class="tab-content"><div class="freshness-info" id="freshnessInfo"><p><strong>Last Data Update:</strong> <span id="lastUpdateTime">Loading...</span></p><p><strong>Records Imported:</strong> <span id="lastUpdateRecords">-</span></p></div><div id="freshnessDetailPanel" style="margin-top:1rem;padding:1rem;background:#f5f5f7;border-radius:12px"><div style="font-weight:600;color:#1e3a5f;margin-bottom:0.5rem">Data Feed Status</div><div id="freshnessDetailPanelList">Loading detail...</div></div><p style="color:#666;font-size:0.875rem;margin-top:1rem">This shows when each data feed was last updated via CSV import.</p></div>';
    html += '<div id="historyTab" class="tab-content"><table><thead><tr><th>Date</th><th>Type</th><th>Status</th><th>Records</th><th>Error</th></tr></thead><tbody id="historyTable"></tbody></table></div></div>';
    
    // Admin panel (admin only)
    html += '<div id="adminPanel" class="admin-panel hidden"><h2>Admin Settings</h2><div class="tabs"><button class="tab active" data-tab="zoho2">Zoho Sync</button><button class="tab" data-tab="import2">Import CSV</button><button class="tab" data-tab="sales2">Import Sales</button><button class="tab" data-tab="autoimport2">Auto Import</button><button class="tab" data-tab="ai2">AI Analysis</button><button class="tab" data-tab="cache2">Image Cache</button><button class="tab" data-tab="users2">Users</button><button class="tab" data-tab="system2">System Health</button><button class="tab" data-tab="merch2">Merchandising</button><button class="tab" data-tab="catalogShare2">📧 Catalog Sharing</button></div>';
    html += '<div id="zoho2Tab" class="tab-content active"><div class="status-box"><div class="status-item"><span class="status-label">Status: </span><span class="status-value" id="zohoStatusText">Checking...</span></div><div class="status-item"><span class="status-label">Workspace ID: </span><span class="status-value" id="zohoWorkspaceId">-</span></div><div class="status-item"><span class="status-label">View ID: </span><span class="status-value" id="zohoViewId">-</span></div></div><div style="display:flex;gap:1rem"><button class="btn btn-secondary" id="testZohoBtn">Test Connection</button><button class="btn btn-success" id="syncZohoBtn">Sync Now</button></div><div id="zohoMessage" style="margin-top:1rem"></div></div>';
    html += '<div id="import2Tab" class="tab-content"><div class="upload-area"><input type="file" id="csvFile" accept=".csv"><label for="csvFile">Click to upload CSV file</label></div><div id="importStatus"></div><button class="btn btn-danger" id="clearBtn" style="margin-top:1rem">Clear All Products</button></div>';
    html += '<div id="sales2Tab" class="tab-content"><p style="margin-bottom:1rem;color:#666">Import sales data (Sales Orders and Purchase Orders) from the PO-SO Query CSV export.</p><div class="upload-area"><input type="file" id="salesCsvFile" accept=".csv"><label for="salesCsvFile">Click to upload Sales CSV file</label></div><div id="salesImportStatus"></div><div id="salesDataStats" style="margin-top:1rem"></div><button class="btn btn-danger" id="clearSalesBtn" style="margin-top:1rem">Clear All Sales Data</button><p style="margin-top:0.5rem;font-size:0.75rem;color:#999">Use this to start fresh before uploading historical files.</p></div>';
    html += '<div id="autoimport2Tab" class="tab-content"><div class="status-box"><div class="status-item"><span class="status-label">Status: </span><span class="status-value" id="autoImportStatus">Checking...</span></div><div class="status-item"><span class="status-label">Check Interval: </span><span class="status-value" id="autoImportInterval">-</span></div><div class="status-item"><span class="status-label">Inventory Files: </span><span class="status-value" id="autoImportInventory">-</span></div><div class="status-item"><span class="status-label">Sales-PO Files: </span><span class="status-value" id="autoImportSales">-</span></div></div><p style="color:#666;font-size:0.875rem;margin-bottom:1rem">Automatically imports CSV files from two WorkDrive folders:<br>• <strong>Inventory folder</strong> - for Inventory Availability reports<br>• <strong>Sales-PO folder</strong> - for PO-SO Query exports</p><button class="btn btn-primary" id="checkWorkDriveBtn">Check All</button><button class="btn btn-secondary" id="checkSalesOnlyBtn" style="margin-left:0.5rem">Check Sales Only</button><button class="btn btn-danger" id="clearAutoImportBtn" style="margin-left:0.5rem">Clear History</button><div id="autoImportMessage" style="margin-top:1rem"></div><h4 style="margin-top:1.5rem;margin-bottom:0.5rem;border-top:1px solid #ddd;padding-top:1rem">🔄 Trigger Export via Zoho Flow</h4><p style="color:#666;font-size:0.8rem;margin-bottom:0.5rem">Trigger a new Zoho Analytics export. The file will be uploaded to WorkDrive and ready for import.</p><div style="display:flex;gap:0.5rem;align-items:center;margin-bottom:0.5rem"><button class="btn btn-success" id="triggerExportBtn">Trigger Export</button><button class="btn btn-secondary" id="clearStuckJobsBtn" style="font-size:0.75rem">Clear Stuck</button><span id="exportJobStatus" style="font-size:0.8rem;color:#666;margin-left:0.5rem"></span></div><div id="exportJobsList" style="max-height:120px;overflow-y:auto;font-size:0.75rem;margin-bottom:1rem"></div><h4 style="margin-top:1.5rem;margin-bottom:0.5rem">Recent Imports</h4><div id="recentImportsList" style="max-height:200px;overflow-y:auto;font-size:0.8rem"></div></div>';
    html += '<div id="ai2Tab" class="tab-content"><div class="status-box"><div class="status-item"><span class="status-label">API Status: </span><span class="status-value" id="aiStatusText">Checking...</span></div><div class="status-item"><span class="status-label">Products Analyzed: </span><span class="status-value" id="aiAnalyzedCount">-</span></div><div class="status-item"><span class="status-label">Remaining: </span><span class="status-value" id="aiRemainingCount">-</span></div></div><p style="color:#666;font-size:0.875rem;margin-bottom:1rem">AI analysis uses Claude Vision to generate searchable tags from product images. This enables searching by garment type (cardigan, hoodie), style (casual, formal), pattern (striped, floral), and more.</p><button class="btn btn-primary" id="runAiBtn">Analyze Next 100 Products</button><button class="btn btn-success" id="runAllAiBtn" style="margin-left:0.5rem">Analyze All (Background)</button><button class="btn btn-secondary" id="stopAiBtn" style="margin-left:0.5rem;display:none">Stop</button><div id="aiMessage" style="margin-top:1rem"></div></div>';
    html += '<div id="cache2Tab" class="tab-content"><div class="status-box"><div class="status-item"><span class="status-label">Cache Status: </span><span class="status-value" id="cacheStatus">Checking...</span></div><div class="status-item"><span class="status-label">Cached Images: </span><span class="status-value" id="cachedCount">-</span></div><div class="status-item"><span class="status-label">Total Products with Images: </span><span class="status-value" id="totalImagesCount">-</span></div><div class="status-item"><span class="status-label">Cache Size: </span><span class="status-value" id="cacheSize">-</span></div></div><p style="color:#666;font-size:0.875rem;margin-bottom:1rem">Image caching stores product images locally to reduce Zoho API calls and speed up image loading. Images are cached on first view and refreshed when you upload a new inventory CSV.</p><button class="btn btn-primary" id="refreshCacheBtn">Refresh All Images</button><button class="btn btn-danger" id="clearCacheBtn" style="margin-left:0.5rem">Clear Cache</button><div id="cacheMessage" style="margin-top:1rem"></div></div>';
    html += '<div id="users2Tab" class="tab-content"><table><thead><tr><th>Name</th><th>PIN</th><th>Role</th><th>Actions</th></tr></thead><tbody id="usersTable"></tbody></table><div class="add-form"><input type="text" id="newUserName" placeholder="Display Name"><select id="newRole"><option value="sales_rep">Sales Rep</option><option value="admin">Admin</option></select><button class="btn btn-primary" id="addUserBtn">Add User</button></div><p style="margin-top:1rem;font-size:0.8rem;color:#666">New users are assigned a random 4-digit PIN. They can change it after logging in.</p></div>';
    html += '<div id="system2Tab" class="tab-content"><div id="systemHealthContent"><p>Loading system health data...</p></div><button class="btn btn-secondary" id="refreshSystemBtn" style="margin-top:1rem">🔄 Refresh</button></div>';

    // Merchandising tab content
    html += '<div id="merch2Tab" class="tab-content">';
    html += '<div class="merch-section"><h3>📊 Category Mix Balance</h3>';
    html += '<div class="merch-chart-row">';
    html += '<div class="merch-chart-container"><div class="merch-donut-wrapper"><canvas id="merchDonutChart" width="280" height="280"></canvas><div class="merch-donut-center"><div class="total" id="merchDonutTotal">-</div><div class="label">Total Units</div></div></div></div>';
    html += '<div class="merch-legend" id="merchLegend"><p style="color:#86868b;text-align:center;padding:1rem">Loading...</p></div>';
    html += '</div></div>';
    html += '<div class="merch-section"><h3>📈 Category Performance (Volume vs Value)</h3>';
    html += '<div class="merch-bubble-controls"><div class="merch-radio-group"><span style="font-weight:500;margin-right:0.5rem">Y-Axis:</span><label><input type="radio" name="bubbleMetric" value="openOrders" checked> Open Orders</label><label><input type="radio" name="bubbleMetric" value="importPOs"> Import POs</label></div></div>';
    html += '<div class="merch-bubble-container"><canvas id="merchBubbleChart"></canvas></div></div>';
    html += '<div class="merch-section scorecard-section"><h3>🎯 Customer Assortment Scorecard</h3>';
    html += '<div class="scorecard-customer-select"><label>Select Customer:</label><select id="scorecardCustomer"><option value="">-- Choose a customer --</option></select></div>';
    html += '<div id="scorecardContent"><div class="scorecard-empty">Select a customer to view their assortment metrics</div></div></div>';
    html += '</div>';

    // Catalog Sharing tab content
    html += '<div id="catalogShare2Tab" class="tab-content">';
    html += '<h3 style="margin-top:0;color:#1e3a5f">📧 Automated Catalog Sharing</h3>';
    html += '<p style="color:#86868b;margin-bottom:20px;font-size:0.875rem">Set up automatic catalog emails to your buyers. They receive a link to a live, filtered view of your inventory.</p>';

    // Add New Subscription Form
    html += '<div style="background:#f5f5f7;border:1px solid #e5e5e7;border-radius:12px;padding:20px;margin-bottom:25px;">';
    html += '<h4 style="margin-top:0;color:#0088c2;font-size:1rem">➕ Add New Recipient</h4>';
    html += '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:15px;margin-bottom:15px;">';
    html += '<div><label style="display:block;color:#86868b;margin-bottom:5px;font-size:13px;">Recipient Name *</label><input type="text" id="subRecipientName" placeholder="Joe Smith" style="width:100%;padding:10px;border-radius:8px;border:1px solid #d2d2d7;background:white;color:#1e3a5f;box-sizing:border-box;font-size:0.875rem"></div>';
    html += '<div><label style="display:block;color:#86868b;margin-bottom:5px;font-size:13px;">Email Address *</label><input type="email" id="subRecipientEmail" placeholder="joe@burlington.com" style="width:100%;padding:10px;border-radius:8px;border:1px solid #d2d2d7;background:white;color:#1e3a5f;box-sizing:border-box;font-size:0.875rem"></div>';
    html += '<div><label style="display:block;color:#86868b;margin-bottom:5px;font-size:13px;">Company</label><input type="text" id="subCompany" placeholder="Burlington" style="width:100%;padding:10px;border-radius:8px;border:1px solid #d2d2d7;background:white;color:#1e3a5f;box-sizing:border-box;font-size:0.875rem"></div>';
    html += '</div>';

    html += '<div style="margin-bottom:15px;"><label style="display:block;color:#86868b;margin-bottom:5px;font-size:13px;">Categories (click to select)</label><div id="subCategoryPills" style="display:flex;flex-wrap:wrap;gap:8px;"></div></div>';

    html += '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:15px;margin-bottom:15px;">';
    html += '<div><label style="display:block;color:#86868b;margin-bottom:5px;font-size:13px;">Frequency</label><select id="subFrequency" style="width:100%;padding:10px;border-radius:8px;border:1px solid #d2d2d7;background:white;color:#1e3a5f;font-size:0.875rem"><option value="daily">Daily</option><option value="weekly" selected>Weekly</option><option value="biweekly">Every 2 Weeks</option><option value="monthly">Monthly</option></select></div>';
    html += '<div><label style="display:block;color:#86868b;margin-bottom:5px;font-size:13px;">Send Time</label><select id="subSendTime" style="width:100%;padding:10px;border-radius:8px;border:1px solid #d2d2d7;background:white;color:#1e3a5f;font-size:0.875rem"><option value="06:00">6:00 AM</option><option value="07:00">7:00 AM</option><option value="08:00" selected>8:00 AM</option><option value="09:00">9:00 AM</option><option value="10:00">10:00 AM</option><option value="11:00">11:00 AM</option><option value="12:00">12:00 PM</option><option value="13:00">1:00 PM</option><option value="14:00">2:00 PM</option><option value="15:00">3:00 PM</option><option value="16:00">4:00 PM</option><option value="17:00">5:00 PM</option></select></div>';
    html += '<div><label style="display:block;color:#86868b;margin-bottom:5px;font-size:13px;">Quantity View</label><select id="subQuantityMode" style="width:100%;padding:10px;border-radius:8px;border:1px solid #d2d2d7;background:white;color:#1e3a5f;font-size:0.875rem"><option value="available_now">Available Now</option><option value="left_to_sell">Left to Sell</option><option value="both">Both (Avail Now & Left to Sell)</option></select></div>';
    html += '</div>';

    html += '<div style="margin-bottom:15px;"><label style="display:block;color:#86868b;margin-bottom:5px;font-size:13px;">Send Days (click to select multiple)</label>';
    html += '<div id="subDayPills" style="display:flex;flex-wrap:wrap;gap:8px;">';
    html += '<div class="sub-day-pill active" data-day="monday" onclick="toggleSubDay(this,\'monday\')" style="padding:6px 14px;border-radius:20px;cursor:pointer;font-size:13px;border:1px solid #0088c2;background:#0088c2;color:white;font-weight:600;">Mon</div>';
    html += '<div class="sub-day-pill" data-day="tuesday" onclick="toggleSubDay(this,\'tuesday\')" style="padding:6px 14px;border-radius:20px;cursor:pointer;font-size:13px;border:1px solid #d2d2d7;background:transparent;color:#6e6e73;">Tue</div>';
    html += '<div class="sub-day-pill" data-day="wednesday" onclick="toggleSubDay(this,\'wednesday\')" style="padding:6px 14px;border-radius:20px;cursor:pointer;font-size:13px;border:1px solid #d2d2d7;background:transparent;color:#6e6e73;">Wed</div>';
    html += '<div class="sub-day-pill" data-day="thursday" onclick="toggleSubDay(this,\'thursday\')" style="padding:6px 14px;border-radius:20px;cursor:pointer;font-size:13px;border:1px solid #d2d2d7;background:transparent;color:#6e6e73;">Thu</div>';
    html += '<div class="sub-day-pill" data-day="friday" onclick="toggleSubDay(this,\'friday\')" style="padding:6px 14px;border-radius:20px;cursor:pointer;font-size:13px;border:1px solid #d2d2d7;background:transparent;color:#6e6e73;">Fri</div>';
    html += '<div class="sub-day-pill" data-day="saturday" onclick="toggleSubDay(this,\'saturday\')" style="padding:6px 14px;border-radius:20px;cursor:pointer;font-size:13px;border:1px solid #d2d2d7;background:transparent;color:#6e6e73;">Sat</div>';
    html += '<div class="sub-day-pill" data-day="sunday" onclick="toggleSubDay(this,\'sunday\')" style="padding:6px 14px;border-radius:20px;cursor:pointer;font-size:13px;border:1px solid #d2d2d7;background:transparent;color:#6e6e73;">Sun</div>';
    html += '</div></div>';

    html += '<div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:15px;margin-bottom:15px;">';
    html += '<div><label style="display:block;color:#86868b;margin-bottom:5px;font-size:13px;">Min Quantity</label><input type="number" id="subMinQty" value="0" min="0" style="width:100%;padding:10px;border-radius:8px;border:1px solid #d2d2d7;background:white;color:#1e3a5f;box-sizing:border-box;font-size:0.875rem"></div>';
    html += '<div style="display:flex;align-items:center;padding-top:20px;"><label style="color:#86868b;font-size:13px;cursor:pointer;"><input type="checkbox" id="subShowPricing" checked style="margin-right:8px;"> Show Pricing</label></div>';
    html += '<div style="display:flex;align-items:center;padding-top:20px;"><label style="color:#86868b;font-size:13px;cursor:pointer;"><input type="checkbox" id="subShowImages" checked style="margin-right:8px;"> Include Images</label></div>';
    html += '</div>';

    html += '<div style="margin-bottom:15px;"><label style="display:block;color:#86868b;margin-bottom:5px;font-size:13px;">Custom Message (optional - included in email)</label><textarea id="subCustomMessage" rows="2" placeholder="Hi Joe, here&#39;s your updated catalog for this week..." style="width:100%;padding:10px;border-radius:8px;border:1px solid #d2d2d7;background:white;color:#1e3a5f;resize:vertical;box-sizing:border-box;font-family:inherit;font-size:0.875rem"></textarea></div>';

    html += '<button onclick="createSubscription()" class="btn btn-primary" style="font-size:15px;padding:12px 30px;">✅ Add Subscription</button>';
    html += '</div>';

    // Active Subscriptions List
    html += '<h4 style="color:#0088c2;font-size:1rem">📋 Active Subscriptions</h4>';
    html += '<div id="subscriptionsList" style="margin-bottom:25px;"><p style="color:#86868b;">Loading...</p></div>';

    // Send History
    html += '<h4 style="color:#0088c2;margin-top:30px;font-size:1rem">📜 Send History</h4>';
    html += '<div id="sendHistoryList"><p style="color:#86868b;">Loading...</p></div>';
    html += '</div>';

    html += '</div>';

    html += '<div class="stats"><div><div class="stat-value" id="totalStyles">0</div><div class="stat-label">Styles</div></div><div id="availNowStat" class="stat-box"><div class="stat-value" id="totalAvailNow">0</div><div class="stat-label">Avail Now</div></div><div id="leftToSellStat" class="stat-box stat-active"><div class="stat-value" id="totalLeftToSell">0</div><div class="stat-label">Left to Sell</div></div>' + (SUPPLY_DEMAND_FEATURE_ENABLED ? '<div id="availToSellStat" class="stat-box" style="display:none"><div class="stat-value" id="totalAvailToSell" style="color:#1e3a5f">0</div><div class="stat-label">Avail to Sell</div></div><div id="oversoldStat" class="stat-box" style="display:none"><div class="stat-value" id="totalOversold" style="color:#ff3b30">0</div><div class="stat-label">Oversold</div></div>' : '') + '<div class="qty-toggle"><button class="qty-toggle-btn" id="toggleAvailableNow" data-mode="available_now">Available Now</button><button class="qty-toggle-btn active" id="toggleLeftToSell" data-mode="left_to_sell">Left to Sell</button>' + (SUPPLY_DEMAND_FEATURE_ENABLED ? '<div style="display:flex;align-items:center;gap:0.5rem;margin-left:1rem;padding-left:1rem;border-left:1px solid #ddd"><input type="checkbox" id="supplyDemandToggle" style="cursor:pointer"><label for="supplyDemandToggle" style="cursor:pointer;font-size:0.75rem;white-space:nowrap">Supply vs Demand</label></div>' : '') + '</div><div style="margin-left:auto;text-align:right;font-size:0.7rem;color:#999;position:relative"><span id="dataFreshness" style="cursor:pointer;text-decoration:underline dotted" onclick="toggleFreshnessDetail()">Loading...</span><div id="freshnessDropdown" style="display:none;position:absolute;right:0;top:1.5rem;background:#fff;border:1px solid #ddd;border-radius:8px;padding:0.75rem;min-width:320px;box-shadow:0 4px 12px rgba(0,0,0,0.15);z-index:1000;text-align:left;font-size:0.75rem"><div style="font-weight:600;color:#1e3a5f;margin-bottom:0.5rem;font-size:0.8rem">Data Freshness Detail</div><div id="freshnessDetailList">Loading...</div></div></div></div>';
    html += '<div class="view-controls"><div class="search-box" style="display:flex;align-items:center;gap:0.5rem;margin-right:1.5rem;position:relative"><input type="text" id="searchInput" placeholder="Search products..." style="padding:0.5rem 0.75rem;border:1px solid #ddd;border-radius:6px;font-size:0.875rem;width:200px"><button id="clearSearchBtn" style="padding:0.4rem 0.6rem;border:1px solid #ddd;background:#f5f5f5;border-radius:4px;cursor:pointer;font-size:0.75rem">Clear</button><span id="aiSearchIndicator" class="hidden" style="position:absolute;top:100%;left:0;font-size:0.65rem;color:#0088c2;white-space:nowrap">AI-enhanced search</span></div><label>View:</label><button class="size-btn" data-size="list">List</button><button class="size-btn" data-size="small">Small</button><button class="size-btn active" data-size="medium">Medium</button><button class="size-btn" data-size="large">Large</button><div class="feature-toggle active-indicator" id="groupByStyleWrapper"><input type="checkbox" id="groupByStyleToggle" checked><label for="groupByStyleToggle">Group by Style</label></div><label style="margin-left:1.5rem">Sort:</label><select id="sortSelect" style="padding:0.5rem 0.75rem;border:2px solid #1e3a5f;border-radius:8px;font-size:0.8125rem;background:#1e3a5f;color:white;font-weight:500;cursor:pointer"><option value="name-asc">Name A-Z</option><option value="name-desc">Name Z-A</option><option value="qty-high" selected>Qty High-Low</option><option value="qty-low">Qty Low-High</option><option value="newest">Newest First</option></select><div class="qty-filter-group" style="margin-left:1.5rem"><label>Qty:</label><input type="number" id="minQty" placeholder="Min"><span>-</span><input type="number" id="maxQty" placeholder="Max"><button id="resetQtyBtn" style="padding:0.4rem 0.75rem;border:1px solid #ddd;background:#f5f5f5;border-radius:4px;cursor:pointer;font-size:0.75rem">Reset</button></div><span style="margin-left:auto"></span><button class="select-mode-btn" id="selectModeBtn">Select for Sharing</button><button class="select-mode-btn" id="orderModeBtn" onclick="toggleOrderMode()" style="margin-left:0.5rem">📋 Create Order</button></div>';
    html += '<div class="filters"><button class="filter-btn special" data-special="new">New Arrivals</button><button class="filter-btn special" data-special="picks">My Picks</button><button class="filter-btn special" data-special="notes">Has Notes</button>' + (SUPPLY_DEMAND_FEATURE_ENABLED ? '<button class="filter-btn special" data-special="oversold" style="background:#fff0f0;border-color:#ff3b30;color:#ff3b30">Oversold</button>' : '') + '<button id="resetAllFiltersBtn" style="padding:0.5rem 1rem;border:1px solid #86868b;background:#f5f5f7;color:#1e3a5f;border-radius:980px;cursor:pointer;font-weight:600;font-size:0.8125rem;margin-left:1rem">✕ Clear All Filters</button><div class="filter-summary-badge" id="filterSummaryBadge" onclick="openFilterPanel()"><span>📋 View Active</span><span class="filter-count-badge" id="filterCountBadge">0</span></div><span class="filter-divider"></span><div style="display:inline-flex;position:relative;align-items:center;margin-right:0.5rem"><button class="filter-btn" id="colorFilterBtn" style="font-weight:500">Color: All ▼</button><button class="filter-btn hidden" id="clearColorBtn" style="margin-left:0.25rem;padding:0.4rem 0.625rem">✕</button><div id="colorDropdown" class="multi-dropdown hidden"><div class="multi-dropdown-header"><input type="text" id="colorSearch" placeholder="Search colors..." style="width:100%;padding:0.5rem;border:1px solid #ddd;border-radius:6px;font-size:0.875rem;margin-bottom:0.5rem"><div style="display:flex;gap:0.5rem"><button id="applyColorFilter" class="btn btn-primary btn-sm">Apply</button><button id="clearColorFilter" class="btn btn-secondary btn-sm">Clear</button></div></div><div id="colorList" class="multi-dropdown-list"></div></div></div><div style="display:inline-flex;position:relative;align-items:center;margin-right:0.5rem"><button class="filter-btn" id="customerFilterBtn" style="font-weight:500">Customer: All ▼</button><button class="filter-btn hidden" id="clearCustomerBtn" style="margin-left:0.25rem;padding:0.4rem 0.625rem">✕</button><div id="customerDropdown" class="multi-dropdown hidden"><div class="multi-dropdown-header"><input type="text" id="customerSearch" placeholder="Search customers..." style="width:100%;padding:0.5rem;border:1px solid #ddd;border-radius:6px;font-size:0.875rem;margin-bottom:0.5rem"><div style="display:flex;gap:0.5rem"><button id="applyCustomerFilter" class="btn btn-primary btn-sm">Apply</button><button id="clearCustomerFilter" class="btn btn-secondary btn-sm">Clear</button></div></div><div id="customerList" class="multi-dropdown-list"></div></div></div><div style="display:inline-flex;position:relative;align-items:center;margin-right:0.5rem"><button class="filter-btn" id="supplierFilterBtn" style="font-weight:500">Supplier: All ▼</button><button class="filter-btn hidden" id="clearSupplierBtn" style="margin-left:0.25rem;padding:0.4rem 0.625rem">✕</button><div id="supplierDropdown" class="multi-dropdown hidden"><div class="multi-dropdown-header"><input type="text" id="supplierSearch" placeholder="Search suppliers..." style="width:100%;padding:0.5rem;border:1px solid #ddd;border-radius:6px;font-size:0.875rem;margin-bottom:0.5rem"><div style="display:flex;gap:0.5rem"><button id="applySupplierFilter" class="btn btn-primary btn-sm">Apply</button><button id="clearSupplierFilter" class="btn btn-secondary btn-sm">Clear</button></div></div><div id="supplierList" class="multi-dropdown-list"></div></div></div><span class="filter-divider"></span><span id="categoryFilters"></span></div>';
    html += '<div class="product-grid size-medium" id="productGrid"></div><div class="empty hidden" id="emptyState">No products found.</div></main>';
    html += '</div></div>'; // Close main-content-area and main-with-shelf

    // Selection bar
    html += '<div class="order-bar" id="orderBar"><span class="order-bar-count"><span id="orderSelectedCount">0</span> items in order</span><div class="order-bar-actions"><button class="btn btn-clear-order" onclick="clearOrderSelection()">Clear</button><button class="btn btn-exit-order" onclick="toggleOrderMode()">Exit</button><button class="btn btn-review" onclick="showOrderReview()">Review & Submit →</button></div></div><div class="selection-bar" id="selectionBar"><span class="selection-count"><span id="selectedCount">0</span> items selected</span><div class="selection-actions"><button class="btn btn-secondary" id="togglePreviewBtn">Preview</button><button class="btn btn-secondary" id="clearSelectionBtn">Clear</button><button class="btn btn-secondary" id="exitSelectionBtn">Exit Selection Mode</button><button class="btn btn-primary" id="shareSelectionBtn">Share / Download</button></div></div>';
    html += '<div class="selection-preview" id="selectionPreview"><div class="selection-preview-header"><h3>Selected Items</h3><button class="selection-preview-close" id="closePreviewBtn">×</button></div><div class="selection-preview-stats"><span><strong id="previewStyleCount">0</strong> styles</span><span><strong id="previewColorCount">0</strong> SKUs</span><span><strong id="previewQtyTotal">0</strong> units</span></div><div class="selection-preview-list" id="selectionPreviewList"></div></div>';
    
    // Chat UI
    html += '<div class="chat-bubble" id="chatBubble" title="Ask me anything about inventory"><svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z"/></svg><span class="chat-bubble-label">Ask AI</span></div>';
    html += '<div class="chat-panel" id="chatPanel"><div class="chat-header"><h3>Product Assistant</h3><button class="chat-close" id="chatClose">&times;</button></div><div class="chat-messages" id="chatMessages"><div class="chat-message assistant">Hi! I can help you find products and search orders. Try asking me:<br><br><strong>Products:</strong><br>• "Show me navy sweaters"<br>• "Joggers with more than 1,000 units"<br><br><strong>Orders & Sales:</strong><br>• "What did Amazon order?"<br>• "Show me all POs"<br>• "What stores bought style 71169?"</div></div><div class="chat-input-area"><textarea class="chat-input" id="chatInput" placeholder="Ask about products or orders..." rows="1"></textarea><button class="chat-send" id="chatSend">Send</button></div></div>';
    
    // Share modal
    html += '<div class="share-modal" id="shareModal"><div class="share-modal-content"><h3>Share Selection</h3><div id="shareForm"><input type="text" id="selectionName" placeholder="Name this selection (e.g. Spring Collection for Acme Co)"><div style="margin:1rem 0"><label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;font-size:0.875rem;color:#4a5568"><input type="checkbox" id="hideQuantities" style="width:18px;height:18px;accent-color:#0088c2"> Hide quantities (Available Now & Left to Sell)</label></div><div class="share-modal-actions"><button class="btn btn-secondary" id="cancelShareBtn">Cancel</button><button class="btn btn-primary" id="createShareBtn">Create Link</button></div></div><div class="share-result hidden" id="shareResult"><p style="margin-bottom:1rem;color:#666" id="shareNameDisplay"></p><div class="share-buttons"><button class="share-action-btn" id="emailLinkBtn">Email Link</button><button class="share-action-btn" id="textLinkBtn">Text Link</button><button class="share-action-btn" id="copyLinkBtn">Copy Link</button><a class="share-action-btn" id="pdfLink" href="" target="_blank">Download PDF</a></div><div style="margin-top:1.5rem;text-align:center"><button class="btn btn-secondary" id="closeShareModalBtn">Done</button></div></div></div></div>';
    
    // Product modal
    html += '<div class="modal" id="modal"><div class="modal-content"><button class="modal-close" id="modalClose">&times;</button><div class="modal-body"><div class="modal-image"><img id="modalImage" src="" alt=""></div><div class="modal-details"><div style="margin-bottom:1.5rem;padding-bottom:1rem;border-bottom:1px solid #e0e0e0"><div class="product-style" id="modalStyle" style="color:#0088c2;font-size:0.875rem;font-weight:600;margin-bottom:0.25rem"></div><h2 id="modalName" style="margin:0;padding:0;font-size:1.75rem;font-weight:600;color:#1e3a5f;background:none"></h2><p id="modalCategory" style="color:#6e6e73;margin:0.25rem 0 0;font-size:0.875rem"></p></div><div id="modalColors"></div><div class="total-row"><span>Total Available</span><span id="modalTotal"></span></div><div class="modal-actions"><button class="btn btn-secondary btn-sm" id="modalPickBtn">♡ Add to My Picks</button></div><div id="sizeGridContainer" style="margin-top:0.75rem"></div><div class="sales-history-section"><h3 style="margin:1.5rem 0 0.5rem;font-size:1rem;display:flex;align-items:center;gap:0.5rem;color:#1e3a5f;background:none">Sales & Import PO History <span id="salesHistoryLoading" style="font-size:0.75rem;color:#666;font-weight:normal">(loading...)</span></h3><p style="margin:0 0 0.75rem;font-size:0.75rem;color:#999;font-style:italic">(Showing trailing 12 months)</p><div id="salesHistorySummary" style="display:flex;gap:0.5rem;margin-bottom:0.75rem"></div><div id="salesHistoryFilter" style="margin-bottom:0.5rem;font-size:0.8rem;color:#666"></div><div id="salesHistoryList" style="max-height:200px;overflow-y:auto;font-size:0.875rem"></div></div><div class="note-section"><label><strong>Notes:</strong></label><textarea id="modalNote" placeholder="Add notes about this product..."></textarea><button class="btn btn-sm btn-primary" id="saveNoteBtn">Save Note</button></div></div></div></div></div>';
    
    
    // Change PIN modal
    html += '<div class="pin-modal" id="pinModal"><div class="pin-modal-content"><h3>Change Your PIN</h3><div class="form-group"><label>Current PIN</label><input type="password" id="currentPinInput" maxlength="4" pattern="[0-9]{4}" inputmode="numeric" placeholder="••••"></div><div class="form-group"><label>New PIN</label><input type="password" id="newPinInput" maxlength="4" pattern="[0-9]{4}" inputmode="numeric" placeholder="••••"></div><div id="pinError" class="error hidden"></div><div id="pinSuccess" class="success hidden"></div><div class="pin-modal-actions"><button class="btn btn-secondary" id="cancelPinBtn">Cancel</button><button class="btn btn-primary" id="savePinBtn">Save PIN</button></div></div></div>';
    
    // Help modal
    html += '<div class="help-modal" id="helpModal"><div class="help-content"><button class="modal-close" id="helpClose">&times;</button><h2>📘 Product Catalog User Guide</h2><div class="help-sections">';
    
    // Overview
    html += '<div class="help-section"><h3>📦 Overview</h3><p style="background:#E8F4F8;padding:0.75rem;border-radius:6px;border-left:3px solid #0088C2"><strong>Live Inventory from Zoho ATS Report</strong><br>Your catalog syncs twice daily with Zoho Analytics to show real-time Available to Sell data.</p><div class="help-cards"><div class="help-card"><div class="help-icon">1</div><h4>Filter</h4><p>Category, Customer, Supplier, Color, Quantity - even combine multiple!</p></div><div class="help-card"><div class="help-icon">2</div><h4>Search</h4><p>Style numbers, names, colors, or AI-powered visual features</p></div><div class="help-card"><div class="help-icon">3</div><h4>AI Assistant</h4><p>Ask questions in plain English and get instant results</p></div><div class="help-card"><div class="help-icon">4</div><h4>Share</h4><p>Create custom catalogs to email or text to customers</p></div></div></div>';
    
    // Filtering
    html += '<div class="help-section"><h3>🔍 Filters & Search</h3><table class="help-table"><tr><td class="help-feature"><strong>Category Pills</strong></td><td>Click multiple categories (Hoody, Sweater, etc.) at once. They stay highlighted. Click "All" to clear.</td></tr><tr><td class="help-feature"><strong>Customer Filter</strong></td><td>Filter to show only styles associated with specific customers. Great for "What does Ross buy?"</td></tr><tr><td class="help-feature"><strong>Supplier Filter</strong></td><td>See styles from specific suppliers. Helpful for sourcing questions.</td></tr><tr><td class="help-feature"><strong>Color Filter</strong></td><td>Click "Color: All ▼" to filter by specific colors like Navy or Black.</td></tr><tr><td class="help-feature"><strong>Min/Max Qty</strong></td><td>Find styles with specific inventory levels. Min 2000 = high-volume items only.</td></tr><tr><td class="help-feature"><strong>View Active Filters</strong></td><td>Click "📋 View Active" badge (next to Clear All) to see all filters in one panel.</td></tr></table></div>';
    
    // AI Assistant
    html += '<div class="help-section"><h3>🤖 AI Product Assistant</h3><p>Ask questions in plain English - no clicking needed!</p><div style="background:#E8F4F8;padding:1rem;border-radius:8px;margin-top:0.75rem"><strong>Example Questions:</strong><ul style="margin:0.5rem 0 0;padding-left:1.5rem"><li>"Show me all dresses with at least 2000 units"</li><li>"What did Ross order last season?"</li><li>"Find hoodies in stock with 3+ colors"</li><li>"Show me new arrivals"</li><li>"What stores bought style 71169?"</li></ul></div><p style="margin-top:0.75rem;color:#666"><strong>Note:</strong> AI-applied filters show in the filter panel with "🤖 AI Assistant Active" indicator.</p></div>';
    
    // Sales Data & History
    html += '<div class="help-section"><h3>📊 Sales Data & History</h3><p>Click any product to see detailed sales information:</p><table class="help-table"><tr><td class="help-feature"><strong>Sales Orders Tab</strong></td><td>View past invoices and open sales orders from Zoho Books - see customer names, quantities, and dollar amounts.</td></tr><tr><td class="help-feature"><strong>Import POs Tab</strong></td><td>See incoming purchase orders with expected delivery dates.</td></tr><tr><td class="help-feature"><strong>Filter by Orders</strong></td><td>Ask AI: "What did Burlington order last quarter?" or "Show styles with active POs"</td></tr></table><p style="margin-top:0.75rem;background:#FFF3CD;padding:0.75rem;border-radius:6px;border-left:3px solid #FFC107;color:#856404"><strong>Pro Tip:</strong> This is a powerful feature! Use it to quickly answer customer questions about order history.</p></div>';
    
    // Quantity Toggle
    html += '<div class="help-section"><h3>📈 Available Now vs Left to Sell</h3><table class="help-table"><tr><td class="help-feature"><strong>Available Now</strong></td><td>Inventory in DC ready to ship TODAY. Use when discussing immediate delivery.</td></tr><tr><td class="help-feature"><strong>Left to Sell</strong></td><td>Available Now PLUS incoming POs. Use for seasonal planning and future commitments.</td></tr><tr><td class="help-feature"><strong>Toggle</strong></td><td>Click buttons in the stats bar to switch views. Selected mode is highlighted.</td></tr></table></div>';
    
    // Viewing Options
    html += '<div class="help-section"><h3>👁️ View Options</h3><table class="help-table"><tr><td class="help-feature"><strong>List / Small / Medium / Large</strong></td><td>Choose your preferred grid size. Medium is default.</td></tr><tr><td class="help-feature"><strong>Group by Style</strong></td><td>ON (default): Shows one card per base style with all colors combined. OFF: Each color is a separate card.</td></tr><tr><td class="help-feature"><strong>Sort Options</strong></td><td>Sort by Name (A-Z/Z-A), Quantity (High/Low), or Newest arrivals.</td></tr></table></div>';
    
    // Sharing
    html += '<div class="help-section"><h3>📤 Share Custom Catalogs</h3><div class="help-steps"><div class="help-step"><div class="step-num">1</div><div class="step-content"><strong>Enter Selection Mode</strong><p>Click "Select for Sharing" button (top right)</p></div></div><div class="help-step"><div class="step-num">2</div><div class="step-content"><strong>Select Products</strong><p>Click cards - checkmark appears. Click again to deselect.</p></div></div><div class="help-step"><div class="step-num">3</div><div class="step-content"><strong>Name & Share</strong><p>Click "Share X Products", give it a clear name</p></div></div><div class="help-step"><div class="step-num">4</div><div class="step-content"><strong>Send to Customer</strong><p>Copy link and send via email or text</p></div></div></div><p style="margin-top:1rem;color:#666"><strong>What customers see:</strong> Clean 3-column layout, product images, quantities (In DC / Coming Soon), colors with individual counts, PDF download option.</p><p style="margin-top:0.5rem;color:#666"><strong>Note:</strong> Sales history is NOT visible on shared links (privacy).</p></div>';
    
    // History
    html += '<div class="help-section"><h3>📜 History Panel</h3><p>Click "History" button (top right) to access:</p><table class="help-table"><tr><td class="help-feature"><strong>Sharing History</strong></td><td>See all catalogs you\'ve shared. View, copy link, or delete them.</td></tr><tr><td class="help-feature"><strong>Data Freshness</strong></td><td>Check when inventory was last updated from Zoho (updates twice daily).</td></tr><tr><td class="help-feature"><strong>Sync History</strong></td><td>View all data sync logs with timestamps and record counts.</td></tr></table></div>';
    
    // Pro Tips
    html += '<div class="help-section"><h3>💡 Pro Tips</h3><ul style="padding-left:1.5rem"><li><strong>Combine Filters:</strong> Category + Customer + Min Qty together = laser-focused results</li><li><strong>Use AI for Complex Queries:</strong> "Show tops Ross bought with 1000+ units" is faster than clicking</li><li><strong>Name Selections Clearly:</strong> "Burlington Spring 2025 - Hoodies" not "Selection 1"</li><li><strong>Check Data Freshness:</strong> Look at "Updated" time (top right) to see how current data is</li><li><strong>Mobile Works:</strong> Show shared catalogs on your phone during customer meetings</li><li><strong>Style Number Search:</strong> Know the style? Type it directly for instant results</li></ul></div>';
    
    // Keyboard Shortcuts
    html += '<div class="help-section"><h3>⌨️ Keyboard Shortcuts</h3><table class="help-table"><tr><td><kbd>←</kbd> <kbd>→</kbd> <kbd>↑</kbd> <kbd>↓</kbd></td><td>Navigate between products</td></tr><tr><td><kbd>Enter</kbd></td><td>Open product / Toggle selection in selection mode</td></tr><tr><td><kbd>Space</kbd></td><td>Toggle selection (in selection mode)</td></tr><tr><td><kbd>Esc</kbd></td><td>Close any open modal</td></tr></table></div>';
    
    // FAQ
    html += '<div class="help-section"><h3>❓ FAQ</h3><div class="faq-item"><strong>Q: What is "Live ATS Report"?</strong><p>A: ATS = Available to Sell. Data syncs from Zoho Analytics twice daily showing current inventory.</p></div><div class="faq-item"><strong>Q: Can I select multiple categories?</strong><p>A: Yes! Click multiple category pills and they all stay active. Products from ANY selected category will show.</p></div><div class="faq-item"><strong>Q: Why do I see "146 groups" instead of "292 styles"?</strong><p>A: "Group by Style" is ON - color variants are combined. Toggle OFF to see each color separately.</p></div><div class="faq-item"><strong>Q: Can customers place orders from shared links?</strong><p>A: No, shared links are view-only. They see products and quantities but cannot order.</p></div><div class="faq-item"><strong>Q: Are my picks/notes private?</strong><p>A: Yes, picks and notes are saved to your account only.</p></div></div>';
    
    html += '</div></div></div>';
    
    // Order Review Overlay
    html += '<div class="or-review-overlay" id="orderReviewOverlay" onclick="if(event.target===this)closeOrderReview()"><div class="or-review-box" id="orderReviewContent"></div></div>';

    html += '<script>';
    html += 'var products=[];var allProducts=[];var groupedProducts=[];var lastImportId=null;var selectedCategories=[];var colorFilter=null;var specialFilter=null;var departmentFilter=null;var currentSort="qty-high";var currentSize="medium";var selectedProducts=[];var selectionMode=false;var currentShareId=null;var userPicks=[];var userNotes={};var currentModalProductId=null;var currentModalBaseStyle=null;var focusedIndex=-1;var qtyMode="left_to_sell";var groupByStyle=true;var minColorsFilter=0;var supplyDemandMode=false;var openOrdersByStyle={};var importPOsByStyle={};';
    
    html += 'function checkSession(){loadProducts();loadPicks();loadNotes();loadZohoStatus();loadDataFreshness();loadShares();loadHistory()}';
    html += 'function showApp(displayName,r){document.getElementById("loginPage").style.display="none";document.getElementById("mainApp").style.display="block";document.getElementById("userInfo").textContent=displayName||"User";if(r==="admin"){document.getElementById("adminBtn").style.display="inline-block"}}';
    
    html += 'var currentDisplayName="";';
    html += 'function loadLoginUsers(){showApp("User","admin");loadProducts();loadPicks();loadNotes();loadZohoStatus();loadDataFreshness();loadShares();loadHistory();loadUsers();loadAiStatus()}';
    
    html += 'document.getElementById("logoutBtn").addEventListener("click",function(){fetch("/api/logout",{method:"POST"}).then(function(){location.reload()})});';
    html += 'document.getElementById("userMenuBtn").addEventListener("click",function(e){e.stopPropagation();document.getElementById("userMenu").classList.toggle("hidden")});';
    html += 'document.addEventListener("click",function(e){if(!e.target.closest(".user-menu-wrapper")){document.getElementById("userMenu").classList.add("hidden")}});';
    html += 'document.getElementById("changePinBtn").addEventListener("click",function(){document.getElementById("userMenu").classList.add("hidden");document.getElementById("pinModal").classList.add("active");document.getElementById("currentPinInput").value="";document.getElementById("newPinInput").value="";document.getElementById("pinError").classList.add("hidden");document.getElementById("pinSuccess").classList.add("hidden")});';
    html += 'document.getElementById("cancelPinBtn").addEventListener("click",function(){document.getElementById("pinModal").classList.remove("active")});';
    html += 'document.getElementById("savePinBtn").addEventListener("click",function(){var currentPin=document.getElementById("currentPinInput").value;var newPin=document.getElementById("newPinInput").value;if(!/^\\d{4}$/.test(newPin)){document.getElementById("pinError").textContent="PIN must be 4 digits";document.getElementById("pinError").classList.remove("hidden");return}fetch("/api/change-pin",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({currentPin:currentPin,newPin:newPin})}).then(function(r){return r.json()}).then(function(d){if(d.success){document.getElementById("pinSuccess").textContent="PIN changed successfully!";document.getElementById("pinSuccess").classList.remove("hidden");document.getElementById("pinError").classList.add("hidden");setTimeout(function(){document.getElementById("pinModal").classList.remove("active")},1500)}else{document.getElementById("pinError").textContent=d.error;document.getElementById("pinError").classList.remove("hidden")}})});';
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
    
    html += 'function executeChatActions(actions){if(!actions||!actions.length)return;actions.forEach(function(a){switch(a.action){case"search":document.getElementById("searchInput").value=a.value||"";break;case"setCategory":currentFilter=a.value==="all"?"all":a.value;document.querySelectorAll(".filter-btn[data-cat]").forEach(function(b){b.classList.toggle("active",b.getAttribute("data-cat")===currentFilter)});break;case"setColor":colorFilter=a.value||null;var btn=document.getElementById("colorFilterBtn");btn.textContent=colorFilter?"Color: "+colorFilter+" ▼":"Color: All ▼";document.getElementById("clearColorBtn").classList.toggle("hidden",!colorFilter);break;case"setMinQty":document.getElementById("minQty").value=a.value||"";break;case"setMaxQty":document.getElementById("maxQty").value=a.value||"";break;case"setMinColors":minColorsFilter=a.value||0;break;case"clearFilters":document.getElementById("searchInput").value="";document.getElementById("minQty").value="";document.getElementById("maxQty").value="";currentFilter="all";colorFilter=null;specialFilter=null;departmentFilter=null;minColorsFilter=0;customerStyleFilter=null;document.querySelectorAll(".filter-btn").forEach(function(b){b.classList.remove("active")});document.querySelector(".filter-btn[data-cat=\\"all\\"]").classList.add("active");document.getElementById("colorFilterBtn").textContent="Color: All ▼";document.getElementById("clearColorBtn").classList.add("hidden");break;case"setSort":currentSort=a.value||"name-asc";document.getElementById("sortSelect").value=currentSort;break;case"showNewArrivals":specialFilter="new";document.querySelectorAll(".filter-btn[data-special]").forEach(function(b){b.classList.toggle("active",b.getAttribute("data-special")==="new")});break;case"showPicks":specialFilter="picks";document.querySelectorAll(".filter-btn[data-special]").forEach(function(b){b.classList.toggle("active",b.getAttribute("data-special")==="picks")});break;case"filterByCustomerOrders":filterByCustomerOrders(a.value);break;case"filterByPOStyles":filterByPOStyles();break}});renderProducts();window.scrollTo(0,0);if(window.innerWidth<=768){document.getElementById("chatPanel").classList.remove("active")}}';
    
    // Customer style filter variable
    html += 'var customerStyleFilter=null;var selectedCustomers=[];var selectedSuppliers=[];var allCustomers=[];var allSuppliers=[];var customerFilterStyles=[];var supplierFilterStyles=[];var aiFiltersActive=false;';
    
    // Filter products by customer orders - shows styles in stock that customer ordered
    html += 'async function filterByCustomerOrders(customer){var url="/api/sales-search?customer="+encodeURIComponent(customer);try{var resp=await fetch(url);var data=await resp.json();if(data.success&&data.orderedStyles&&data.orderedStyles.length>0){customerStyleFilter=data.orderedStyles;var inStockCount=0;allProducts.forEach(function(p){var baseStyle=p.style_id.split("-")[0];if(customerStyleFilter.indexOf(baseStyle)!==-1){var tot=0;(p.colors||[]).forEach(function(c){tot+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))});if(tot>0)inStockCount++}});addChatMessage("<strong>Showing "+inStockCount+" styles in stock</strong> that "+customer+" has ordered.<br><span style=\\"font-size:0.8rem;color:#86868b\\">From "+data.summary.styleCount+" total styles ordered ("+data.summary.totalQty.toLocaleString()+" units, $"+data.summary.totalAmount.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2})+")</span>","assistant");renderProducts();setTimeout(function(){window.scrollTo(0,0)},100)}else{addChatMessage("No orders found for \\""+customer+"\\".","assistant")}}catch(err){addChatMessage("Error searching orders: "+err.message,"assistant")}}';
    
    // Filter products by PO styles - shows styles in stock that have POs
    html += 'async function filterByPOStyles(){var url="/api/sales-search?type=po";try{var resp=await fetch(url);var data=await resp.json();if(data.success&&data.orderedStyles&&data.orderedStyles.length>0){customerStyleFilter=data.orderedStyles;var inStockCount=0;allProducts.forEach(function(p){var baseStyle=p.style_id.split("-")[0];if(customerStyleFilter.indexOf(baseStyle)!==-1){var tot=0;(p.colors||[]).forEach(function(c){tot+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))});if(tot>0)inStockCount++}});addChatMessage("<strong>Showing "+inStockCount+" styles in stock</strong> that have Purchase Orders.<br><span style=\\"font-size:0.8rem;color:#86868b\\">From "+data.summary.styleCount+" total styles with POs</span>","assistant");renderProducts();setTimeout(function(){window.scrollTo(0,0)},100)}else{addChatMessage("No purchase orders found.","assistant")}}catch(err){addChatMessage("Error searching POs: "+err.message,"assistant")}}';

    // Fetch open orders for Supply vs Demand feature
    html += 'async function fetchOpenOrders(){try{var resp=await fetch("/api/open-orders-by-style");var data=await resp.json();if(data.success){openOrdersByStyle=data.openOrders;importPOsByStyle=data.importPOs||{};console.log("Loaded open orders for",Object.keys(openOrdersByStyle).length,"styles");console.log("Loaded import POs for",Object.keys(importPOsByStyle).length,"styles")}else{console.error("Error loading open orders:",data.error)}}catch(err){console.error("Error fetching open orders:",err)}}';

    html += 'async function sendChatMessage(){var input=document.getElementById("chatInput");var msg=input.value.trim();if(!msg)return;addChatMessage(msg,"user");input.value="";input.style.height="auto";document.getElementById("chatSend").disabled=true;showTyping();try{var resp=await fetch("/api/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({message:msg})});var data=await resp.json();hideTyping();if(data.success){addChatMessage(data.message,"assistant");if(data.actions&&data.actions.length>0){executeChatActions(data.actions)}}else{addChatMessage("Sorry, I encountered an error. Please try again.","assistant")}}catch(err){hideTyping();addChatMessage("Sorry, something went wrong. Please try again.","assistant")}document.getElementById("chatSend").disabled=false}';

    // Merchandising tab functions
    html += 'var merchData=null;var merchBubbleMetric="openOrders";';
    html += 'var merchColors=["#1a5276","#0e6655","#7d3c98","#c0392b","#d4ac0d","#2471a3","#148f77","#a04000","#1f618d","#7b241c","#196f3d","#6c3483","#b9770e","#117864","#884ea0"];';

    html += 'async function loadMerchandisingTab(){try{var resp=await fetch("/api/merchandising/category-mix");var data=await resp.json();if(data.success){merchData=data;renderMerchDonutChart();renderMerchLegend();renderMerchBubbleChart()}populateScorecardCustomers()}catch(err){console.error("Error loading merchandising data:",err)}}';

    html += 'function renderMerchDonutChart(){var canvas=document.getElementById("merchDonutChart");if(!canvas||!merchData)return;var ctx=canvas.getContext("2d");var cats=merchData.categories;var total=merchData.totalLeftToSell||0;ctx.clearRect(0,0,canvas.width,canvas.height);var cx=140,cy=140,outerR=120,innerR=70;var startAngle=-Math.PI/2;cats.forEach(function(c,idx){var pct=(c.leftToSell||0)/total;if(pct===0)return;var endAngle=startAngle+pct*2*Math.PI;ctx.beginPath();ctx.moveTo(cx+innerR*Math.cos(startAngle),cy+innerR*Math.sin(startAngle));ctx.arc(cx,cy,outerR,startAngle,endAngle);ctx.arc(cx,cy,innerR,endAngle,startAngle,true);ctx.closePath();ctx.fillStyle=merchColors[idx%merchColors.length];ctx.fill();startAngle=endAngle});document.getElementById("merchDonutTotal").textContent=(total/1000).toFixed(0)+"K"}';

    html += 'function renderMerchLegend(){var el=document.getElementById("merchLegend");if(!el||!merchData)return;var html="";merchData.categories.forEach(function(c,idx){var warning=c.overIndexed?"<span class=\\"merch-legend-warning\\">OVER-INDEXED</span>":"";html+="<div class=\\"merch-legend-item\\"><div class=\\"merch-legend-color\\" style=\\"background:"+merchColors[idx%merchColors.length]+"\\"></div><div class=\\"merch-legend-info\\"><div class=\\"merch-legend-name\\">"+c.category+"</div><div class=\\"merch-legend-stats\\">"+(c.leftToSell/1000).toFixed(0)+"K units ("+c.mixPercentage+"%) · "+c.styleCount+" styles</div></div>"+warning+"</div>"});el.innerHTML=html||"<p style=\\"color:#86868b;text-align:center;padding:1rem\\">No data</p>"}';

    html += 'function renderMerchBubbleChart(){var container=document.getElementById("merchBubbleChart");if(!container||!merchData)return;var ctx=container.getContext("2d");var cats=merchData.categories;var w=container.parentElement.clientWidth;var h=350;container.width=w;container.height=h;ctx.clearRect(0,0,w,h);var padding={top:40,right:40,bottom:50,left:70};var chartW=w-padding.left-padding.right;var chartH=h-padding.top-padding.bottom;ctx.strokeStyle="#e0e0e0";ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(padding.left,padding.top);ctx.lineTo(padding.left,h-padding.bottom);ctx.lineTo(w-padding.right,h-padding.bottom);ctx.stroke();var maxX=Math.max.apply(null,cats.map(function(c){return c.leftToSell||0}))||1;var maxY=Math.max.apply(null,cats.map(function(c){return c[merchBubbleMetric]||0}))||1;var maxSize=Math.max.apply(null,cats.map(function(c){return c.styleCount||0}))||1;ctx.fillStyle="#86868b";ctx.font="11px -apple-system,BlinkMacSystemFont,sans-serif";ctx.textAlign="center";ctx.fillText("Inventory (Left to Sell)",w/2,h-10);ctx.save();ctx.translate(15,h/2);ctx.rotate(-Math.PI/2);ctx.fillText(merchBubbleMetric==="openOrders"?"Open Orders (units)":"Import POs (units)",0,0);ctx.restore();cats.forEach(function(c,idx){var x=padding.left+(c.leftToSell||0)/maxX*chartW;var y=h-padding.bottom-(c[merchBubbleMetric]||0)/maxY*chartH;var r=Math.max(8,Math.sqrt(c.styleCount/maxSize)*40);ctx.beginPath();ctx.arc(x,y,r,0,2*Math.PI);ctx.fillStyle=merchColors[idx%merchColors.length]+"99";ctx.fill();ctx.strokeStyle=merchColors[idx%merchColors.length];ctx.lineWidth=2;ctx.stroke();if(r>15){ctx.fillStyle="#1e3a5f";ctx.font="bold 9px -apple-system,BlinkMacSystemFont,sans-serif";ctx.textAlign="center";ctx.textBaseline="middle";ctx.fillText(c.category.substring(0,8),x,y)}})}';

    html += 'async function populateScorecardCustomers(){try{var resp=await fetch("/api/customers");var data=await resp.json();if(data.success){var sel=document.getElementById("scorecardCustomer");if(!sel)return;var opts="<option value=\\"\\">&mdash; Choose a customer &mdash;</option>";data.customers.forEach(function(c){opts+="<option value=\\""+c.name.replace(/"/g,"&quot;")+"\\">"+c.name+"</option>"});sel.innerHTML=opts}}catch(err){console.error("Error loading customers:",err)}}';

    html += 'async function loadCustomerScorecard(customerName){var content=document.getElementById("scorecardContent");if(!content)return;if(!customerName){content.innerHTML="<div class=\\"scorecard-empty\\">Select a customer to view their assortment metrics</div>";return}content.innerHTML="<div class=\\"scorecard-empty\\">Loading...</div>";try{var resp=await fetch("/api/merchandising/customer-scorecard/"+encodeURIComponent(customerName));var data=await resp.json();if(data.success){var healthClass=data.healthIndicator;var healthLabel=data.healthIndicator==="strong"?"Strong Breadth":data.healthIndicator==="moderate"?"Moderate Breadth":"Growth Opportunity";var html="<div class=\\"scorecard-grid\\"><div class=\\"scorecard-metric\\"><div class=\\"value\\">"+data.categoriesRepresented+"/"+data.totalCategories+"</div><div class=\\"label\\">Categories</div></div><div class=\\"scorecard-metric\\"><div class=\\"value\\">"+data.totalStyles+"</div><div class=\\"label\\">Styles</div></div><div class=\\"scorecard-metric\\"><div class=\\"value\\">"+(data.totalUnits/1000).toFixed(1)+"K</div><div class=\\"label\\">Units</div></div><div class=\\"scorecard-metric\\"><div class=\\"value\\">$"+(data.totalDollars/1000).toFixed(0)+"K</div><div class=\\"label\\">Dollars</div></div></div><div style=\\"text-align:center;margin-top:1rem\\"><div class=\\"scorecard-health "+healthClass+"\\">"+data.breadthScore+"% Breadth - "+healthLabel+"</div></div>";if(data.topCategories&&data.topCategories.length>0){html+="<div class=\\"scorecard-top-cats\\"><h4>Top Categories</h4>";data.topCategories.forEach(function(tc){html+="<div class=\\"scorecard-cat-item\\"><span>"+tc.category+"</span><span>"+(tc.units/1000).toFixed(1)+"K units · $"+(tc.dollars/1000).toFixed(0)+"K</span></div>"});html+="</div>"}content.innerHTML=html}else{content.innerHTML="<div class=\\"scorecard-empty\\">Error loading data</div>"}}catch(err){console.error("Error loading scorecard:",err);content.innerHTML="<div class=\\"scorecard-empty\\">Error loading data</div>"}}';

    html += 'document.querySelectorAll("input[name=\\"bubbleMetric\\"]").forEach(function(radio){radio.addEventListener("change",function(){merchBubbleMetric=this.value;renderMerchBubbleChart()})});';
    html += 'document.getElementById("scorecardCustomer").addEventListener("change",function(){loadCustomerScorecard(this.value)});';

    // Treemap Shelf Functions
    html += 'var treemapMode="commodity";var treemapFilters=[];var treemapView="tiles";'; // Array for multi-select

    html += 'function openTreemapShelf(){document.getElementById("treemapShelf").classList.add("open");document.getElementById("openTreemapShelf").classList.add("shelf-open");renderTreemap()}';
    html += 'function closeTreemapShelf(){document.getElementById("treemapShelf").classList.remove("open");document.getElementById("openTreemapShelf").classList.remove("shelf-open")}';

    html += 'document.getElementById("openTreemapShelf").addEventListener("click",openTreemapShelf);';
    html += 'document.getElementById("closeTreemapShelf").addEventListener("click",closeTreemapShelf);';

    // View toggle (Tiles vs Bar)
    html += 'document.getElementById("treemapViewTiles").addEventListener("click",function(){treemapView="tiles";document.getElementById("treemapViewTiles").classList.add("active");document.getElementById("treemapViewBar").classList.remove("active");renderTreemap()});';
    html += 'document.getElementById("treemapViewBar").addEventListener("click",function(){treemapView="bar";document.getElementById("treemapViewBar").classList.add("active");document.getElementById("treemapViewTiles").classList.remove("active");renderTreemap()});';

    // Mode switching
    html += 'document.getElementById("treemapModeCommodity").addEventListener("click",function(){treemapMode="commodity";document.getElementById("treemapModeCommodity").classList.add("active");document.getElementById("treemapModeColor").classList.remove("active");document.getElementById("treemapTitle").textContent="By Commodity";treemapFilters=[];clearTreemapFilter();renderTreemap()});';
    html += 'document.getElementById("treemapModeColor").addEventListener("click",function(){treemapMode="color";document.getElementById("treemapModeColor").classList.add("active");document.getElementById("treemapModeCommodity").classList.remove("active");document.getElementById("treemapTitle").textContent="By Color";treemapFilters=[];clearTreemapFilter();renderTreemap()});';
    html += 'document.getElementById("treemapClearFilter").addEventListener("click",function(){treemapFilters=[];clearTreemapFilter();renderTreemap()});';

    // Render treemap based on current mode and qtyMode
    html += 'function renderTreemap(){var data={};var total=0;allProducts.forEach(function(p){(p.colors||[]).forEach(function(c){var qty=qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0);if(qty<=0)return;total+=qty;var key=treemapMode==="commodity"?(p.category||"Uncategorized"):(c.color_name||"Unknown");if(!data[key])data[key]=0;data[key]+=qty})});var sorted=Object.entries(data).sort(function(a,b){return b[1]-a[1]});document.getElementById("treemapTotal").textContent=total.toLocaleString();if(treemapView==="bar"){renderStackedBar(sorted,total)}else{renderTreemapTiles(sorted,total)}}';

    // Render the actual tiles - bigger, more comfortable sizing
    html += 'function renderTreemapTiles(sorted,total){var grid=document.getElementById("treemapGrid");var html="";var containerWidth=295;sorted.forEach(function(item,i){var name=item[0];var qty=item[1];var pct=total>0?(qty/total*100):0;if(pct<0.3)return;var color=getTreemapColor(name,i);var width,height;if(pct>=20){width=containerWidth;height=75}else if(pct>=12){width=containerWidth;height=65}else if(pct>=8){width=(containerWidth/2)-3;height=70}else if(pct>=5){width=(containerWidth/2)-3;height=60}else if(pct>=3){width=(containerWidth/2)-3;height=50}else if(pct>=1.5){width=(containerWidth/3)-4;height=45}else{width=(containerWidth/4)-4;height=40}var isActive=treemapFilters.indexOf(name)!==-1?"active":"";html+="<div class=\\"treemap-tile "+isActive+"\\" style=\\"width:"+width+"px;height:"+height+"px;background:"+color+"\\" onclick=\\"filterByTreemap(\'"+name.replace(/\'/g,"\\\\\'")+"\')\\" title=\\""+name+": "+qty.toLocaleString()+" units ("+pct.toFixed(1)+"%)\\">";html+="<div class=\\"treemap-tile-name\\">"+name+"</div>";html+="<div class=\\"treemap-tile-qty\\">"+(qty>=1000?(qty/1000).toFixed(1)+"K":qty)+"</div>";html+="<div class=\\"treemap-tile-pct\\">"+pct.toFixed(1)+"%</div>";html+="</div>"});grid.innerHTML=html||"<p style=\\"padding:1rem;color:#86868b\\">No data</p>";document.getElementById("treemapClearFilter").classList.toggle("hidden",treemapFilters.length===0)}';

    // Get color for treemap tile
    html += 'function getTreemapColor(name,index){var colorMap={"Navy":"#1a365d","Black":"#1a1a1a","White":"#9ca3af","Grey":"#6b7280","Gray":"#6b7280","Red":"#dc2626","Blue":"#2563eb","Green":"#16a34a","Yellow":"#ca8a04","Orange":"#ea580c","Pink":"#ec4899","Purple":"#9333ea","Brown":"#78350f","Tan":"#a8896c","Cream":"#d4c5a9","Charcoal":"#374151","Burgundy":"#7f1d1d","Olive":"#4d7c0f","Teal":"#0d9488","Coral":"#f97316","Wine":"#7f1d1d","Ivory":"#f5f5dc","Khaki":"#c3b091","Oatmeal":"#c9b99a","Heather":"#9ca3af"};if(treemapMode==="color"){var lower=name.toLowerCase();for(var key in colorMap){if(lower.indexOf(key.toLowerCase())!==-1)return colorMap[key]}};return merchColors[index%merchColors.length]}';

    // Stacked bar chart rendering
    html += 'function renderStackedBar(sorted,total){var grid=document.getElementById("treemapGrid");var html="<div class=\\"stacked-bar-container\\"><div class=\\"stacked-bar\\">";sorted.forEach(function(item,i){var name=item[0];var qty=item[1];var pct=total>0?(qty/total*100):0;if(pct<0.5)return;var color=getTreemapColor(name,i);var isActive=treemapFilters.indexOf(name)!==-1?"active":"";html+="<div class=\\"stacked-bar-segment "+isActive+"\\" style=\\"width:"+pct+"%;background:"+color+"\\" onclick=\\"filterByTreemap(\'"+name.replace(/\'/g,"\\\\\'")+"\')\\" title=\\""+name+": "+qty.toLocaleString()+" units ("+pct.toFixed(1)+"%)\\">"+(pct>=6?name.substring(0,6):"")+"</div>"});html+="</div><div class=\\"stacked-bar-legend\\">";sorted.forEach(function(item,i){var name=item[0];var qty=item[1];var pct=total>0?(qty/total*100):0;if(pct<0.3)return;var color=getTreemapColor(name,i);var isActive=treemapFilters.indexOf(name)!==-1?"active":"";html+="<div class=\\"stacked-bar-legend-item "+isActive+"\\" onclick=\\"filterByTreemap(\'"+name.replace(/\'/g,"\\\\\'")+"\')\\">";html+="<div class=\\"stacked-bar-legend-swatch\\" style=\\"background:"+color+"\\"></div>";html+="<div class=\\"stacked-bar-legend-name\\">"+name+"</div>";html+="<div class=\\"stacked-bar-legend-qty\\">"+(qty>=1000?(qty/1000).toFixed(1)+"K":qty)+"</div>";html+="<div class=\\"stacked-bar-legend-pct\\">"+pct.toFixed(1)+"%</div>";html+="</div>"});html+="</div></div>";grid.innerHTML=html;document.getElementById("treemapClearFilter").classList.toggle("hidden",treemapFilters.length===0)}';

    // Filter by treemap tile click - multi-select
    html += 'function filterByTreemap(name){var idx=treemapFilters.indexOf(name);if(idx!==-1){treemapFilters.splice(idx,1)}else{treemapFilters.push(name)}applyTreemapFilters();renderTreemap()}';

    html += 'function applyTreemapFilters(){if(treemapFilters.length===0){clearTreemapFilter();return}if(treemapMode==="commodity"){selectedCategories=treemapFilters.slice();document.querySelectorAll("[data-cat]").forEach(function(btn){btn.classList.toggle("active",treemapFilters.indexOf(btn.getAttribute("data-cat"))!==-1)});document.querySelector("[data-cat=\\"all\\"]").classList.remove("active")}else{if(treemapFilters.length===1){colorFilter=treemapFilters[0];document.getElementById("colorFilterBtn").textContent="Color: "+treemapFilters[0]+" ▼"}else{colorFilter=treemapFilters;document.getElementById("colorFilterBtn").textContent="Color: "+treemapFilters.length+" selected ▼"}document.getElementById("clearColorBtn").classList.remove("hidden")}renderProducts()}';

    html += 'function clearTreemapFilter(){treemapFilters=[];if(treemapMode==="commodity"){selectedCategories=[];document.querySelectorAll("[data-cat]").forEach(function(btn){btn.classList.remove("active")});var allBtn=document.querySelector("[data-cat=\\"all\\"]");if(allBtn)allBtn.classList.add("active")}else{colorFilter=null;document.getElementById("colorFilterBtn").textContent="Color: All ▼";document.getElementById("clearColorBtn").classList.add("hidden")}document.getElementById("treemapClearFilter").classList.add("hidden");renderProducts()}';

    html += 'var tabs=document.querySelectorAll(".tab");for(var i=0;i<tabs.length;i++){tabs[i].addEventListener("click",function(e){var panel=e.target.closest(".admin-panel");panel.querySelectorAll(".tab").forEach(function(t){t.classList.remove("active")});panel.querySelectorAll(".tab-content").forEach(function(c){c.classList.remove("active")});e.target.classList.add("active");document.getElementById(e.target.getAttribute("data-tab")+"Tab").classList.add("active");if(e.target.getAttribute("data-tab")==="cache2")loadCacheStatus();if(e.target.getAttribute("data-tab")==="autoimport2"){loadAutoImportStatus();loadExportJobs()}if(e.target.getAttribute("data-tab")==="merch2")loadMerchandisingTab();if(e.target.getAttribute("data-tab")==="catalogShare2")loadCatalogSharingPanel()})}';
    
    html += 'var sizeBtns=document.querySelectorAll(".size-btn");sizeBtns.forEach(function(btn){btn.addEventListener("click",function(e){sizeBtns.forEach(function(b){b.classList.remove("active")});e.target.classList.add("active");currentSize=e.target.getAttribute("data-size");document.getElementById("productGrid").className="product-grid size-"+currentSize;renderProducts()})});';
    
    // Group by style toggle
    html += 'document.getElementById("groupByStyleToggle").addEventListener("change",function(){groupByStyle=this.checked;var wrapper=document.getElementById("groupByStyleWrapper");var label=wrapper.querySelector("label");if(this.checked){wrapper.classList.add("active-indicator");label.textContent="Grouped by Style ✓"}else{wrapper.classList.remove("active-indicator");label.textContent="Group by Style"}renderProducts()});';
    
    // Sort handler
    html += 'document.getElementById("sortSelect").addEventListener("change",function(e){currentSort=e.target.value;renderProducts()});';
    
    // Quantity mode toggle handlers
    html += 'document.getElementById("toggleAvailableNow").addEventListener("click",function(){qtyMode="available_now";document.getElementById("toggleAvailableNow").classList.add("active");document.getElementById("toggleLeftToSell").classList.remove("active");document.getElementById("availNowStat").classList.add("stat-active");document.getElementById("leftToSellStat").classList.remove("stat-active");renderProducts();if(document.getElementById("treemapShelf").classList.contains("open"))renderTreemap()});';
    html += 'document.getElementById("toggleLeftToSell").addEventListener("click",function(){qtyMode="left_to_sell";document.getElementById("toggleLeftToSell").classList.add("active");document.getElementById("toggleAvailableNow").classList.remove("active");document.getElementById("leftToSellStat").classList.add("stat-active");document.getElementById("availNowStat").classList.remove("stat-active");renderProducts();if(document.getElementById("treemapShelf").classList.contains("open"))renderTreemap()});';

    // Supply vs Demand toggle event listener
    html += 'if(document.getElementById("supplyDemandToggle")){document.getElementById("supplyDemandToggle").addEventListener("change",function(){supplyDemandMode=this.checked;renderProducts()})}';

    html += 'function loadZohoStatus(){fetch("/api/zoho/status").then(function(r){return r.json()}).then(function(d){var st=document.getElementById("zohoStatusText");if(d.connected){st.textContent="Connected";st.className="status-value connected"}else{st.textContent="Not connected";st.className="status-value disconnected"}document.getElementById("zohoWorkspaceId").textContent=d.workspaceId||"Not set";document.getElementById("zohoViewId").textContent=d.viewId||"Not set"})}';
    
    html += 'var freshnessDetailData=null;function toggleFreshnessDetail(){var dd=document.getElementById("freshnessDropdown");if(dd.style.display==="none"){dd.style.display="block";if(freshnessDetailData){renderFreshnessDetail(freshnessDetailData)}document.addEventListener("click",closeFreshnessDropdown,true)}else{dd.style.display="none";document.removeEventListener("click",closeFreshnessDropdown,true)}}function closeFreshnessDropdown(e){var dd=document.getElementById("freshnessDropdown");var trigger=document.getElementById("dataFreshness");if(dd&&!dd.contains(e.target)&&e.target!==trigger){dd.style.display="none";document.removeEventListener("click",closeFreshnessDropdown,true)}}';
    html += 'var freshnessTypeLabels={"lts_inventory":"LTS Inventory","avail_now_inventory":"Avail Now Inventory","lts_inventory_sizes":"LTS Inventory (by Size)","avail_now_inventory_sizes":"Avail Now Inventory (by Size)","sales_orders_pos":"Sales Orders & POs","combined_inventory":"Combined Inventory"};';
    html += 'function renderFreshnessDetail(d){var list=document.getElementById("freshnessDetailList");if(!list)return;var h="";var types=["lts_inventory","lts_inventory_sizes","avail_now_inventory","avail_now_inventory_sizes","sales_orders_pos"];var detailMap={};if(d.detail){d.detail.forEach(function(item){detailMap[item.data_type]=item})}types.forEach(function(t){var label=freshnessTypeLabels[t]||t;var item=detailMap[t];if(item){var dt=new Date(item.last_updated);var hoursSince=(Date.now()-dt.getTime())/(1000*60*60);var staleColor=hoursSince>24?"red":hoursSince>12?"orange":"green";var timeStr=dt.toLocaleDateString()+" "+dt.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});var rowCount=item.record_count?(" ("+item.record_count.toLocaleString()+" rows)"):"";h+="<div class=fd-row><span class=fd-label>"+label+"</span><span class=fd-count>"+rowCount+"</span><span class=fd-dot style=background:"+staleColor+"></span><span class=fd-time>"+timeStr+"</span></div>"}else{h+="<div class=fd-row><span class=fd-label>"+label+"</span><span class=fd-count></span><span class=fd-dot style=background:#ccc></span><span class=fd-time>No data</span></div>"}});if(d.sizeRows!==undefined){var sc=d.sizeRows>0?"green":"red";var st=d.sizeRows>0?d.sizeRows.toLocaleString()+" rows loaded":"⚠ EMPTY - no size data loaded";h+="<div class=fd-size style=color:"+sc+">Size Data: "+st+"</div>"}list.innerHTML=h}';
    html += 'function loadDataFreshness(){fetch("/api/data-freshness").then(function(r){return r.json()}).then(function(d){freshnessDetailData=d;renderFreshnessDetail(d);var panelList=document.getElementById("freshnessDetailPanelList");if(panelList){panelList.innerHTML=document.getElementById("freshnessDetailList")?document.getElementById("freshnessDetailList").innerHTML:""}if(d.lastUpdate){var dt=new Date(d.lastUpdate);document.getElementById("lastUpdateTime").textContent=dt.toLocaleString();document.getElementById("lastUpdateRecords").textContent=d.recordCount.toLocaleString()+" records";var hoursSince=(Date.now()-dt.getTime())/(1000*60*60);if(hoursSince>24){document.getElementById("freshnessInfo").classList.add("stale")}var freshnessEl=document.getElementById("dataFreshness");if(freshnessEl){var anyIssue=d.sizeRows===0;freshnessEl.innerHTML="Updated: "+dt.toLocaleDateString()+" "+dt.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"})+(anyIssue?" <span style=\"color:#e74c3c\">⚠</span>":"")+" ▾"}}else{document.getElementById("lastUpdateTime").textContent="No data imported yet";document.getElementById("lastUpdateRecords").textContent="-";var freshnessEl=document.getElementById("dataFreshness");if(freshnessEl){freshnessEl.textContent="No data yet"}}})}';

    
    html += 'function loadShares(){fetch("/api/selections").then(function(r){return r.json()}).then(function(shares){var h="";shares.forEach(function(s){var dt=new Date(s.created_at).toLocaleString();var type=s.share_type||"link";var badge=type==="pdf"?"<span class=\\"share-type-badge pdf\\">PDF</span>":"<span class=\\"share-type-badge link\\">Link</span>";var itemCount=(s.product_ids||[]).length;h+="<tr><td>"+dt+"</td><td>"+s.name+"</td><td>"+s.created_by+"</td><td>"+badge+"</td><td>"+itemCount+"</td><td><a href=\\"/share/"+s.share_id+"\\" target=\\"_blank\\">View</a></td></tr>"});document.getElementById("sharesTable").innerHTML=h||"<tr><td colspan=6 style=\\"text-align:center;color:#666\\">No shares yet</td></tr>"})}';
    
    html += 'document.getElementById("testZohoBtn").addEventListener("click",function(){document.getElementById("zohoMessage").innerHTML="Testing...";fetch("/api/zoho/test",{method:"POST"}).then(function(r){return r.json()}).then(function(d){document.getElementById("zohoMessage").innerHTML=d.success?"<span class=success>"+d.message+"</span>":"<span class=error>"+d.error+"</span>";loadZohoStatus()})});';
    html += 'document.getElementById("syncZohoBtn").addEventListener("click",function(){document.getElementById("zohoMessage").innerHTML="Syncing...";fetch("/api/zoho/sync",{method:"POST"}).then(function(r){return r.json()}).then(function(d){document.getElementById("zohoMessage").innerHTML=d.success?"<span class=success>"+d.message+"</span>":"<span class=error>"+d.error+"</span>";loadProducts();loadHistory();loadDataFreshness()})});';
    
    html += 'function getImageUrl(url){if(!url)return null;if(url.indexOf("download-accl.zoho.com")!==-1){return"/api/image/"+url.split("/").pop()}return url}';
    html += 'function loadProducts(){fetch("/api/products").then(function(r){return r.json()}).then(function(d){allProducts=d.products||d;lastImportId=d.lastImportId;products=allProducts;var hasAiTags=allProducts.some(function(p){return p.ai_tags&&p.ai_tags.length>0});document.getElementById("aiSearchIndicator").classList.toggle("hidden",!hasAiTags);renderFilters();renderProducts();loadCustomersList();loadSuppliersList()})}';
    
    // Load customers list
    html += 'function loadCustomersList(){fetch("/api/customers").then(function(r){return r.json()}).then(function(d){if(d.success){allCustomers=d.customers;renderCustomerDropdown()}})}';
    
    // Load suppliers list
    html += 'function loadSuppliersList(){fetch("/api/suppliers").then(function(r){return r.json()}).then(function(d){if(d.success){allSuppliers=d.suppliers;renderSupplierDropdown()}})}';
    
    // Render customer dropdown
    html += 'function renderCustomerDropdown(searchTerm){var list=document.getElementById("customerList");if(!list)return;var filtered=allCustomers;if(searchTerm){searchTerm=searchTerm.toLowerCase();filtered=allCustomers.filter(function(c){return c.name.toLowerCase().indexOf(searchTerm)!==-1})}var h="";filtered.slice(0,50).forEach(function(c){var checked=selectedCustomers.indexOf(c.name)!==-1?"checked":"";h+="<label class=\\"multi-option "+(checked?"selected":"")+"\\"><input type=\\"checkbox\\" "+checked+" value=\\""+c.name.replace(/"/g,"&quot;")+"\\" onchange=\\"toggleCustomerSelection(this)\\"><span>"+c.name+"</span><span class=\\"option-count\\">"+c.styleCount+" styles</span></label>"});list.innerHTML=h||"<div style=\\"padding:0.5rem;color:#666\\">No customers found</div>"}';
    
    // Render supplier dropdown
    html += 'function renderSupplierDropdown(searchTerm){var list=document.getElementById("supplierList");if(!list)return;var filtered=allSuppliers;if(searchTerm){searchTerm=searchTerm.toLowerCase();filtered=allSuppliers.filter(function(s){return s.name.toLowerCase().indexOf(searchTerm)!==-1})}var h="";filtered.slice(0,50).forEach(function(s){var checked=selectedSuppliers.indexOf(s.name)!==-1?"checked":"";h+="<label class=\\"multi-option "+(checked?"selected":"")+"\\"><input type=\\"checkbox\\" "+checked+" value=\\""+s.name.replace(/"/g,"&quot;")+"\\" onchange=\\"toggleSupplierSelection(this)\\"><span>"+s.name+"</span><span class=\\"option-count\\">"+s.styleCount+" styles</span></label>"});list.innerHTML=h||"<div style=\\"padding:0.5rem;color:#666\\">No suppliers found</div>"}';
    
    // Toggle customer selection
    html += 'function toggleCustomerSelection(checkbox){var name=checkbox.value;if(checkbox.checked){if(selectedCustomers.indexOf(name)===-1)selectedCustomers.push(name)}else{var idx=selectedCustomers.indexOf(name);if(idx!==-1)selectedCustomers.splice(idx,1)}checkbox.parentElement.classList.toggle("selected",checkbox.checked)}';
    
    // Toggle supplier selection
    html += 'function toggleSupplierSelection(checkbox){var name=checkbox.value;if(checkbox.checked){if(selectedSuppliers.indexOf(name)===-1)selectedSuppliers.push(name)}else{var idx=selectedSuppliers.indexOf(name);if(idx!==-1)selectedSuppliers.splice(idx,1)}checkbox.parentElement.classList.toggle("selected",checkbox.checked)}';
    
    // Apply customer filter
    html += 'async function applyCustomerFilter(){if(selectedCustomers.length===0){customerFilterStyles=[];document.getElementById("customerFilterBtn").textContent="Customer: All ▼";document.getElementById("clearCustomerBtn").classList.add("hidden");document.getElementById("customerFilterBtn").classList.remove("active")}else{var resp=await fetch("/api/styles-by-customers?customers="+encodeURIComponent(selectedCustomers.join(",")));var data=await resp.json();if(data.success){customerFilterStyles=data.styles;document.getElementById("customerFilterBtn").textContent="Customer: "+selectedCustomers.length+" selected ▼";document.getElementById("clearCustomerBtn").classList.remove("hidden");document.getElementById("customerFilterBtn").classList.add("active")}}document.getElementById("customerDropdown").classList.add("hidden");renderProducts()}';
    
    // Apply supplier filter
    html += 'async function applySupplierFilter(){if(selectedSuppliers.length===0){supplierFilterStyles=[];document.getElementById("supplierFilterBtn").textContent="Supplier: All ▼";document.getElementById("clearSupplierBtn").classList.add("hidden");document.getElementById("supplierFilterBtn").classList.remove("active")}else{var resp=await fetch("/api/styles-by-suppliers?suppliers="+encodeURIComponent(selectedSuppliers.join(",")));var data=await resp.json();if(data.success){supplierFilterStyles=data.styles;document.getElementById("supplierFilterBtn").textContent="Supplier: "+selectedSuppliers.length+" selected ▼";document.getElementById("clearSupplierBtn").classList.remove("hidden");document.getElementById("supplierFilterBtn").classList.add("active")}}document.getElementById("supplierDropdown").classList.add("hidden");renderProducts()}';
    
    // Clear customer filter
    html += 'function clearCustomerFilterFn(){selectedCustomers=[];customerFilterStyles=[];document.getElementById("customerFilterBtn").textContent="Customer: All ▼";document.getElementById("clearCustomerBtn").classList.add("hidden");document.getElementById("customerFilterBtn").classList.remove("active");renderCustomerDropdown();renderProducts()}';
    
    // Clear supplier filter
    html += 'function clearSupplierFilterFn(){selectedSuppliers=[];supplierFilterStyles=[];document.getElementById("supplierFilterBtn").textContent="Supplier: All ▼";document.getElementById("clearSupplierBtn").classList.add("hidden");document.getElementById("supplierFilterBtn").classList.remove("active");renderSupplierDropdown();renderProducts()}';
    
    html += 'function loadPicks(){fetch("/api/picks").then(function(r){return r.json()}).then(function(p){userPicks=p;renderProducts()})}';
    html += 'function loadNotes(){fetch("/api/notes").then(function(r){return r.json()}).then(function(n){userNotes=n;renderProducts()})}';
    
    html += 'var selectedColors=[];';
    html += 'function getBaseColor(name){if(!name)return"Unknown";var n=name.toUpperCase().trim();var parts=n.split(/[\\s\\/]+/);return parts[0]||"Unknown"}';
    html += 'function renderColorDropdown(){var colorCounts={};allProducts.forEach(function(p){(p.colors||[]).forEach(function(c){if(c.color_name){var base=getBaseColor(c.color_name);if(!colorCounts[base])colorCounts[base]={count:0,names:[]};var qty=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0));colorCounts[base].count+=qty;if(colorCounts[base].names.indexOf(c.color_name)===-1)colorCounts[base].names.push(c.color_name)}})});var sorted=Object.keys(colorCounts).sort(function(a,b){return colorCounts[b].count-colorCounts[a].count});var ch="";sorted.forEach(function(base){var d=colorCounts[base].count>=1000?(colorCounts[base].count/1000).toFixed(1)+"K":colorCounts[base].count.toString();var checked=selectedColors.indexOf(base)!==-1?"checked":"";ch+="<label class=\\"multi-dropdown-item\\"><input type=\\"checkbox\\" value=\\""+base+"\\" "+checked+"><span class=\\"multi-item-name\\">"+base+"</span><span class=\\"multi-item-count\\">"+d+"</span></label>"});document.getElementById("colorList").innerHTML=ch}';
    html += 'function applyColorSelection(){if(selectedColors.length===0){colorFilter=null;document.getElementById("colorFilterBtn").textContent="Color: All ▼";document.getElementById("clearColorBtn").classList.add("hidden")}else{var allColorNames=[];var colorCounts={};allProducts.forEach(function(p){(p.colors||[]).forEach(function(c){if(c.color_name){var base=getBaseColor(c.color_name);if(!colorCounts[base])colorCounts[base]=[];if(colorCounts[base].indexOf(c.color_name)===-1)colorCounts[base].push(c.color_name)}})});selectedColors.forEach(function(base){if(colorCounts[base]){colorCounts[base].forEach(function(cn){if(allColorNames.indexOf(cn)===-1)allColorNames.push(cn)})}});if(allColorNames.length===1){colorFilter=allColorNames[0]}else{colorFilter=allColorNames}if(selectedColors.length===1){document.getElementById("colorFilterBtn").textContent="Color: "+selectedColors[0]+" ▼"}else{document.getElementById("colorFilterBtn").textContent="Color: "+selectedColors.length+" selected ▼"}document.getElementById("clearColorBtn").classList.remove("hidden")}document.getElementById("colorDropdown").classList.add("hidden");renderProducts()}';
    html += 'function renderFilters(){var cats=[];allProducts.forEach(function(p){if(p.category&&cats.indexOf(p.category)===-1)cats.push(p.category)});cats.sort();var h="<button class=\\"filter-btn\\" data-cat=\\"all\\">All</button>";cats.forEach(function(c){h+="<button class=\\"filter-btn\\" data-cat=\\""+c+"\\">"+c+"</button>"});document.getElementById("categoryFilters").innerHTML=h;renderColorDropdown();document.querySelectorAll("[data-cat]").forEach(function(btn){btn.addEventListener("click",function(e){var cat=e.target.getAttribute("data-cat");if(cat==="all"){selectedCategories=[];document.querySelectorAll("[data-cat]").forEach(function(b){b.classList.remove("active")});e.target.classList.add("active")}else{var idx=selectedCategories.indexOf(cat);if(idx!==-1){selectedCategories.splice(idx,1);e.target.classList.remove("active")}else{selectedCategories.push(cat);e.target.classList.add("active")}document.querySelector("[data-cat=\\"all\\"]").classList.remove("active")}if(selectedCategories.length===0){document.querySelector("[data-cat=\\"all\\"]").classList.add("active")}renderProducts()})});document.querySelectorAll("[data-special]").forEach(function(btn){btn.addEventListener("click",function(e){var sp=e.target.getAttribute("data-special");if(specialFilter===sp){specialFilter=null;e.target.classList.remove("active")}else{document.querySelectorAll("[data-special]").forEach(function(b){b.classList.remove("active")});specialFilter=sp;e.target.classList.add("active")}renderProducts()})});setTimeout(function(){if(selectedCategories.length===0){var allBtn=document.querySelector("[data-cat=\\"all\\"]");if(allBtn)allBtn.classList.add("active")}},0)}';    
    // Selection mode toggle - button toggles on/off
    html += 'document.getElementById("selectModeBtn").addEventListener("click",function(){selectionMode=!selectionMode;this.classList.toggle("active",selectionMode);this.textContent=selectionMode?"✕ Exit Selection Mode":"Select for Sharing";if(!selectionMode){selectedProducts=[];updateSelectionUI()}renderProducts()});';
    
    html += 'document.getElementById("exitSelectionBtn").addEventListener("click",function(){selectionMode=false;selectedProducts=[];document.getElementById("selectModeBtn").classList.remove("active");document.getElementById("selectModeBtn").textContent="Select for Sharing";updateSelectionUI();renderProducts()});';
    
    html += 'function handleCardClick(id,e){if(e.target.classList.contains("pick-badge")){togglePick(id,e);return}if(typeof isOrderMode==="function"&&isOrderMode()){handleOrderCardClick(id);return}if(selectionMode){e.stopPropagation();var idx=selectedProducts.indexOf(id);if(idx===-1){selectedProducts.push(id)}else{selectedProducts.splice(idx,1)}updateSelectionUI();renderProducts()}else{showProductModal(id)}}';
    
    html += 'function togglePick(id,e){e.stopPropagation();var idx=userPicks.indexOf(id);if(idx===-1){fetch("/api/picks/"+id,{method:"POST"}).then(function(){userPicks.push(id);renderProducts()})}else{fetch("/api/picks/"+id,{method:"DELETE"}).then(function(){userPicks.splice(idx,1);renderProducts()})}}';
    
    html += 'function updateSelectionUI(){document.getElementById("selectedCount").textContent=selectedProducts.length;var bar=document.getElementById("selectionBar");var bubble=document.getElementById("chatBubble");if(selectedProducts.length>0&&selectionMode){bar.classList.add("visible");bubble.classList.add("selection-active")}else{bar.classList.remove("visible");bubble.classList.remove("selection-active");document.getElementById("selectionPreview").classList.remove("visible")}updateSelectionPreview()}';
    
    html += 'function showProductModal(id){currentModalProductId=id;var pr=products.find(function(p){return p.id===id});if(!pr)return;var baseStyle=pr.style_id.split("-")[0];currentModalBaseStyle=baseStyle;var imgUrl=getImageUrl(pr.image_url);document.getElementById("modalImage").src=imgUrl||"";document.getElementById("modalStyle").textContent=pr.style_id;document.getElementById("modalName").textContent=pr.name;var cols=pr.colors||[];var colorName=cols.length===1?cols[0].color_name:(pr.category||"");document.getElementById("modalCategory").textContent=colorName;var totNow=0,totLts=0;cols.forEach(function(c){var aNow=c.available_now||c.available_qty||0;var lts=c.left_to_sell||0;totNow+=aNow;totLts+=lts});var ch="";if(cols.length>1){ch="<table style=\\"width:100%;border-collapse:collapse;font-size:0.875rem\\"><thead><tr style=\\"border-bottom:1px solid #ddd\\"><th style=\\"text-align:left;padding:0.5rem 0;font-weight:600;color:#666\\">Color</th><th style=\\"text-align:right;padding:0.5rem 0;font-weight:600;color:#666;width:80px\\">Avail Now</th><th style=\\"text-align:right;padding:0.5rem 0;font-weight:600;color:#666;width:80px\\">Left to Sell</th></tr></thead><tbody>";cols.forEach(function(c){var aNow=c.available_now||c.available_qty||0;var lts=c.left_to_sell||0;ch+="<tr><td style=\\"padding:0.4rem 0\\">"+c.color_name+"</td><td style=\\"text-align:right;padding:0.4rem 0\\">"+aNow.toLocaleString()+"</td><td style=\\"text-align:right;padding:0.4rem 0;color:#666\\">"+lts.toLocaleString()+"</td></tr>"});ch+="</tbody></table>"}document.getElementById("modalColors").innerHTML=ch;var modalTotalHtml="<span style=\\"margin-right:2rem\\">Now: "+totNow.toLocaleString()+"</span><span>LTS: "+totLts.toLocaleString()+"</span>";if(supplyDemandMode){var openOrders=openOrdersByStyle[baseStyle]||0;var totalSupply=totNow+totLts;var availToSell=totalSupply-openOrders;var availColor=availToSell<0?"#ff3b30":"#1e3a5f";modalTotalHtml+="<div style=\\"margin-top:1rem;padding:0.75rem;background:#f8f9fa;border-radius:8px;font-size:0.875rem\\"><div style=\\"display:flex;justify-content:space-between;padding:0.4rem 0\\"><span>Supply (LTS):</span><span style=\\"font-weight:500\\">"+totalSupply.toLocaleString()+"</span></div><div style=\\"display:flex;justify-content:space-between;padding:0.4rem 0;border-bottom:1px solid #e0e0e0\\"><span>Demand (Open SOs):</span><span style=\\"font-weight:500\\">"+openOrders.toLocaleString()+"</span></div><div style=\\"display:flex;justify-content:space-between;padding:0.5rem 0 0.25rem;font-weight:700;font-size:0.95rem;color:"+availColor+"\\"><span>Available to Sell:</span><span>"+availToSell.toLocaleString()+"</span></div></div>"}document.getElementById("modalTotal").innerHTML=modalTotalHtml;document.getElementById("modalNote").value=userNotes[baseStyle]||"";document.getElementById("modalPickBtn").style.display="";var isPicked=userPicks.indexOf(id)!==-1;document.getElementById("modalPickBtn").textContent=isPicked?"♥ In My Picks":"♡ Add to My Picks";document.getElementById("modal").classList.add("active");loadSalesHistory(pr.style_id);var sizeStyle=pr.style_id;loadSizeGrid(pr.style_id)}';
    
    html += 'var currentSalesFilter="all";var currentSalesHistory=[];function loadSalesHistory(styleId){currentSalesFilter="all";document.getElementById("salesHistoryLoading").textContent="(loading...)";document.getElementById("salesHistorySummary").innerHTML="";document.getElementById("salesHistoryFilter").innerHTML="";document.getElementById("salesHistoryList").innerHTML="<div style=\\"color:#666;padding:0.5rem\\">Loading...</div>";fetch("/api/sales-history/"+encodeURIComponent(styleId)).then(function(r){return r.json()}).then(function(d){document.getElementById("salesHistoryLoading").textContent="";if(!d.success){document.getElementById("salesHistoryList").innerHTML="<div style=\\"color:#999;padding:0.5rem\\">Unable to load</div>";return}currentSalesHistory=d.history;var sum=d.summary;var invDollars=sum.totalInvoicedDollars?"$"+sum.totalInvoicedDollars.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}):"";var openDollars=sum.totalOpenOrdersDollars?"$"+sum.totalOpenOrdersDollars.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}):"";var poDollars=sum.totalPODollars?"$"+sum.totalPODollars.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}):"";document.getElementById("salesHistorySummary").innerHTML="<div onclick=\\"filterSalesHistory(\'invoiced\')\\" style=\\"flex:1;padding:0.5rem 0.75rem;background:#e8f5e9;border-radius:6px;cursor:pointer;border:2px solid transparent;text-align:center\\" class=\\"sales-tile\\" data-filter=\\"invoiced\\"><div style=\\"font-size:1.1rem;font-weight:bold;color:#2e7d32\\">"+sum.totalInvoiced.toLocaleString()+"</div><div style=\\"font-size:0.7rem;color:#666\\">Invoiced ("+sum.invoiceCount+")</div>"+(invDollars?"<div style=\\"font-size:0.75rem;font-weight:600;color:#2e7d32\\">"+invDollars+"</div>":"")+"</div><div onclick=\\"filterSalesHistory(\'open\')\\" style=\\"flex:1;padding:0.5rem 0.75rem;background:#fff3e0;border-radius:6px;cursor:pointer;border:2px solid transparent;text-align:center\\" class=\\"sales-tile\\" data-filter=\\"open\\"><div style=\\"font-size:1.1rem;font-weight:bold;color:#ef6c00\\">"+sum.totalOpenOrders.toLocaleString()+"</div><div style=\\"font-size:0.7rem;color:#666\\">Open SO ("+sum.openOrderCount+")</div>"+(openDollars?"<div style=\\"font-size:0.75rem;font-weight:600;color:#ef6c00\\">"+openDollars+"</div>":"")+"</div><div onclick=\\"filterSalesHistory(\'po\')\\" style=\\"flex:1;padding:0.5rem 0.75rem;background:#e3f2fd;border-radius:6px;cursor:pointer;border:2px solid transparent;text-align:center\\" class=\\"sales-tile\\" data-filter=\\"po\\"><div style=\\"font-size:1.1rem;font-weight:bold;color:#1565c0\\">"+(sum.totalPO||0).toLocaleString()+"</div><div style=\\"font-size:0.7rem;color:#666\\">Open PO ("+(sum.poCount||0)+")</div>"+(poDollars?"<div style=\\"font-size:0.75rem;font-weight:600;color:#1565c0\\">"+poDollars+"</div>":"")+"</div>";renderSalesHistoryList(d.history)}).catch(function(err){document.getElementById("salesHistoryLoading").textContent="";document.getElementById("salesHistoryList").innerHTML="<div style=\\"color:#999\\">Error: "+err.message+"</div>"})}';
    html += 'function filterSalesHistory(filter){if(currentSalesFilter===filter){currentSalesFilter="all";document.querySelectorAll(".sales-tile").forEach(function(t){t.style.border="2px solid transparent";t.style.opacity="1"});document.getElementById("salesHistoryFilter").innerHTML=""}else{currentSalesFilter=filter;document.querySelectorAll(".sales-tile").forEach(function(t){if(t.dataset.filter===filter){t.style.border="2px solid #1e3a5f"}else{t.style.border="2px solid transparent";t.style.opacity="0.5"}});var label=filter==="invoiced"?"Invoiced":filter==="open"?"Open SO":"Import PO";document.getElementById("salesHistoryFilter").innerHTML="<span style=\\"background:#f0f4f8;padding:0.25rem 0.75rem;border-radius:12px;font-size:0.8rem\\">Showing: <strong>"+label+"</strong> <span onclick=\\"filterSalesHistory(\'all\')\\" style=\\"cursor:pointer;margin-left:0.5rem\\">✕</span></span>"}var filtered=currentSalesHistory;if(filter==="invoiced"){filtered=currentSalesHistory.filter(function(r){var st=(r.status||"").toLowerCase();return r.type!=="purchaseorder"&&(st==="invoiced"||st==="closed"||st==="fulfilled")})}else if(filter==="open"){filtered=currentSalesHistory.filter(function(r){var st=(r.status||"").toLowerCase();return r.type!=="purchaseorder"&&st!=="invoiced"&&st!=="closed"&&st!=="fulfilled"})}else if(filter==="po"){filtered=currentSalesHistory.filter(function(r){return r.type==="purchaseorder"})}else{document.querySelectorAll(".sales-tile").forEach(function(t){t.style.border="2px solid transparent";t.style.opacity="1"});document.getElementById("salesHistoryFilter").innerHTML=""}renderSalesHistoryList(filtered)}';
    html += 'var ZOHO_ORG="677681121";function zohoLink(type,docNum,docId){if(docId){var path=type==="purchaseorder"?"purchaseorders":type==="salesorder"?"salesorders":"invoices";return\'<a href="https://inventory.zoho.com/app/\'+ZOHO_ORG+\'#/\'+path+\'/\'+docId+\'" target="zoho-doc" style="text-decoration:underline;color:inherit" title="Open in Zoho Books">\'+docNum+\'</a>\'}return\'<a href="#" class="zoho-doc-link" data-type="\'+type+\'" data-num="\'+docNum+\'" style="text-decoration:underline;color:inherit;cursor:pointer" title="Open in Zoho Books">\'+docNum+\'</a>\'}document.addEventListener("click",function(e){var link=e.target.closest(".zoho-doc-link");if(!link)return;e.preventDefault();var type=link.dataset.type;var num=link.dataset.num;link.style.opacity="0.5";link.textContent=num+" ⏳";fetch("/api/zoho-link/"+type+"/"+encodeURIComponent(num)).then(function(r){return r.json()}).then(function(d){link.style.opacity="1";link.textContent=num;if(d.url)window.open(d.url,"zoho-doc")}).catch(function(){link.style.opacity="1";link.textContent=num})});';
    html += 'function renderSalesHistoryList(history){if(history.length===0){document.getElementById("salesHistoryList").innerHTML="<div style=\\"color:#999;padding:0.5rem\\">No records</div>";return}var h="<table style=\\"width:100%;border-collapse:collapse;font-size:0.8rem\\"><thead><tr style=\\"background:#f5f5f5\\"><th style=\\"text-align:left;padding:0.4rem\\">Date</th><th style=\\"text-align:left;padding:0.4rem\\">Customer</th><th style=\\"text-align:left;padding:0.4rem\\">Type</th><th style=\\"text-align:right;padding:0.4rem\\">Qty</th><th style=\\"text-align:right;padding:0.4rem\\">Amount</th></tr></thead><tbody>";history.forEach(function(rec){var typeLabel;var st=(rec.status||"").toLowerCase();if(rec.type==="purchaseorder"){var whDate=rec.inWarehouseDate?new Date(rec.inWarehouseDate).toLocaleDateString():"";typeLabel="<span style=\\"color:#1565c0\\">PO "+zohoLink(rec.type,rec.documentNumber,rec.documentId)+(rec.status?" ("+rec.status+")":"")+(whDate?"<br><span style=\\"font-size:0.7rem;color:#666\\">IN: "+whDate+"</span>":"")+"</span>"}else if(st==="invoiced"||st==="closed"||st==="fulfilled"){typeLabel="<span style=\\"color:#2e7d32\\">INV "+zohoLink(rec.type,rec.documentNumber,rec.documentId)+"</span>"}else{typeLabel="<span style=\\"color:#ef6c00\\">SO "+zohoLink(rec.type,rec.documentNumber,rec.documentId)+" (Open)</span>"}var dt=new Date(rec.date).toLocaleDateString();var amt=rec.amount?"$"+rec.amount.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}):"-";h+="<tr style=\\"border-bottom:1px solid #eee\\"><td style=\\"padding:0.4rem\\">"+dt+"</td><td style=\\"padding:0.4rem\\">"+rec.customerName+"</td><td style=\\"padding:0.4rem\\">"+typeLabel+"</td><td style=\\"padding:0.4rem;text-align:right\\">"+rec.quantity.toLocaleString()+"</td><td style=\\"padding:0.4rem;text-align:right\\">"+amt+"</td></tr>"});h+="</tbody></table>";document.getElementById("salesHistoryList").innerHTML=h}';
    
    // Helper to group products by base style
    html += 'function groupProductsByStyle(prods){var groups={};prods.forEach(function(p){var base=p.style_id.split("-")[0];if(!groups[base]){groups[base]={baseStyle:base,name:p.name.replace(p.style_id,base),category:p.category,variants:[],firstSeenImport:p.first_seen_import}}groups[base].variants.push(p)});return Object.values(groups)}';
    
    html += 'function renderListView(items,isGrouped){var h="<table class=\\"list-table\\"><thead><tr><th style=\\"width:60px\\"></th><th>Style</th><th>Name</th><th>Category</th><th>Colors</th>"+(supplyDemandMode?"<th class=\\"right\\">Supply</th><th class=\\"right\\">Demand</th><th class=\\"right\\">Avail to Sell</th>":"<th class=\\"right\\">Avail Now</th><th class=\\"right\\">Left to Sell</th>")+"</tr></thead><tbody>";if(isGrouped){items.forEach(function(grp){var totNow=0,totLts=0,totOnHand=0;var colorList=[];grp.variants.forEach(function(v){(v.colors||[]).forEach(function(c){totNow+=(c.available_now||c.available_qty||0);totLts+=(c.left_to_sell||0);totOnHand+=(c.on_hand||0);if(colorList.indexOf(c.color_name)===-1)colorList.push(c.color_name)})});var imgUrl=getImageUrl(grp.variants[0].image_url);var thumbHtml=imgUrl?"<img class=\\"thumb\\" src=\\""+imgUrl+"\\" onerror=\\"this.style.display=\'none\'\\">":"";var colorsText=colorList.slice(0,4).join(", ");if(colorList.length>4)colorsText+=" +"+(colorList.length-4);var rowHtml="<tr onclick=\\"handleGroupClick(\'"+grp.baseStyle+"\',event)\\"><td>"+thumbHtml+"</td><td class=\\"style-cell\\">"+grp.baseStyle+"</td><td class=\\"name-cell\\">"+grp.name+"</td><td class=\\"cat-cell\\">"+(grp.variants[0].category||"-")+"</td><td class=\\"colors-cell\\">"+colorsText+"</td>";if(supplyDemandMode){var openPOs=importPOsByStyle[grp.baseStyle]||0;var openOrders=openOrdersByStyle[grp.baseStyle]||0;var totalSupply=totOnHand+openPOs;var availToSell=totalSupply-openOrders;var availStyle=availToSell<0?"color:#ff3b30;font-weight:600":"";rowHtml+="<td class=\\"right\\">"+totalSupply.toLocaleString()+"</td><td class=\\"right\\">"+openOrders.toLocaleString()+"</td><td class=\\"right\\" style=\\""+availStyle+"\\">"+availToSell.toLocaleString()+"</td>"}else{rowHtml+="<td class=\\"right qty-now\\">"+totNow.toLocaleString()+"</td><td class=\\"right qty-lts\\">"+totLts.toLocaleString()+"</td>"}rowHtml+="</tr>";h+=rowHtml})}else{items.forEach(function(pr){var cols=pr.colors||[];var totNow=0,totLts=0,totOnHand=0;cols.forEach(function(c){totNow+=(c.available_now||c.available_qty||0);totLts+=(c.left_to_sell||0);totOnHand+=(c.on_hand||0)});var colorList=cols.map(function(c){return c.color_name});var colorsText=colorList.slice(0,4).join(", ");if(colorList.length>4)colorsText+=" +"+(colorList.length-4);var imgUrl=getImageUrl(pr.image_url);var thumbHtml=imgUrl?"<img class=\\"thumb\\" src=\\""+imgUrl+"\\" onerror=\\"this.style.display=\'none\'\\">":"";var sel=selectedProducts.indexOf(pr.id)!==-1?"selected":"";var rowHtml="<tr class=\\""+sel+"\\" onclick=\\"handleCardClick("+pr.id+",event)\\"><td>"+thumbHtml+"</td><td class=\\"style-cell\\">"+pr.style_id+"</td><td class=\\"name-cell\\">"+pr.name+"</td><td class=\\"cat-cell\\">"+(pr.category||"-")+"</td><td class=\\"colors-cell\\">"+colorsText+"</td>";if(supplyDemandMode){var baseStyle=pr.style_id.split("-")[0];var openPOs=importPOsByStyle[baseStyle]||0;var openOrders=openOrdersByStyle[baseStyle]||0;var totalSupply=totOnHand+openPOs;var availToSell=totalSupply-openOrders;var availStyle=availToSell<0?"color:#ff3b30;font-weight:600":"";rowHtml+="<td class=\\"right\\">"+totalSupply.toLocaleString()+"</td><td class=\\"right\\">"+openOrders.toLocaleString()+"</td><td class=\\"right\\" style=\\""+availStyle+"\\">"+availToSell.toLocaleString()+"</td>"}else{rowHtml+="<td class=\\"right qty-now\\">"+totNow.toLocaleString()+"</td><td class=\\"right qty-lts\\">"+totLts.toLocaleString()+"</td>"}rowHtml+="</tr>";h+=rowHtml})}h+="</tbody></table>";return h}';
    // Filter panel management functions
    html += 'function updateFilterPanel(){var filterCount=0;var filterHTML="";var hasCustomer=selectedCustomers.length>0;var hasSupplier=selectedSuppliers.length>0;var hasCategory=selectedCategories.length>0;var hasColor=colorFilter!==null;var hasSpecial=specialFilter!==null;var searchTerm=document.getElementById("searchInput").value.trim();var hasSearch=searchTerm.length>0;var minQty=parseInt(document.getElementById("minQty").value);var maxQty=parseInt(document.getElementById("maxQty").value);var hasMinQty=!isNaN(minQty)&&minQty>1;var hasMaxQty=!isNaN(maxQty)&&maxQty<999999999;var hasAIFilter=(customerStyleFilter&&customerStyleFilter.length>0)||(minColorsFilter>0);if(hasAIFilter||hasSearch||hasMinQty||hasMaxQty){filterHTML+="<div style=\\"padding:0.75rem;background:#fff3cd;border-left:3px solid #ffc107;margin-bottom:1rem;border-radius:4px\\"><div style=\\"font-size:0.8125rem;font-weight:600;color:#856404;margin-bottom:0.25rem\\">🤖 AI Assistant Active</div><div style=\\"font-size:0.75rem;color:#856404\\">Filters applied by AI or advanced search</div></div>"}if(hasCustomer||hasSupplier){filterHTML+="<div class=\\"filter-group\\">";if(hasCustomer||hasSupplier){filterHTML+="<div class=\\"filter-group-title\\">Business Filters</div>"}if(hasCustomer){filterCount++;var custText=selectedCustomers.length===1?selectedCustomers[0]:(selectedCustomers.length+" selected");filterHTML+="<div class=\\"filter-item\\"><div><div class=\\"filter-item-label\\">Customer</div><div class=\\"filter-item-value\\">"+custText+"</div></div><button class=\\"filter-item-remove\\" onclick=\\"removeCustomerFromPanel()\\">Remove</button></div>"}if(hasSupplier){filterCount++;var suppText=selectedSuppliers.length===1?selectedSuppliers[0]:(selectedSuppliers.length+" selected");filterHTML+="<div class=\\"filter-item\\"><div><div class=\\"filter-item-label\\">Supplier</div><div class=\\"filter-item-value\\">"+suppText+"</div></div><button class=\\"filter-item-remove\\" onclick=\\"removeSupplierFromPanel()\\">Remove</button></div>"}filterHTML+="</div>"}if(hasCategory||hasColor||hasSpecial){filterHTML+="<div class=\\"filter-group\\"><div class=\\"filter-group-title\\">Product Filters</div>";if(hasCategory){filterCount++;var catText=selectedCategories.length===1?selectedCategories[0]:(selectedCategories.length+" categories");filterHTML+="<div class=\\"filter-item\\"><div><div class=\\"filter-item-label\\">Categories</div><div class=\\"filter-item-value\\">"+catText+"</div></div><button class=\\"filter-item-remove\\" onclick=\\"removeCategoryFromPanel()\\">Remove</button></div>"}if(hasColor){filterCount++;filterHTML+="<div class=\\"filter-item\\"><div><div class=\\"filter-item-label\\">Color</div><div class=\\"filter-item-value\\">"+colorFilter+"</div></div><button class=\\"filter-item-remove\\" onclick=\\"removeColorFromPanel()\\">Remove</button></div>"}if(hasSpecial){filterCount++;var specialText=specialFilter==="new"?"New Arrivals":(specialFilter==="picks"?"My Picks":"Has Notes");filterHTML+="<div class=\\"filter-item\\"><div><div class=\\"filter-item-label\\">Special Filter</div><div class=\\"filter-item-value\\">"+specialText+"</div></div><button class=\\"filter-item-remove\\" onclick=\\"removeSpecialFromPanel()\\">Remove</button></div>"}filterHTML+="</div>"}if(hasSearch||hasMinQty||hasMaxQty||hasAIFilter){filterHTML+="<div class=\\"filter-group\\"><div class=\\"filter-group-title\\">Additional Filters</div>";if(hasSearch){filterCount++;filterHTML+="<div class=\\"filter-item\\"><div><div class=\\"filter-item-label\\">Search</div><div class=\\"filter-item-value\\">"+searchTerm+"</div></div><button class=\\"filter-item-remove\\" onclick=\\"removeSearchFromPanel()\\">Remove</button></div>"}if(hasMinQty&&hasMaxQty){filterCount++;filterHTML+="<div class=\\"filter-item\\"><div><div class=\\"filter-item-label\\">Quantity Range</div><div class=\\"filter-item-value\\">"+minQty.toLocaleString()+" - "+maxQty.toLocaleString()+"</div></div><button class=\\"filter-item-remove\\" onclick=\\"removeQtyFromPanel()\\">Remove</button></div>"}else if(hasMinQty){filterCount++;filterHTML+="<div class=\\"filter-item\\"><div><div class=\\"filter-item-label\\">Min Quantity</div><div class=\\"filter-item-value\\">"+minQty.toLocaleString()+"</div></div><button class=\\"filter-item-remove\\" onclick=\\"removeQtyFromPanel()\\">Remove</button></div>"}else if(hasMaxQty){filterCount++;filterHTML+="<div class=\\"filter-item\\"><div><div class=\\"filter-item-label\\">Max Quantity</div><div class=\\"filter-item-value\\">"+maxQty.toLocaleString()+"</div></div><button class=\\"filter-item-remove\\" onclick=\\"removeQtyFromPanel()\\">Remove</button></div>"}if(customerStyleFilter&&customerStyleFilter.length>0){filterCount++;filterHTML+="<div class=\\"filter-item\\"><div><div class=\\"filter-item-label\\">AI Filter</div><div class=\\"filter-item-value\\">"+customerStyleFilter.length+" specific styles</div></div><button class=\\"filter-item-remove\\" onclick=\\"removeAIStyleFilter()\\">Remove</button></div>"}if(minColorsFilter>0){filterCount++;filterHTML+="<div class=\\"filter-item\\"><div><div class=\\"filter-item-label\\">Min Colors</div><div class=\\"filter-item-value\\">"+minColorsFilter+" colors</div></div><button class=\\"filter-item-remove\\" onclick=\\"removeMinColorsFilter()\\">Remove</button></div>"}filterHTML+="</div>"}document.getElementById("filterPanelBody").innerHTML=filterHTML;document.getElementById("filterCountBadge").textContent=filterCount;document.getElementById("filterPanelTitle").textContent="Active Filters ("+filterCount+")";if(filterCount>0){document.getElementById("filterSummaryBadge").classList.add("visible")}else{document.getElementById("filterSummaryBadge").classList.remove("visible");closeFilterPanel()}}';
    html += 'function openFilterPanel(){document.getElementById("filterSummaryPanel").classList.add("active")}';
    html += 'function closeFilterPanel(){document.getElementById("filterSummaryPanel").classList.remove("active")}';
    html += 'function removeCustomerFromPanel(){selectedCustomers=[];customerFilterStyles=[];document.getElementById("customerFilterBtn").textContent="Customer: All ▼";document.getElementById("clearCustomerBtn").classList.add("hidden");document.getElementById("customerFilterBtn").classList.remove("active");renderCustomerDropdown();updateFilterPanel();renderProducts()}';
    html += 'function removeSupplierFromPanel(){selectedSuppliers=[];supplierFilterStyles=[];document.getElementById("supplierFilterBtn").textContent="Supplier: All ▼";document.getElementById("clearSupplierBtn").classList.add("hidden");document.getElementById("supplierFilterBtn").classList.remove("active");renderSupplierDropdown();updateFilterPanel();renderProducts()}';
    html += 'function removeCategoryFromPanel(){selectedCategories=[];document.querySelectorAll(".filter-btn[data-cat]").forEach(function(b){b.classList.remove("active")});updateFilterPanel();renderProducts()}';
    html += 'function removeColorFromPanel(){colorFilter=null;document.getElementById("colorFilterBtn").textContent="Color: All ▼";document.getElementById("clearColorBtn").classList.add("hidden");updateFilterPanel();renderProducts()}';
    html += 'function removeSearchFromPanel(){document.getElementById("searchInput").value="";updateFilterPanel();renderProducts()}';
    html += 'function removeQtyFromPanel(){document.getElementById("minQty").value="";document.getElementById("maxQty").value="";updateFilterPanel();renderProducts()}';
    html += 'function removeAIStyleFilter(){customerStyleFilter=null;updateFilterPanel();renderProducts()}';
    html += 'function removeMinColorsFilter(){minColorsFilter=0;updateFilterPanel();renderProducts()}';
    html += 'function removeSpecialFromPanel(){specialFilter=null;document.querySelectorAll(".filter-btn[data-special]").forEach(function(b){b.classList.remove("active")});updateFilterPanel();renderProducts()}';
    html += 'function clearAllFiltersFromPanel(){selectedCustomers=[];selectedSuppliers=[];customerFilterStyles=[];supplierFilterStyles=[];selectedCategories=[];selectedColors=[];colorFilter=null;specialFilter=null;document.getElementById("customerFilterBtn").textContent="Customer: All ▼";document.getElementById("clearCustomerBtn").classList.add("hidden");document.getElementById("customerFilterBtn").classList.remove("active");document.getElementById("supplierFilterBtn").textContent="Supplier: All ▼";document.getElementById("clearSupplierBtn").classList.add("hidden");document.getElementById("supplierFilterBtn").classList.remove("active");document.getElementById("colorFilterBtn").textContent="Color: All ▼";document.getElementById("clearColorBtn").classList.add("hidden");document.querySelectorAll(".filter-btn[data-cat]").forEach(function(b){b.classList.remove("active")});document.querySelectorAll(".filter-btn[data-special]").forEach(function(b){b.classList.remove("active")});renderCustomerDropdown();renderSupplierDropdown();renderColorDropdown();closeFilterPanel();updateFilterPanel();renderProducts()}';
    
    html += 'function renderProducts(){var grid=document.getElementById("productGrid");if(grid){if(typeof isOrderMode==="function"&&isOrderMode()){grid.classList.add("order-mode")}else{grid.classList.remove("order-mode")}}var s=document.getElementById("searchInput").value.toLowerCase().trim();var searchWords=s?s.split(/\\s+/):[];var minQ=parseInt(document.getElementById("minQty").value)||1;var maxQ=parseInt(document.getElementById("maxQty").value)||999999999;var f=allProducts.filter(function(p){var searchText=p.style_id.toLowerCase()+" "+p.name.toLowerCase()+" "+(p.ai_tags||"").toLowerCase();var ms=searchWords.length===0||searchWords.every(function(word){return searchText.indexOf(word)!==-1});var mc=selectedCategories.length===0||selectedCategories.indexOf(p.category)!==-1;var colorNames=(p.colors||[]).map(function(c){return c.color_name});var mcolor=!colorFilter||(Array.isArray(colorFilter)?colorFilter.some(function(cf){return colorNames.indexOf(cf)!==-1}):colorNames.indexOf(colorFilter)!==-1);var tot=0;(p.colors||[]).forEach(function(c){tot+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))});var mq=tot>=minQ&&tot<=maxQ;var msp=true;if(specialFilter==="new"){msp=p.first_seen_import===lastImportId}else if(specialFilter==="picks"){msp=userPicks.indexOf(p.id)!==-1}else if(specialFilter==="notes"){var baseStyle=p.style_id.split("-")[0];msp=!!userNotes[baseStyle]}else if(specialFilter==="oversold"){var baseStyle=p.style_id.split("-")[0];var onHand=0;allProducts.filter(function(x){return x.style_id.split("-")[0]===baseStyle}).forEach(function(x){(x.colors||[]).forEach(function(c){onHand+=(c.on_hand||0)})});var openPOs=importPOsByStyle[baseStyle]||0;var openOrders=openOrdersByStyle[baseStyle]||0;var availToSell=(onHand+openPOs)-openOrders;msp=availToSell<0}var mcust=true;if(customerStyleFilter&&customerStyleFilter.length>0){var baseStyle=p.style_id.split("-")[0];mcust=customerStyleFilter.indexOf(baseStyle)!==-1}var mcustDropdown=true;if(customerFilterStyles&&customerFilterStyles.length>0){var baseStyle=p.style_id.split("-")[0];mcustDropdown=customerFilterStyles.indexOf(baseStyle)!==-1}var msuppDropdown=true;if(supplierFilterStyles&&supplierFilterStyles.length>0){var baseStyle=p.style_id.split("-")[0];msuppDropdown=supplierFilterStyles.indexOf(baseStyle)!==-1}var mdept=true;if(departmentFilter){var dBase=p.style_id.split("-")[0];var dLast=dBase.charAt(dBase.length-1).toUpperCase();mdept=dLast===departmentFilter}return ms&&mc&&mcolor&&mq&&msp&&mcust&&mcustDropdown&&msuppDropdown&&mdept});f.sort(function(a,b){var ta=0,tb=0;(a.colors||[]).forEach(function(c){ta+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))});(b.colors||[]).forEach(function(c){tb+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))});if(currentSort==="qty-high")return tb-ta;if(currentSort==="qty-low")return ta-tb;if(currentSort==="name-desc")return b.name.localeCompare(a.name);if(currentSort==="newest")return(b.first_seen_import||0)-(a.first_seen_import||0);return a.name.localeCompare(b.name)});products=f;if(f.length===0){document.getElementById("productGrid").innerHTML="";document.getElementById("emptyState").classList.remove("hidden")}else{document.getElementById("emptyState").classList.add("hidden");var h="";var isListView=currentSize==="list";if(groupByStyle){var grouped=groupProductsByStyle(f);var shownGroups=0;grouped.sort(function(a,b){var ta=0,tb=0;a.variants.forEach(function(v){(v.colors||[]).forEach(function(c){ta+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))})});b.variants.forEach(function(v){(v.colors||[]).forEach(function(c){tb+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))})});if(currentSort==="qty-high")return tb-ta;if(currentSort==="qty-low")return ta-tb;if(currentSort==="name-desc")return b.name.localeCompare(a.name);return a.name.localeCompare(b.name)});var filteredGroups=grouped.filter(function(grp){if(minColorsFilter>0){var uniqueColors={};grp.variants.forEach(function(v){(v.colors||[]).forEach(function(c){var cQty=qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0);if(cQty>0)uniqueColors[c.color_name]=true})});if(Object.keys(uniqueColors).length<minColorsFilter)return false}return true});shownGroups=filteredGroups.length;if(isListView){h=renderListView(filteredGroups,true)}else{filteredGroups.forEach(function(grp,idx){var totNow=0,totLts=0,totOnHand=0;grp.variants.forEach(function(v){(v.colors||[]).forEach(function(c){totNow+=(c.available_now||c.available_qty||0);totLts+=(c.left_to_sell||0);totOnHand+=(c.on_hand||0)})});var primaryQty=qtyMode==="left_to_sell"?totLts:totNow;var secondaryQty=qtyMode==="left_to_sell"?totNow:totLts;var secondaryLabel=qtyMode==="left_to_sell"?"Now":"LTS";var openPOs=importPOsByStyle[grp.baseStyle]||0;var openOrders=openOrdersByStyle[grp.baseStyle]||0;var totalSupply=totOnHand+openPOs;var netAvailable=totalSupply-openOrders;var displayQty=supplyDemandMode?netAvailable:primaryQty;var qtyStyle=supplyDemandMode&&netAvailable<0?"color:#ff3b30":"";var imgUrl=getImageUrl(grp.variants[0].image_url);var im=imgUrl?"<img src=\\""+imgUrl+"\\" onerror=\\"this.parentElement.innerHTML=\'No Image\'\\">":"No Image";var uniqueColors={};grp.variants.forEach(function(v){(v.colors||[]).forEach(function(c){var cQty=qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0);if(cQty>0)uniqueColors[c.color_name]=true})});var colorCount=Object.keys(uniqueColors).length||1;var variantIds=grp.variants.map(function(v){return v.id}).join(",");var selModeClass=selectionMode?"selection-mode":"";var groupSelected=selectionMode&&grp.variants.every(function(v){return selectedProducts.indexOf(v.id)!==-1})?"group-selected":"";var orderGroupSel=typeof isOrderGroupSelected==="function"&&isOrderGroupSelected(grp.baseStyle)?"order-selected":"";if(supplyDemandMode){h+="<div class=\\"product-card grouped "+selModeClass+" "+groupSelected+" "+orderGroupSel+"\\" data-idx=\\""+idx+"\\" data-variants=\\""+variantIds+"\\" onclick=\\"handleGroupClick(\'"+grp.baseStyle+"\',event)\\"><div class=\\"select-badge\\">✓</div><div class=\\"color-count-badge\\">"+colorCount+" colors</div><div class=\\"product-image\\">"+im+"</div><div class=\\"product-info\\"><div class=\\"product-style\\">"+grp.baseStyle+"</div><div class=\\"product-name\\">"+grp.name+"</div><div style=\\"font-size:0.7rem;padding:0.5rem 0;border-top:1px solid #eee;border-bottom:1px solid #eee\\"><div style=\\"display:flex;justify-content:space-between;margin-bottom:0.25rem\\"><span>Supply:</span><span>"+totalSupply.toLocaleString()+"</span></div><div style=\\"display:flex;justify-content:space-between;margin-bottom:0.25rem\\"><span>Demand:</span><span>"+openOrders.toLocaleString()+"</span></div><hr style=\\"margin:0.25rem 0;border:none;border-top:1px solid #ddd\\"><div style=\\"display:flex;justify-content:space-between;font-weight:700;font-size:0.8rem;"+qtyStyle+"\\"><span>Available to Sell:</span><span>"+displayQty.toLocaleString()+"</span></div></div></div></div>"}else{h+="<div class=\\"product-card grouped "+selModeClass+" "+groupSelected+" "+orderGroupSel+"\\" data-idx=\\""+idx+"\\" data-variants=\\""+variantIds+"\\" onclick=\\"handleGroupClick(\'"+grp.baseStyle+"\',event)\\"><div class=\\"select-badge\\">✓</div><div class=\\"color-count-badge\\">"+colorCount+" colors</div><div class=\\"product-image\\">"+im+"</div><div class=\\"product-info\\"><div class=\\"product-style\\">"+grp.baseStyle+"</div><div class=\\"product-name\\">"+grp.name+"</div><div class=\\"total-row\\"><span>Total</span><span>"+primaryQty.toLocaleString()+"</span></div><div style=\\"font-size:0.75rem;color:#999;text-align:right\\">("+secondaryLabel+": "+secondaryQty.toLocaleString()+")</div></div></div>"}})}document.getElementById("totalStyles").textContent=shownGroups+" groups"}else{if(isListView){h=renderListView(f,false)}else{f.forEach(function(pr,idx){var cols=pr.colors||[];var totNow=0,totLts=0;cols.forEach(function(c){totNow+=(c.available_now||c.available_qty||0);totLts+=(c.left_to_sell||0)});var primaryQty=qtyMode==="left_to_sell"?totLts:totNow;var secondaryQty=qtyMode==="left_to_sell"?totNow:totLts;var secondaryLabel=qtyMode==="left_to_sell"?"Now":"LTS";var ch="";var mx=Math.min(cols.length,3);for(var d=0;d<mx;d++){var cq=qtyMode==="left_to_sell"?(cols[d].left_to_sell||0):(cols[d].available_now||cols[d].available_qty||0);ch+="<div class=\\"color-row\\"><span>"+cols[d].color_name+"</span><span>"+cq.toLocaleString()+"</span></div>"}if(cols.length>3)ch+="<div class=\\"color-row\\" style=\\"color:#999\\">+"+(cols.length-3)+" more</div>";var imgUrl=getImageUrl(pr.image_url);var im=imgUrl?"<img src=\\""+imgUrl+"\\" onerror=\\"this.parentElement.innerHTML=\'No Image\'\\">":"No Image";var sel=selectedProducts.indexOf(pr.id)!==-1?"selected":"";var selModeClass=selectionMode?"selection-mode":"";var isPicked=userPicks.indexOf(pr.id)!==-1;var hasNote=!!userNotes[pr.style_id.split("-")[0]];h+="<div class=\\"product-card "+sel+" "+selModeClass+"\\" data-idx=\\""+idx+"\\" onclick=\\"handleCardClick("+pr.id+",event)\\"><div class=\\"select-badge\\">✓</div><div class=\\"pick-badge "+(isPicked?"active":"")+"\\">"+(isPicked?"♥":"♡")+"</div><div class=\\"note-badge "+(hasNote?"has-note":"")+"\\"></div><div class=\\"product-image\\">"+im+"</div><div class=\\"product-info\\"><div class=\\"product-style\\">"+pr.style_id+"</div><div class=\\"product-name\\">"+pr.name+"</div><div class=\\"color-list\\">"+ch+"</div><div class=\\"total-row\\"><span>Total</span><span>"+primaryQty.toLocaleString()+"</span></div><div style=\\"font-size:0.75rem;color:#999;text-align:right\\">("+secondaryLabel+": "+secondaryQty.toLocaleString()+")</div></div></div>"})}document.getElementById("totalStyles").textContent=f.length}document.getElementById("productGrid").innerHTML=h}var totalNow=0;var totalLts=0;allProducts.forEach(function(p){(p.colors||[]).forEach(function(c){totalNow+=(c.available_now||c.available_qty||0);totalLts+=(c.left_to_sell||0)})});document.getElementById("totalAvailNow").textContent=totalNow.toLocaleString();document.getElementById("totalLeftToSell").textContent=totalLts.toLocaleString();var availToSellEl=document.getElementById("availToSellStat");var oversoldEl=document.getElementById("oversoldStat");if(availToSellEl&&oversoldEl){if(supplyDemandMode){var totalPositive=0;var totalNegative=0;var seenStyles={};allProducts.forEach(function(p){var baseStyle=p.style_id.split("-")[0];if(!seenStyles[baseStyle]){seenStyles[baseStyle]=true;var onHand=0;allProducts.filter(function(x){return x.style_id.split("-")[0]===baseStyle}).forEach(function(x){(x.colors||[]).forEach(function(c){onHand+=(c.on_hand||0)})});var openPOs=importPOsByStyle[baseStyle]||0;var openOrders=openOrdersByStyle[baseStyle]||0;var availToSell=(onHand+openPOs)-openOrders;if(availToSell>=0){totalPositive+=availToSell}else{totalNegative+=Math.abs(availToSell)}}});availToSellEl.style.display="block";document.getElementById("totalAvailToSell").textContent=totalPositive.toLocaleString();if(totalNegative>0){oversoldEl.style.display="block";document.getElementById("totalOversold").textContent=totalNegative.toLocaleString()}else{oversoldEl.style.display="none"}}else{availToSellEl.style.display="none";oversoldEl.style.display="none"}}updateFilterPanel();focusedIndex=-1}';
    
    // Handle click on grouped card - show group modal
    html += 'function handleGroupClick(baseStyle,e){if(e.target.classList.contains("pick-badge"))return;if(typeof isOrderMode==="function"&&isOrderMode()){handleOrderGroupClick(baseStyle);return}var variants=allProducts.filter(function(p){return p.style_id.split("-")[0]===baseStyle});if(selectionMode){e.stopPropagation();var variantIds=variants.map(function(v){return v.id});var allSelected=variantIds.every(function(id){return selectedProducts.indexOf(id)!==-1});if(allSelected){variantIds.forEach(function(id){var idx=selectedProducts.indexOf(id);if(idx!==-1)selectedProducts.splice(idx,1)})}else{variantIds.forEach(function(id){if(selectedProducts.indexOf(id)===-1)selectedProducts.push(id)})}updateSelectionUI();renderProducts()}else{showGroupModal(baseStyle,variants)}}';
    
    // Show group modal with all color variants
    html += 'function showGroupModal(baseStyle,variants){currentModalBaseStyle=baseStyle;var totNow=0,totLts=0,totOnHand=0;variants.forEach(function(v){(v.colors||[]).forEach(function(c){totNow+=(c.available_now||c.available_qty||0);totLts+=(c.left_to_sell||0);totOnHand+=(c.on_hand||0)})});document.getElementById("modalStyle").textContent=baseStyle;document.getElementById("modalName").textContent=variants[0].name.replace(variants[0].style_id,baseStyle);document.getElementById("modalCategory").textContent=variants[0].category||"";var imgUrl=getImageUrl(variants[0].image_url);document.getElementById("modalImage").src=imgUrl||"";var swatchHtml="<div style=\\"display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:1rem\\">";variants.forEach(function(v,i){var vImg=getImageUrl(v.image_url);var colorCode=v.style_id.split("-")[1]||"";var colorName=(v.colors&&v.colors[0])?v.colors[0].color_name:colorCode;var swatchDisplay=colorName+(colorCode?" ("+colorCode+")":"");swatchHtml+="<div class=\\"color-swatch"+(i===0?" active":"")+"\\" data-idx=\\""+i+"\\" style=\\"padding:0.5rem 0.75rem;border:2px solid "+(i===0?"#1a3b5d":"#ddd")+";border-radius:4px;cursor:pointer;font-size:0.75rem;background:"+(i===0?"#f0f4f8":"#fff")+"\\" onclick=\\"switchVariantImage("+i+",\'"+baseStyle+"\')\\">"+colorName+"</div>"});swatchHtml+="</div>";var ch="<table style=\\"width:100%;border-collapse:collapse;font-size:0.875rem\\"><thead><tr style=\\"border-bottom:1px solid #ddd\\"><th style=\\"text-align:left;padding:0.5rem 0;font-weight:600;color:#666\\">Color Variant</th><th style=\\"text-align:right;padding:0.5rem 0;font-weight:600;color:#666;width:80px\\">Avail Now</th><th style=\\"text-align:right;padding:0.5rem 0;font-weight:600;color:#666;width:80px\\">Left to Sell</th></tr></thead><tbody>";variants.forEach(function(v){var vNow=0,vLts=0;(v.colors||[]).forEach(function(c){vNow+=(c.available_now||c.available_qty||0);vLts+=(c.left_to_sell||0)});var colorName=(v.colors&&v.colors[0])?v.colors[0].color_name:v.style_id;var colorCode=v.style_id.split("-")[1]||"";var displayName=colorName+(colorCode?" ("+colorCode+")":"");ch+="<tr><td style=\\"padding:0.4rem 0\\">"+displayName+"</td><td style=\\"text-align:right;padding:0.4rem 0\\">"+vNow.toLocaleString()+"</td><td style=\\"text-align:right;padding:0.4rem 0;color:#666\\">"+vLts.toLocaleString()+"</td></tr>"});ch+="</tbody></table>";document.getElementById("modalColors").innerHTML=swatchHtml+ch;var modalTotalHtml="<span style=\\"margin-right:2rem\\">Now: "+totNow.toLocaleString()+"</span><span>LTS: "+totLts.toLocaleString()+"</span>";if(supplyDemandMode){var openPOs=importPOsByStyle[baseStyle]||0;var openOrders=openOrdersByStyle[baseStyle]||0;var totalSupply=totOnHand+openPOs;var availToSell=totalSupply-openOrders;var availColor=availToSell<0?"#ff3b30":"#1e3a5f";modalTotalHtml+="<div style=\\"margin-top:1rem;padding:0.75rem;background:#f8f9fa;border-radius:8px;font-size:0.875rem\\"><div style=\\"display:flex;justify-content:space-between;padding:0.4rem 0\\"><span>On Hand:</span><span style=\\"font-weight:500\\">"+totOnHand.toLocaleString()+"</span></div><div style=\\"display:flex;justify-content:space-between;padding:0.4rem 0\\"><span>Open Import POs:</span><span style=\\"font-weight:500\\">"+openPOs.toLocaleString()+"</span></div><div style=\\"display:flex;justify-content:space-between;padding:0.4rem 0;font-weight:600;border-bottom:1px solid #e0e0e0\\"><span>Total Supply:</span><span>"+totalSupply.toLocaleString()+"</span></div><div style=\\"display:flex;justify-content:space-between;padding:0.4rem 0;border-bottom:1px solid #e0e0e0\\"><span>Open Sales Orders:</span><span style=\\"font-weight:500\\">"+openOrders.toLocaleString()+"</span></div><div style=\\"display:flex;justify-content:space-between;padding:0.5rem 0 0.25rem;font-weight:700;font-size:0.95rem;color:"+availColor+"\\"><span>Available to Sell:</span><span>"+availToSell.toLocaleString()+"</span></div></div>"}document.getElementById("modalTotal").innerHTML=modalTotalHtml;document.getElementById("modalNote").value=userNotes[baseStyle]||"";document.getElementById("modalPickBtn").style.display="none";currentModalProductId=null;window.currentGroupVariants=variants;document.getElementById("modal").classList.add("active");loadSalesHistory(baseStyle);loadSizeGrid(baseStyle)}';
    
    // Switch image when clicking color swatch
    html += 'function switchVariantImage(idx,baseStyle){var variants=window.currentGroupVariants||allProducts.filter(function(p){return p.style_id.split("-")[0]===baseStyle});if(variants[idx]){var imgUrl=getImageUrl(variants[idx].image_url);document.getElementById("modalImage").src=imgUrl||"";document.querySelectorAll(".color-swatch").forEach(function(sw,i){sw.style.border=i===idx?"2px solid #1a3b5d":"2px solid #ddd";sw.style.background=i===idx?"#f0f4f8":"#fff"})}}';
    
    
    html += 'document.getElementById("searchInput").addEventListener("input",renderProducts);';
    html += 'document.getElementById("clearSearchBtn").addEventListener("click",function(){document.getElementById("searchInput").value="";renderProducts()});';
    html += 'document.getElementById("colorFilterBtn").addEventListener("click",function(e){e.stopPropagation();document.getElementById("colorDropdown").classList.toggle("hidden");document.getElementById("customerDropdown").classList.add("hidden");document.getElementById("supplierDropdown").classList.add("hidden")});';
    html += 'document.getElementById("clearColorBtn").addEventListener("click",function(){selectedColors=[];colorFilter=null;document.getElementById("colorFilterBtn").textContent="Color: All ▼";document.getElementById("clearColorBtn").classList.add("hidden");renderColorDropdown();renderProducts()});';
    html += 'document.getElementById("applyColorFilter").addEventListener("click",function(){selectedColors=[];document.querySelectorAll("#colorList input[type=checkbox]:checked").forEach(function(cb){selectedColors.push(cb.value)});applyColorSelection()});';
    html += 'document.getElementById("clearColorFilter").addEventListener("click",function(){selectedColors=[];colorFilter=null;document.getElementById("colorFilterBtn").textContent="Color: All ▼";document.getElementById("clearColorBtn").classList.add("hidden");renderColorDropdown();document.getElementById("colorDropdown").classList.add("hidden");renderProducts()});';
    html += 'document.getElementById("colorSearch").addEventListener("input",function(){var q=this.value.toLowerCase();document.querySelectorAll("#colorList label").forEach(function(l){var name=l.querySelector(".multi-item-name").textContent.toLowerCase();l.style.display=name.indexOf(q)!==-1?"":"none"})});';
    html += 'document.getElementById("colorList").addEventListener("change",function(e){if(e.target.type==="checkbox"){var val=e.target.value;if(e.target.checked){if(selectedColors.indexOf(val)===-1)selectedColors.push(val)}else{var idx=selectedColors.indexOf(val);if(idx!==-1)selectedColors.splice(idx,1)}}});';
    html += 'document.addEventListener("click",function(e){if(!e.target.closest("#colorDropdown")&&!e.target.closest("#colorFilterBtn")){document.getElementById("colorDropdown").classList.add("hidden")}if(!e.target.closest("#customerDropdown")&&!e.target.closest("#customerFilterBtn")){document.getElementById("customerDropdown").classList.add("hidden")}if(!e.target.closest("#supplierDropdown")&&!e.target.closest("#supplierFilterBtn")){document.getElementById("supplierDropdown").classList.add("hidden")}});';
    
    // Customer filter dropdown
    html += 'document.getElementById("customerFilterBtn").addEventListener("click",function(e){e.stopPropagation();document.getElementById("customerDropdown").classList.toggle("hidden");document.getElementById("colorDropdown").classList.add("hidden");document.getElementById("supplierDropdown").classList.add("hidden")});';
    html += 'document.getElementById("customerSearch").addEventListener("input",function(e){renderCustomerDropdown(e.target.value)});';
    html += 'document.getElementById("applyCustomerFilter").addEventListener("click",applyCustomerFilter);';
    html += 'document.getElementById("clearCustomerFilter").addEventListener("click",function(){selectedCustomers=[];renderCustomerDropdown();});';
    html += 'document.getElementById("clearCustomerBtn").addEventListener("click",clearCustomerFilterFn);';
    
    // Supplier filter dropdown
    html += 'document.getElementById("supplierFilterBtn").addEventListener("click",function(e){e.stopPropagation();document.getElementById("supplierDropdown").classList.toggle("hidden");document.getElementById("colorDropdown").classList.add("hidden");document.getElementById("customerDropdown").classList.add("hidden")});';
    html += 'document.getElementById("supplierSearch").addEventListener("input",function(e){renderSupplierDropdown(e.target.value)});';
    html += 'document.getElementById("applySupplierFilter").addEventListener("click",applySupplierFilter);';
    html += 'document.getElementById("clearSupplierFilter").addEventListener("click",function(){selectedSuppliers=[];renderSupplierDropdown();});';
    html += 'document.getElementById("clearSupplierBtn").addEventListener("click",clearSupplierFilterFn);';
    
    html += 'document.getElementById("minQty").addEventListener("input",renderProducts);';
    html += 'document.getElementById("maxQty").addEventListener("input",renderProducts);';
    html += 'document.getElementById("resetQtyBtn").addEventListener("click",function(){document.getElementById("minQty").value="";document.getElementById("maxQty").value="";renderProducts()});';
    
    // Reset All Filters button - restores to default view
    html += 'document.getElementById("resetAllFiltersBtn").addEventListener("click",function(){document.getElementById("searchInput").value="";document.getElementById("minQty").value="";document.getElementById("maxQty").value="";selectedCategories=[];selectedColors=[];colorFilter=null;specialFilter=null;departmentFilter=null;minColorsFilter=0;customerStyleFilter=null;selectedCustomers=[];selectedSuppliers=[];customerFilterStyles=[];supplierFilterStyles=[];currentSort="qty-high";currentSize="medium";qtyMode="left_to_sell";document.getElementById("sortSelect").value="qty-high";var catBtns=document.querySelectorAll(".filter-btn[data-cat]");for(var i=0;i<catBtns.length;i++){catBtns[i].classList.remove("active")}var specBtns=document.querySelectorAll(".filter-btn[data-special]");for(var i=0;i<specBtns.length;i++){specBtns[i].classList.remove("active")}document.getElementById("colorFilterBtn").textContent="Color: All ▼";document.getElementById("clearColorBtn").classList.add("hidden");document.getElementById("customerFilterBtn").textContent="Customer: All ▼";document.getElementById("clearCustomerBtn").classList.add("hidden");document.getElementById("customerFilterBtn").classList.remove("active");document.getElementById("supplierFilterBtn").textContent="Supplier: All ▼";document.getElementById("clearSupplierBtn").classList.add("hidden");document.getElementById("supplierFilterBtn").classList.remove("active");renderCustomerDropdown();renderSupplierDropdown();var viewBtns=document.querySelectorAll(".size-btn[data-size]");for(var i=0;i<viewBtns.length;i++){viewBtns[i].classList.remove("active");if(viewBtns[i].getAttribute("data-size")==="medium")viewBtns[i].classList.add("active")}var qtyBtns=document.querySelectorAll(".qty-toggle-btn");for(var i=0;i<qtyBtns.length;i++){qtyBtns[i].classList.remove("active")}document.getElementById("toggleLeftToSell").classList.add("active");document.getElementById("availNowStat").classList.remove("stat-active");document.getElementById("leftToSellStat").classList.add("stat-active");document.getElementById("productGrid").className="product-grid size-medium";renderProducts()});';
    
    html += 'document.getElementById("clearSelectionBtn").addEventListener("click",function(){selectedProducts=[];updateSelectionUI();renderProducts()});';
    
    // Selection preview functions
    html += 'function updateSelectionPreview(){var list=document.getElementById("selectionPreviewList");var styleCount=document.getElementById("previewStyleCount");var colorCount=document.getElementById("previewColorCount");var qtyTotal=document.getElementById("previewQtyTotal");if(selectedProducts.length===0){list.innerHTML="<div style=\\"padding:1rem;color:#666;text-align:center\\">No items selected</div>";styleCount.textContent="0";colorCount.textContent="0";qtyTotal.textContent="0";return}var styles={};var totalSkus=0;var totalQty=0;var html="";selectedProducts.forEach(function(id){var pr=allProducts.find(function(p){return p.id===id});if(!pr)return;var baseStyle=pr.style_id.split("-")[0];if(!styles[baseStyle])styles[baseStyle]=0;styles[baseStyle]++;totalSkus++;var qty=0;(pr.colors||[]).forEach(function(c){qty+=(qtyMode==="left_to_sell"?(c.left_to_sell||0):(c.available_now||c.available_qty||0))});totalQty+=qty;var imgUrl=getImageUrl(pr.image_url);html+="<div class=\\"selection-preview-item\\" data-id=\\""+id+"\\"><img src=\\""+(imgUrl||"")+"\\" onerror=\\"this.style.display=\'none\'\\"><div class=\\"selection-preview-item-info\\"><div class=\\"selection-preview-item-style\\">"+pr.style_id+"</div><div class=\\"selection-preview-item-name\\">"+pr.name+"</div></div><button class=\\"selection-preview-item-remove\\" onclick=\\"removeFromSelection("+id+")\\">✕</button></div>"});list.innerHTML=html;styleCount.textContent=Object.keys(styles).length;colorCount.textContent=totalSkus;qtyTotal.textContent=totalQty.toLocaleString()}';
    html += 'function removeFromSelection(id){var idx=selectedProducts.indexOf(id);if(idx!==-1){selectedProducts.splice(idx,1);updateSelectionUI();renderProducts()}}';
    html += 'document.getElementById("togglePreviewBtn").addEventListener("click",function(){var preview=document.getElementById("selectionPreview");preview.classList.toggle("visible")});';
    html += 'document.getElementById("closePreviewBtn").addEventListener("click",function(){document.getElementById("selectionPreview").classList.remove("visible")});';
    
    html += 'document.getElementById("shareSelectionBtn").addEventListener("click",function(){document.getElementById("shareModal").classList.add("active");document.getElementById("shareResult").classList.add("hidden");document.getElementById("shareForm").classList.remove("hidden");document.getElementById("selectionName").value="";document.getElementById("hideQuantities").checked=false});';
    html += 'document.getElementById("cancelShareBtn").addEventListener("click",function(){document.getElementById("shareModal").classList.remove("active")});';
    html += 'document.getElementById("closeShareModalBtn").addEventListener("click",function(){document.getElementById("shareModal").classList.remove("active")});';
    
    html += 'var currentShareUrl="";';
    html += 'document.getElementById("createShareBtn").addEventListener("click",function(){var name=document.getElementById("selectionName").value||"Product Selection";var hideQuantities=document.getElementById("hideQuantities").checked;fetch("/api/selections",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({productIds:selectedProducts,name:name,shareType:"link",hideQuantities:hideQuantities})}).then(function(r){return r.json()}).then(function(d){if(d.success){currentShareId=d.shareId;currentShareUrl=window.location.origin+"/share/"+d.shareId;document.getElementById("shareNameDisplay").textContent=name+" • "+selectedProducts.length+" items";document.getElementById("pdfLink").href="/api/selections/"+d.shareId+"/pdf";document.getElementById("shareForm").classList.add("hidden");document.getElementById("shareResult").classList.remove("hidden");loadShares()}else{alert(d.error)}})});';
    
    html += 'document.getElementById("copyLinkBtn").addEventListener("click",function(){navigator.clipboard.writeText(currentShareUrl).then(function(){var btn=document.getElementById("copyLinkBtn");btn.textContent="✓ Copied!";setTimeout(function(){btn.textContent="Copy Link"},2000)})});';
    
    html += 'document.getElementById("emailLinkBtn").addEventListener("click",function(){var name=document.getElementById("selectionName").value||"Product Selection";var subject=encodeURIComponent(name+" - Mark Edwards Apparel");var body=encodeURIComponent("Here is the product selection I wanted to share with you:\\n\\n"+currentShareUrl);window.location.href="mailto:?subject="+subject+"&body="+body});';
    
    html += 'document.getElementById("textLinkBtn").addEventListener("click",function(){var name=document.getElementById("selectionName").value||"Product Selection";var body=encodeURIComponent(name+"\\n"+currentShareUrl);window.location.href="sms:?body="+body});';
    
    // Record PDF download
    html += 'document.getElementById("pdfLink").addEventListener("click",function(){if(currentShareId){fetch("/api/selections/"+currentShareId+"/record-pdf",{method:"POST"}).then(function(){loadShares()})}});';
    
    html += 'document.getElementById("csvFile").addEventListener("change",function(e){var f=e.target.files[0];if(!f)return;var fd=new FormData();fd.append("file",f);document.getElementById("importStatus").innerHTML="Importing...";fetch("/api/import",{method:"POST",body:fd}).then(function(r){if(!r.ok){return r.text().then(function(t){throw new Error("Server error: "+r.status+" - "+t)})}return r.json()}).then(function(d){document.getElementById("importStatus").innerHTML=d.success?"<span class=success>Imported "+d.imported+" products (File: "+d.fileType+")"+(d.newArrivals?" - "+d.newArrivals+" new":"")+"</span>":"<span class=error>Error: "+(d.error||"Unknown error")+"</span>";loadProducts();loadHistory();loadDataFreshness()}).catch(function(err){document.getElementById("importStatus").innerHTML="<span class=error>Import failed: "+err.message+"</span>"})});';
    
    // Sales CSV import handler
    html += 'document.getElementById("salesCsvFile").addEventListener("change",function(e){var f=e.target.files[0];if(!f)return;var fd=new FormData();fd.append("file",f);document.getElementById("salesImportStatus").innerHTML="<span style=\\"color:#666\\">Importing sales data... This may take a moment for large files.</span>";fetch("/api/import-sales",{method:"POST",body:fd}).then(function(r){return r.json()}).then(function(d){if(d.success){var msg="✓ Imported "+d.imported.toLocaleString()+" new records";if(d.skipped>0)msg+=" ("+d.skipped.toLocaleString()+" duplicates skipped)";if(d.errors)msg+=" ("+d.errors+" errors)";document.getElementById("salesImportStatus").innerHTML="<span class=\\"success\\">"+msg+"</span>";loadSalesStats()}else{document.getElementById("salesImportStatus").innerHTML="<span class=\\"error\\">"+d.error+"</span>"}}).catch(function(e){document.getElementById("salesImportStatus").innerHTML="<span class=\\"error\\">Error: "+e.message+"</span>"})});';
    html += 'function loadSalesStats(){fetch("/api/sales-stats").then(function(r){return r.json()}).then(function(d){if(d.success){var h="<div class=\\"status-box\\"><div class=\\"status-item\\"><span class=\\"status-label\\">Total Records: </span><span class=\\"status-value\\">"+d.totalRecords.toLocaleString()+"</span></div><div class=\\"status-item\\"><span class=\\"status-label\\">Sales Orders: </span><span class=\\"status-value\\">"+d.salesOrders.toLocaleString()+"</span></div><div class=\\"status-item\\"><span class=\\"status-label\\">Purchase Orders: </span><span class=\\"status-value\\">"+d.purchaseOrders.toLocaleString()+"</span></div><div class=\\"status-item\\"><span class=\\"status-label\\">Unique Styles: </span><span class=\\"status-value\\">"+d.uniqueStyles.toLocaleString()+"</span></div></div>";document.getElementById("salesDataStats").innerHTML=h}}).catch(function(){})}';
    
    html += 'document.getElementById("clearBtn").addEventListener("click",function(){if(!confirm("Delete all products?"))return;fetch("/api/products/clear",{method:"POST"}).then(function(){loadProducts()})});';
    html += 'document.getElementById("clearSalesBtn").addEventListener("click",function(){if(!confirm("Delete ALL sales data? This cannot be undone."))return;fetch("/api/sales-data/clear",{method:"POST"}).then(function(r){return r.json()}).then(function(d){if(d.success){alert("Sales data cleared!");loadSalesStats()}else{alert("Error: "+d.error)}})});';
    
    html += 'function loadUsers(){fetch("/api/users").then(function(r){return r.json()}).then(function(u){var h="";u.forEach(function(x){h+="<tr><td>"+x.display_name+"</td><td><span class=\\"pin-display\\">"+x.pin+"</span></td><td><select onchange=\\"changeUserRole("+x.id+",this.value)\\" "+(x.role==="admin"&&u.filter(function(y){return y.role==="admin"}).length===1?"disabled":"")+">"+"<option value=\\"sales_rep\\""+(x.role==="sales_rep"?" selected":"")+">Sales Rep</option>"+"<option value=\\"admin\\""+(x.role==="admin"?" selected":"")+">Admin</option></select></td><td><button class=\\"btn btn-secondary btn-sm\\" onclick=\\"resetUserPin("+x.id+")\\" style=\\"margin-right:0.5rem\\">Reset PIN</button><button class=\\"btn btn-danger btn-sm\\" onclick=\\"deleteUser("+x.id+")\\">Delete</button></td></tr>"});document.getElementById("usersTable").innerHTML=h})}';
    html += 'function resetUserPin(id){if(!confirm("Generate new random PIN for this user?"))return;fetch("/api/users/"+id+"/reset-pin",{method:"PUT"}).then(function(r){return r.json()}).then(function(d){if(d.success){alert("New PIN: "+d.pin);loadUsers()}})}';
    html += 'function changeUserRole(id,role){fetch("/api/users/"+id+"/role",{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify({role:role})}).then(function(r){return r.json()}).then(function(d){if(d.success)loadUsers()})}';
    html += 'document.getElementById("addUserBtn").addEventListener("click",function(){var displayName=document.getElementById("newUserName").value;if(!displayName){alert("Enter a name");return}fetch("/api/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({displayName:displayName,username:displayName.toLowerCase().replace(/\\s+/g,"_"),role:document.getElementById("newRole").value})}).then(function(r){return r.json()}).then(function(d){if(d.success){alert("User created! PIN: "+d.pin);document.getElementById("newUserName").value="";loadUsers()}else{alert("Error: "+d.error)}})});';
    html += 'function deleteUser(id){if(!confirm("Delete user?"))return;fetch("/api/users/"+id,{method:"DELETE"}).then(function(){loadUsers()})}';
    
    // System Health functions
    html += 'function loadSystemHealth(){fetch("/api/system-health").then(function(r){return r.json()}).then(function(d){if(!d.success){document.getElementById("systemHealthContent").innerHTML="<p class=\\"error\\">Error loading system health</p>";return}var h="<div class=\\"system-health-grid\\">";h+="<div class=\\"health-card\\"><h4>Database</h4><div class=\\"health-stats\\">";h+="<div class=\\"health-row\\"><span>Total Size:</span><strong>"+d.database.totalSize+"</strong></div>";h+="<div class=\\"health-row\\"><span>Products:</span><strong>"+d.database.tables.products.toLocaleString()+"</strong></div>";h+="<div class=\\"health-row\\"><span>Color Variants:</span><strong>"+d.database.tables.product_colors.toLocaleString()+"</strong></div>";h+="<div class=\\"health-row\\"><span>Users:</span><strong>"+d.database.tables.users+"</strong></div>";h+="<div class=\\"health-row\\"><span>Shares Created:</span><strong>"+d.database.tables.selections+"</strong></div>";h+="<div class=\\"health-row\\"><span>User Picks:</span><strong>"+d.database.tables.user_picks+"</strong></div>";h+="<div class=\\"health-row\\"><span>User Notes:</span><strong>"+d.database.tables.user_notes+"</strong></div>";h+="</div></div>";h+="<div class=\\"health-card\\"><h4>AI Analysis</h4><div class=\\"health-stats\\">";h+="<div class=\\"health-row\\"><span>Products Analyzed:</span><strong>"+d.database.productsWithAI.toLocaleString()+"</strong></div>";h+="<div class=\\"health-row\\"><span>Pending Analysis:</span><strong>"+d.database.productsWithoutAI.toLocaleString()+"</strong></div>";var aiPct=d.database.tables.products>0?Math.round(d.database.productsWithAI/d.database.tables.products*100):0;h+="<div class=\\"health-row\\"><span>Coverage:</span><strong>"+aiPct+"%</strong></div>";h+="<div class=\\"health-row\\"><span>Anthropic API:</span><strong class=\\"status-"+(d.apiStatus.anthropicConfigured?"ok":"warn")+"\\">"+(d.apiStatus.anthropicConfigured?"✓ Configured":"✗ Not Set")+"</strong></div>";h+="</div></div>";h+="<div class=\\"health-card\\"><h4>Integrations</h4><div class=\\"health-stats\\">";h+="<div class=\\"health-row\\"><span>Zoho Configured:</span><strong class=\\"status-"+(d.apiStatus.zohoConfigured?"ok":"warn")+"\\">"+(d.apiStatus.zohoConfigured?"✓ Yes":"✗ No")+"</strong></div>";h+="<div class=\\"health-row\\"><span>Zoho Connected:</span><strong class=\\"status-"+(d.apiStatus.zohoConnected?"ok":"warn")+"\\">"+(d.apiStatus.zohoConnected?"✓ Yes":"✗ No")+"</strong></div>";h+="<div class=\\"health-row\\"><span>Last Sync:</span><strong>"+(d.activity.lastSuccessfulSync?new Date(d.activity.lastSuccessfulSync).toLocaleDateString():"Never")+"</strong></div>";h+="<div class=\\"health-row\\"><span>Last Sync Records:</span><strong>"+(d.activity.lastSyncRecords||"-")+"</strong></div>";h+="</div></div>";h+="<div class=\\"health-card\\"><h4>Server</h4><div class=\\"health-stats\\">";h+="<div class=\\"health-row\\"><span>Uptime:</span><strong>"+d.server.uptime+"</strong></div>";h+="<div class=\\"health-row\\"><span>Memory Used:</span><strong>"+d.server.memoryUsed+"</strong></div>";h+="<div class=\\"health-row\\"><span>Memory Total:</span><strong>"+d.server.memoryTotal+"</strong></div>";h+="<div class=\\"health-row\\"><span>Node.js:</span><strong>"+d.server.nodeVersion+"</strong></div>";h+="<div class=\\"health-row\\"><span>Platform:</span><strong>"+d.server.platform+"</strong></div>";h+="</div></div>";h+="<div class=\\"health-card\\"><h4>Activity (7 days)</h4><div class=\\"health-stats\\">";h+="<div class=\\"health-row\\"><span>Users with Picks:</span><strong>"+d.activity.activeUsers+"</strong></div>";h+="<div class=\\"health-row\\"><span>Shares Created:</span><strong>"+d.activity.sharesLast7Days+"</strong></div>";h+="<div class=\\"health-row\\"><span>Data Syncs:</span><strong>"+d.activity.syncsLast7Days+"</strong></div>";h+="</div></div>";h+="</div>";h+="<p style=\\"margin-top:1rem;font-size:0.8rem;color:#999\\">Last checked: "+new Date(d.timestamp).toLocaleString()+"</p>";document.getElementById("systemHealthContent").innerHTML=h}).catch(function(e){document.getElementById("systemHealthContent").innerHTML="<p class=\\"error\\">Error: "+e.message+"</p>"})}';
    html += 'document.getElementById("refreshSystemBtn").addEventListener("click",loadSystemHealth);';
    
    // Image Cache functions
    html += 'function loadCacheStatus(){fetch("/api/image-cache/stats").then(function(r){return r.json()}).then(function(d){if(d.error){document.getElementById("cacheStatus").textContent="Error";document.getElementById("cacheStatus").className="status-value disconnected";return}if(d.available){document.getElementById("cacheStatus").textContent="Active";document.getElementById("cacheStatus").className="status-value connected"}else{document.getElementById("cacheStatus").textContent="Not Available (Volume not mounted)";document.getElementById("cacheStatus").className="status-value disconnected"}document.getElementById("cachedCount").textContent=d.cached||0;document.getElementById("totalImagesCount").textContent=d.totalProducts||0;document.getElementById("cacheSize").textContent=(d.totalSizeMB||0)+" MB"})}';
    
    // Auto Import functions
    html += 'function loadAutoImportStatus(){fetch("/api/workdrive-import/status").then(function(r){return r.json()}).then(function(d){if(d.error){document.getElementById("autoImportStatus").textContent="Error";return}document.getElementById("autoImportStatus").textContent="Active";document.getElementById("autoImportStatus").className="status-value connected";document.getElementById("autoImportInterval").textContent="Every "+d.checkIntervalHours+" hours";document.getElementById("autoImportInventory").textContent=d.inventoryFiles+" files ("+d.inventoryRecords.toLocaleString()+" records)";document.getElementById("autoImportSales").textContent=d.salesFiles+" files ("+d.salesRecords.toLocaleString()+" records)";var listHtml="";if(d.recentImports&&d.recentImports.length>0){listHtml="<table style=\\"width:100%;border-collapse:collapse\\"><thead><tr style=\\"border-bottom:1px solid #ddd\\"><th style=\\"text-align:left;padding:4px\\">File</th><th style=\\"text-align:left;padding:4px\\">Type</th><th style=\\"text-align:right;padding:4px\\">Records</th><th style=\\"text-align:left;padding:4px\\">Status</th><th style=\\"text-align:left;padding:4px\\">Time</th></tr></thead><tbody>";d.recentImports.forEach(function(imp){var statusColor=imp.status==="success"?"#22c55e":"#ef4444";listHtml+="<tr><td style=\\"padding:4px\\">"+imp.file_name+"</td><td style=\\"padding:4px\\">"+imp.file_type+"</td><td style=\\"text-align:right;padding:4px\\">"+(imp.records_imported||0)+"</td><td style=\\"padding:4px;color:"+statusColor+"\\">"+imp.status+"</td><td style=\\"padding:4px\\">"+new Date(imp.processed_at).toLocaleString()+"</td></tr>"});listHtml+="</tbody></table>"}else{listHtml="<p style=\\"color:#666\\">No imports yet</p>"}document.getElementById("recentImportsList").innerHTML=listHtml})}';
    html += 'document.getElementById("checkWorkDriveBtn").addEventListener("click",function(){var btn=this;btn.disabled=true;btn.textContent="Checking...";document.getElementById("autoImportMessage").innerHTML="<span style=\\"color:#666\\">Checking WorkDrive folders for new files...</span>";fetch("/api/workdrive-import/check-now",{method:"POST"}).then(function(r){return r.json()}).then(function(d){btn.disabled=false;btn.textContent="Check All";if(d.success){document.getElementById("autoImportMessage").innerHTML="<span class=\\"success\\">Processed "+d.processed+" new files</span>"}else{document.getElementById("autoImportMessage").innerHTML="<span class=\\"error\\">"+d.error+"</span>"}loadAutoImportStatus();loadProducts()})});';
    html += 'document.getElementById("checkSalesOnlyBtn").addEventListener("click",function(){var btn=this;btn.disabled=true;btn.textContent="Checking Sales...";document.getElementById("autoImportMessage").innerHTML="<span style=\\"color:#666\\">Checking Sales-PO folder only...</span>";fetch("/api/workdrive-import/check-sales-only",{method:"POST"}).then(function(r){return r.json()}).then(function(d){btn.disabled=false;btn.textContent="Check Sales Only";if(d.success){document.getElementById("autoImportMessage").innerHTML="<span class=\\"success\\">Processed "+d.processed+" sales file(s)</span>"}else{document.getElementById("autoImportMessage").innerHTML="<span class=\\"error\\">"+d.error+"</span>"}loadAutoImportStatus();loadProducts()})});';
    html += 'document.getElementById("clearAutoImportBtn").addEventListener("click",function(){if(!confirm("Clear import history? Files will be re-processed on next check."))return;fetch("/api/workdrive-import/clear-history",{method:"POST"}).then(function(r){return r.json()}).then(function(d){if(d.success){document.getElementById("autoImportMessage").innerHTML="<span class=\\"success\\">History cleared</span>"}loadAutoImportStatus()})});';

    // Trigger Export via Zoho Flow
    html += 'var currentExportJobId=null;';
    html += 'document.getElementById("triggerExportBtn").addEventListener("click",function(){var btn=this;btn.disabled=true;btn.textContent="Triggering...";document.getElementById("exportJobStatus").textContent="Triggering Zoho Flow export...";fetch("/api/trigger-export",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({exportType:"sales"})}).then(function(r){return r.json()}).then(function(d){btn.disabled=false;btn.textContent="Trigger Export";if(d.success){document.getElementById("exportJobStatus").innerHTML="<span class=\\"success\\">✓ Export triggered! Job ID: "+d.jobId+"</span>";currentExportJobId=d.jobId;pollExportStatus()}else{document.getElementById("exportJobStatus").innerHTML="<span class=\\"error\\">"+d.error+"</span>"}loadExportJobs()})});';
    html += 'function pollExportStatus(){if(!currentExportJobId)return;fetch("/api/export-status?jobId="+currentExportJobId).then(function(r){return r.json()}).then(function(d){if(d.success&&d.job){var job=d.job;var statusText="Status: "+job.status;if(job.file_name)statusText+=" - File: "+job.file_name;document.getElementById("exportJobStatus").innerHTML="<span style=\\"color:"+(job.status==="completed"?"#22c55e":job.status==="failed"?"#ef4444":"#666")+"\\">"+statusText+"</span>";if(job.status==="pending"||job.status==="processing"){setTimeout(pollExportStatus,3000)}else{loadAutoImportStatus();loadExportJobs()}}})}';
    html += 'function loadExportJobs(){fetch("/api/export-jobs").then(function(r){return r.json()}).then(function(jobs){if(!jobs||jobs.length===0){document.getElementById("exportJobsList").innerHTML="<p style=\\"color:#666\\">No export jobs yet</p>";return}var html="<table style=\\"width:100%;border-collapse:collapse;font-size:0.75rem\\"><thead><tr style=\\"border-bottom:1px solid #ddd\\"><th style=\\"text-align:left;padding:2px\\">Job</th><th style=\\"text-align:left;padding:2px\\">Status</th><th style=\\"text-align:left;padding:2px\\">File</th><th style=\\"text-align:left;padding:2px\\">Time</th></tr></thead><tbody>";jobs.slice(0,5).forEach(function(job){var statusColor=job.status==="completed"?"#22c55e":job.status==="failed"?"#ef4444":job.status==="cancelled"?"#9ca3af":"#f59e0b";html+="<tr><td style=\\"padding:2px\\">"+job.job_id.substring(0,15)+"...</td><td style=\\"padding:2px;color:"+statusColor+"\\">"+job.status+"</td><td style=\\"padding:2px\\">"+(job.file_name||"-")+"</td><td style=\\"padding:2px\\">"+new Date(job.triggered_at).toLocaleTimeString()+"</td></tr>"});html+="</tbody></table>";document.getElementById("exportJobsList").innerHTML=html})}';
    html += 'document.getElementById("clearStuckJobsBtn").addEventListener("click",function(){fetch("/api/clear-stuck-jobs",{method:"POST"}).then(function(r){return r.json()}).then(function(d){if(d.success){document.getElementById("exportJobStatus").innerHTML="<span style=\\"color:#666\\">Cleared "+d.cleared+" stuck job(s)</span>";loadExportJobs()}})});';

    html += 'document.getElementById("refreshCacheBtn").addEventListener("click",function(){var btn=this;btn.disabled=true;btn.textContent="Refreshing...";document.getElementById("cacheMessage").innerHTML="<span style=\\"color:#666\\">Downloading images from Zoho WorkDrive... This may take a few minutes.</span>";fetch("/api/image-cache/refresh",{method:"POST"}).then(function(r){return r.json()}).then(function(d){btn.disabled=false;btn.textContent="Refresh All Images";if(d.success){document.getElementById("cacheMessage").innerHTML="<span class=\\"success\\">✓ Refreshed "+d.refreshed+" of "+d.total+" images"+(d.errors?" ("+d.errors+" errors)":"")+"</span>"}else{document.getElementById("cacheMessage").innerHTML="<span class=\\"error\\">"+d.error+"</span>"}loadCacheStatus()})});';
    html += 'document.getElementById("clearCacheBtn").addEventListener("click",function(){if(!confirm("Clear all cached images? They will be re-downloaded on next view."))return;fetch("/api/image-cache/clear",{method:"POST"}).then(function(r){return r.json()}).then(function(d){if(d.success){document.getElementById("cacheMessage").innerHTML="<span class=\\"success\\">✓ Cleared "+d.deleted+" cached files</span>"}else{document.getElementById("cacheMessage").innerHTML="<span class=\\"error\\">"+d.error+"</span>"}loadCacheStatus()})});';
    
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
    html += 'document.getElementById("saveNoteBtn").addEventListener("click",function(){console.log("Save note button clicked");if(currentModalBaseStyle){console.log("Base Style:",currentModalBaseStyle);var btn=this;var originalText=btn.textContent;btn.textContent="Saving...";btn.disabled=true;var note=document.getElementById("modalNote").value;console.log("Note value:",note);fetch("/api/notes/"+encodeURIComponent(currentModalBaseStyle),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({note:note})}).then(function(r){console.log("Response status:",r.status);return r.json()}).then(function(d){console.log("Response data:",d);if(d.success){if(note.trim()){userNotes[currentModalBaseStyle]=note}else{delete userNotes[currentModalBaseStyle]}renderProducts();btn.textContent="✓ Saved!";setTimeout(function(){btn.textContent=originalText;btn.disabled=false},1500)}else{console.error("Save failed:",d);btn.textContent="Error";setTimeout(function(){btn.textContent=originalText;btn.disabled=false},1500)}}).catch(function(err){console.error("Fetch error:",err);btn.textContent="Error";setTimeout(function(){btn.textContent=originalText;btn.disabled=false},1500)})}else{console.error("No currentModalBaseStyle")}});';
    
    // Keyboard navigation
    html += 'document.addEventListener("keydown",function(e){if(document.getElementById("modal").classList.contains("active")){if(e.key==="Escape"){document.getElementById("modal").classList.remove("active")}return}if(document.getElementById("shareModal").classList.contains("active")){if(e.key==="Escape"){document.getElementById("shareModal").classList.remove("active")}return}if(document.activeElement.tagName==="INPUT"||document.activeElement.tagName==="TEXTAREA")return;var cards=document.querySelectorAll(".product-card");if(cards.length===0)return;if(e.key==="ArrowRight"||e.key==="ArrowDown"){e.preventDefault();focusedIndex=Math.min(focusedIndex+1,cards.length-1);updateFocus(cards)}else if(e.key==="ArrowLeft"||e.key==="ArrowUp"){e.preventDefault();focusedIndex=Math.max(focusedIndex-1,0);updateFocus(cards)}else if(e.key==="Enter"&&focusedIndex>=0){e.preventDefault();var id=parseInt(products[focusedIndex].id);if(selectionMode){var idx=selectedProducts.indexOf(id);if(idx===-1){selectedProducts.push(id)}else{selectedProducts.splice(idx,1)}updateSelectionUI();renderProducts()}else{showProductModal(id)}}else if(e.key===" "&&focusedIndex>=0&&selectionMode){e.preventDefault();var id=parseInt(products[focusedIndex].id);var idx=selectedProducts.indexOf(id);if(idx===-1){selectedProducts.push(id)}else{selectedProducts.splice(idx,1)}updateSelectionUI();renderProducts()}});';
    
    html += 'function updateFocus(cards){cards.forEach(function(c,i){c.classList.toggle("focused",i===focusedIndex)});if(focusedIndex>=0&&cards[focusedIndex]){cards[focusedIndex].scrollIntoView({block:"nearest",behavior:"smooth"})}}';
    
    // Compact header scroll handler removed

    // ============================================
    // CATALOG SHARING FUNCTIONS
    // ============================================
    html += 'var selectedSubCategories=[];var selectedSubDays=["monday"];';

    html += 'function toggleSubDay(el,day){var idx=selectedSubDays.indexOf(day);if(idx>-1){if(selectedSubDays.length===1){alert("Select at least one day");return}selectedSubDays.splice(idx,1);el.style.background="transparent";el.style.color="#6e6e73";el.style.borderColor="#d2d2d7"}else{selectedSubDays.push(day);el.style.background="#0088c2";el.style.color="white";el.style.borderColor="#0088c2"}}';

    html += 'async function loadCatalogSharingPanel(){try{var res=await fetch("/api/catalog-categories");var data=await res.json();if(data.success){var container=document.getElementById("subCategoryPills");var h=\'<div class="sub-cat-pill active" data-cat="all" onclick="toggleSubCategory(this,\\\'all\\\')" style="padding:6px 14px;border-radius:20px;cursor:pointer;font-size:13px;border:1px solid #0088c2;background:#0088c2;color:white;font-weight:600;">All Categories</div>\';data.categories.forEach(function(cat){h+=\'<div class="sub-cat-pill" data-cat="\'+cat+\'" onclick="toggleSubCategory(this,\\\'\'+cat+\'\\\')" style="padding:6px 14px;border-radius:20px;cursor:pointer;font-size:13px;border:1px solid #d2d2d7;background:transparent;color:#6e6e73;">\'+cat+\'</div>\'});container.innerHTML=h}}catch(err){console.error("Error loading categories:",err)}loadSubscriptions();loadSendHistory()}';

    html += 'function toggleSubCategory(el,category){if(category==="all"){selectedSubCategories=[];document.querySelectorAll(".sub-cat-pill").forEach(function(p){p.style.background="transparent";p.style.color="#6e6e73";p.style.borderColor="#d2d2d7"});el.style.background="#0088c2";el.style.color="white";el.style.borderColor="#0088c2";return}var allPill=document.querySelector(\'.sub-cat-pill[data-cat="all"]\');allPill.style.background="transparent";allPill.style.color="#6e6e73";allPill.style.borderColor="#d2d2d7";var idx=selectedSubCategories.indexOf(category);if(idx>-1){selectedSubCategories.splice(idx,1);el.style.background="transparent";el.style.color="#6e6e73";el.style.borderColor="#d2d2d7"}else{selectedSubCategories.push(category);el.style.background="#0088c2";el.style.color="white";el.style.borderColor="#0088c2"}if(selectedSubCategories.length===0){allPill.style.background="#0088c2";allPill.style.color="white";allPill.style.borderColor="#0088c2"}}';

    html += 'async function createSubscription(){var name=document.getElementById("subRecipientName").value.trim();var email=document.getElementById("subRecipientEmail").value.trim();var company=document.getElementById("subCompany").value.trim();if(!name||!email){alert("Please enter recipient name and email");return}var body={recipient_name:name,recipient_email:email,company:company,categories:selectedSubCategories.length>0?selectedSubCategories:null,frequency:document.getElementById("subFrequency").value,send_days:selectedSubDays.slice(),send_time:document.getElementById("subSendTime").value,quantity_mode:document.getElementById("subQuantityMode").value,min_quantity:parseInt(document.getElementById("subMinQty").value)||0,show_pricing:document.getElementById("subShowPricing").checked,show_images:document.getElementById("subShowImages").checked,custom_message:document.getElementById("subCustomMessage").value.trim()};try{var res=await fetch("/api/catalog-subscriptions",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});var data=await res.json();if(data.success){document.getElementById("subRecipientName").value="";document.getElementById("subRecipientEmail").value="";document.getElementById("subCompany").value="";document.getElementById("subCustomMessage").value="";document.getElementById("subMinQty").value="0";selectedSubCategories=[];selectedSubDays=["monday"];loadCatalogSharingPanel();alert("Subscription created!")}else{alert("Error: "+data.error)}}catch(err){alert("Error: "+err.message)}}';

    html += 'function formatTime(timeStr){if(!timeStr)return"";var parts=timeStr.split(":");var hour=parseInt(parts[0]);var ampm=hour>=12?"PM":"AM";if(hour>12)hour-=12;if(hour===0)hour=12;return hour+":"+(parts[1]||"00")+" "+ampm}';

    html += 'async function loadSubscriptions(){try{var res=await fetch("/api/catalog-subscriptions");var data=await res.json();if(!data.success)return;var container=document.getElementById("subscriptionsList");if(data.subscriptions.length===0){container.innerHTML=\'<p style="color:#86868b;font-style:italic;">No subscriptions yet. Add one above!</p>\';return}var h="";data.subscriptions.forEach(function(sub){var cats=sub.categories?sub.categories.join(", "):"All Categories";var statusColor=sub.is_active?"#34c759":"#ff3b30";var statusText=sub.is_active?"Active":"Paused";var lastSent=sub.last_sent?new Date(sub.last_sent).toLocaleString():"Never";var freqText=sub.frequency.charAt(0).toUpperCase()+sub.frequency.slice(1);var subDays=sub.send_days||(sub.send_day?[sub.send_day]:["monday"]);if(sub.frequency!=="daily"&&sub.frequency!=="monthly"){var dayNames=subDays.map(function(d){return d.charAt(0).toUpperCase()+d.slice(1,3)});freqText+=" ("+dayNames.join(", ")+")"}freqText+=" at "+formatTime(sub.send_time);h+=\'<div style="background:#f5f5f7;border:1px solid #e5e5e7;border-radius:12px;padding:18px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;">\'+\'<div style="flex:1;">\'+\'<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">\'+\'<strong style="font-size:16px;color:#1e3a5f;">\'+sub.recipient_name+\'</strong>\'+\'<span style="color:#86868b;font-size:14px;">\'+sub.recipient_email+\'</span>\'+(sub.company?\'<span style="background:#e8f4f8;padding:2px 10px;border-radius:10px;font-size:12px;color:#0088c2;">\'+sub.company+\'</span>\':"")+\'<span style="background:\'+statusColor+\'22;color:\'+statusColor+\';padding:2px 10px;border-radius:10px;font-size:12px;font-weight:bold;">\'+statusText+\'</span>\'+\'</div>\'+\'<div style="color:#86868b;font-size:13px;">\'+\'📂 \'+cats+\' &nbsp;|&nbsp; 🔄 \'+freqText+\' &nbsp;|&nbsp; 📊 \'+(sub.quantity_mode==="both"?"Avail Now & LTS":sub.quantity_mode==="left_to_sell"?"Left to Sell":"Available Now")+(sub.min_quantity>0?" (min "+sub.min_quantity+")":"")+" &nbsp;|&nbsp; 📧 "+sub.total_sent+" sent &nbsp;|&nbsp; Last: "+lastSent+\'</div>\'+\'</div>\'+\'<div style="display:flex;gap:8px;flex-shrink:0;">\'+\'<button onclick="previewSubscription(\'+sub.id+\')" class="btn btn-secondary" style="padding:8px 14px;font-size:12px;" title="Preview link">👁 Preview</button>\'+\'<button onclick="sendNow(\'+sub.id+\')" style="background:#ff9500;color:white;border:none;padding:8px 14px;border-radius:980px;cursor:pointer;font-size:12px;" title="Send immediately">📤 Send Now</button>\'+\'<button onclick="toggleSubscription(\'+sub.id+\')" class="btn btn-secondary" style="padding:8px 14px;font-size:12px;" title="Pause/Resume">\'+(sub.is_active?"⏸ Pause":"▶ Resume")+\'</button>\'+\'<button onclick="deleteSubscription(\'+sub.id+\')" class="btn btn-danger" style="padding:8px 14px;font-size:12px;" title="Delete">🗑</button>\'+\'</div>\'+\'</div>\'});container.innerHTML=h}catch(err){console.error("Error loading subscriptions:",err);document.getElementById("subscriptionsList").innerHTML=\'<p style="color:#ff3b30;">Error loading subscriptions</p>\'}}';

    html += 'async function loadSendHistory(){try{var res=await fetch("/api/catalog-send-log");var data=await res.json();if(!data.success)return;var container=document.getElementById("sendHistoryList");if(data.logs.length===0){container.innerHTML=\'<p style="color:#86868b;font-style:italic;">No emails sent yet.</p>\';return}var h=\'<table style="width:100%;border-collapse:collapse;font-size:13px;"><tr style="border-bottom:1px solid #e5e5e7;"><th style="text-align:left;padding:8px;color:#86868b;">Date</th><th style="text-align:left;padding:8px;color:#86868b;">Recipient</th><th style="text-align:left;padding:8px;color:#86868b;">Company</th><th style="text-align:left;padding:8px;color:#86868b;">Categories</th><th style="text-align:left;padding:8px;color:#86868b;">Status</th><th style="text-align:left;padding:8px;color:#86868b;">Link</th></tr>\';data.logs.forEach(function(log){var statusColor=log.status==="sent"?"#34c759":"#ff3b30";h+=\'<tr style="border-bottom:1px solid #f0f0f0;"><td style="padding:8px;">\'+new Date(log.sent_at).toLocaleString()+\'</td><td style="padding:8px;">\'+log.recipient_name+\'<br><span style="color:#86868b;font-size:12px;">\'+log.recipient_email+\'</span></td><td style="padding:8px;">\'+(log.company||"-")+\'</td><td style="padding:8px;">\'+(log.categories?log.categories.join(", "):"All")+\'</td><td style="padding:8px;"><span style="color:\'+statusColor+\';">\'+log.status+\'</span></td><td style="padding:8px;"><a href="\'+log.share_url+\'" target="_blank" style="color:#0088c2;">View →</a></td></tr>\'});h+="</table>";container.innerHTML=h}catch(err){console.error("Error loading send history:",err)}}';

    html += 'async function previewSubscription(id){try{var res=await fetch("/api/catalog-subscriptions/"+id+"/preview",{method:"POST"});var data=await res.json();if(data.success){window.open(data.url,"_blank")}else{alert("Error: "+data.error)}}catch(err){alert("Error: "+err.message)}}';

    html += 'async function sendNow(id){if(!confirm("Send catalog email now?"))return;try{var res=await fetch("/api/catalog-subscriptions/"+id+"/send-now",{method:"POST"});var data=await res.json();if(data.success){alert(data.message);loadSubscriptions();loadSendHistory()}else{alert("Error: "+data.error)}}catch(err){alert("Error: "+err.message)}}';

    html += 'async function toggleSubscription(id){try{var res=await fetch("/api/catalog-subscriptions/"+id+"/toggle",{method:"POST"});var data=await res.json();if(data.success){loadSubscriptions()}}catch(err){alert("Error: "+err.message)}}';

    html += 'async function deleteSubscription(id){if(!confirm("Delete this subscription? This cannot be undone."))return;try{var res=await fetch("/api/catalog-subscriptions/"+id,{method:"DELETE"});var data=await res.json();if(data.success){loadSubscriptions();loadSendHistory()}}catch(err){alert("Error: "+err.message)}}';

    html += 'checkSession();fetchOpenOrders();';
    html += '</script><script src="/order-requests.js"></script><script src="/sidebar-enhanced.js"></script><script src="/size-grid.js"></script><script>';
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
    setTimeout(function() { startWorkDriveImportJob(); }, 15000);
    setTimeout(function() { startCatalogEmailScheduler(); }, 20000);

    // Schedule daily export trigger at 2am EST
    // Cron: minute hour day month weekday
    cron.schedule('0 7 * * *', async function() {  // 7 UTC = 2am EST
        console.log('[CRON] Triggering daily Zoho Flow export at', new Date().toISOString());
        try {
            var jobId = 'export_' + Date.now() + '_' + Math.random().toString(36).substring(2, 15);
            await pool.query(
                'INSERT INTO export_jobs (job_id, export_type, status) VALUES ($1, $2, $3)',
                [jobId, 'sales', 'pending']
            );

            var webhookUrl = process.env.ZOHO_FLOW_WEBHOOK_URL || 'https://flow.zoho.com/691122364/flow/webhook/incoming?zapikey=1001.e31d40549cda427ea3bc24543a0525c5.77f014125de41156e64d1b960d9d8c9b&isdebug=false';
            var callbackUrl = (process.env.APP_URL || 'https://product-catalog-production-682f.up.railway.app') + '/api/zoho-export-callback';

            var response = await fetch(webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ jobId: jobId, exportType: 'sales', callbackUrl: callbackUrl })
            });

            if (response.ok) {
                await pool.query('UPDATE export_jobs SET status = $1 WHERE job_id = $2', ['processing', jobId]);
                console.log('[CRON] Export triggered successfully, jobId:', jobId);
            } else {
                await pool.query('UPDATE export_jobs SET status = $1, error_message = $2 WHERE job_id = $3',
                    ['failed', 'HTTP ' + response.status, jobId]);
                console.log('[CRON] Export trigger failed:', response.status);
            }
        } catch (err) {
            console.error('[CRON] Export trigger error:', err.message);
        }
    }, { timezone: 'America/New_York' });
    console.log('Scheduled daily export trigger at 2am EST');
});
