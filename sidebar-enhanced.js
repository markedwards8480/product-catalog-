/* ═══════════════════════════════════════════
   ENHANCED SIDEBAR - Filters & Dashboard JS
   v3: Color bars, commodity/color toggle, fixed dropdowns
   ═══════════════════════════════════════════ */

(function() {
  'use strict';

  function waitForReady(cb) {
    if (typeof allProducts !== 'undefined' && allProducts.length > 0 && document.getElementById('treemapShelf')) {
      cb();
    } else {
      setTimeout(function() { waitForReady(cb); }, 300);
    }
  }

  waitForReady(function() {
    loadCSS();
    initEnhancedSidebar();

    // Default: open sidebar on page load
    setTimeout(function() {
      var shelf = document.getElementById('treemapShelf');
      if (shelf && !shelf.classList.contains('open')) {
        if (typeof openTreemapShelf === 'function') {
          openTreemapShelf();
        }
      }
    }, 200);

    // Default: set view to Small
    setTimeout(function() {
      document.querySelectorAll('.size-btn').forEach(function(b) {
        if (b.textContent.trim() === 'Small' && !b.classList.contains('active')) {
          b.click();
        }
      });
    }, 500);
  });

  function loadCSS() {
    if (!document.querySelector('link[href*="sidebar-enhanced"]')) {
      var link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = '/sidebar-enhanced.css';
      document.head.appendChild(link);
    }
  }

  // ═══════════════════════════════════════
  // INIT
  // ═══════════════════════════════════════
  function initEnhancedSidebar() {
    var shelf = document.getElementById('treemapShelf');
    if (!shelf) return;
    var inner = shelf.querySelector('.treemap-shelf-inner');
    if (!inner) return;

    // Update header title
    var titleSpan = inner.querySelector('#treemapTitle');
    if (titleSpan) titleSpan.textContent = 'Filters';

    // Re-attach close button
    var closeBtn = document.getElementById('closeTreemapShelf');
    if (closeBtn && typeof closeTreemapShelf === 'function') {
      closeBtn.addEventListener('click', function() { closeTreemapShelf(); });
    }

    // Build and append filters
    var filtersContainer = document.createElement('div');
    filtersContainer.id = 'shelfFiltersContainer';
    filtersContainer.innerHTML = buildFiltersHTML();
    inner.appendChild(filtersContainer);

    // Wire everything up
    wireSearchFilter();
    wireQuickFilters();
    wireCommodityColorToggle();
    wireCommodityFilter();
    wireColorFilter();
    wireCustomerFilter();
    wireSupplierFilter();
    wireQtyRange();
    wireSectionToggles();
    observeShelfState(shelf);

    // Populate
    populateCommodityList();
    populateColorDropdown();
    populateCustomerDropdown();
    populateSupplierDropdown();
  }

  // ═══════════════════════════════════════
  // BUILD HTML
  // ═══════════════════════════════════════
  function buildFiltersHTML() {
    return '' +
    // Search
    '<div class="shelf-filters-section">' +
      '<div class="shelf-section-header" data-section="search">' +
        '<div class="shelf-section-title"><span class="section-icon">🔍</span> Search</div>' +
        '<span class="chevron">▼</span>' +
      '</div>' +
      '<div class="shelf-section-body" data-section-body="search">' +
        '<div class="shelf-search-box">' +
          '<span class="search-icon">🔍</span>' +
          '<input type="text" class="shelf-search-input" id="shelfSearchInput" placeholder="Search styles...">' +
          '<button class="shelf-search-clear" id="shelfSearchClear">&times;</button>' +
        '</div>' +
      '</div>' +
    '</div>' +

    // Quick Filters
    '<div class="shelf-filters-section">' +
      '<div class="shelf-section-header" data-section="quick">' +
        '<div class="shelf-section-title"><span class="section-icon">⚡</span> Quick Filters</div>' +
        '<span class="chevron">▼</span>' +
      '</div>' +
      '<div class="shelf-section-body" data-section-body="quick">' +
        '<div class="shelf-quick-filters">' +
          '<button class="shelf-quick-btn" data-quick="new_arrivals">New Arrivals <span class="badge" id="shelfBadgeNew">0</span></button>' +
          '<button class="shelf-quick-btn" data-quick="my_picks">My Picks <span class="badge" id="shelfBadgePicks">0</span></button>' +
          '<button class="shelf-quick-btn" data-quick="in_stock">In Stock Now <span class="badge" id="shelfBadgeStock">0</span></button>' +
          '<button class="shelf-quick-btn" data-quick="has_notes">Has Notes <span class="badge" id="shelfBadgeNotes">0</span></button>' +
        '</div>' +
      '</div>' +
    '</div>' +

    // Commodity / Color toggle + list
    '<div class="shelf-filters-section">' +
      '<div class="shelf-section-header" data-section="commodity">' +
        '<div class="shelf-section-title"><span class="section-icon">📦</span> <span id="shelfListTitle">Commodity</span> <span class="shelf-filter-active-dot" id="commodityActiveDot"></span></div>' +
        '<span class="chevron">▼</span>' +
      '</div>' +
      '<div class="shelf-section-body" data-section-body="commodity">' +
        '<div class="shelf-toggle-row">' +
          '<button class="shelf-toggle-btn active" id="shelfShowCommodity">Commodity</button>' +
          '<button class="shelf-toggle-btn" id="shelfShowColor">Color</button>' +
        '</div>' +
        '<div class="shelf-commodity-list" id="shelfCommodityList"></div>' +
      '</div>' +
    '</div>' +

    // Color dropdown
    '<div class="shelf-filters-section">' +
      '<div class="shelf-section-header" data-section="color">' +
        '<div class="shelf-section-title"><span class="section-icon">🎨</span> Color Filter <span class="shelf-filter-active-dot" id="colorActiveDot"></span></div>' +
        '<span class="chevron">▼</span>' +
      '</div>' +
      '<div class="shelf-section-body" data-section-body="color">' +
        '<select class="shelf-dropdown" id="shelfColorDropdown"><option value="">All Colors</option></select>' +
      '</div>' +
    '</div>' +

    // Customer
    '<div class="shelf-filters-section">' +
      '<div class="shelf-section-header" data-section="customer">' +
        '<div class="shelf-section-title"><span class="section-icon">👥</span> Customer <span class="shelf-filter-active-dot" id="customerActiveDot"></span></div>' +
        '<span class="chevron">▼</span>' +
      '</div>' +
      '<div class="shelf-section-body" data-section-body="customer">' +
        '<select class="shelf-dropdown" id="shelfCustomerDropdown"><option value="">All Customers</option></select>' +
      '</div>' +
    '</div>' +

    // Supplier
    '<div class="shelf-filters-section">' +
      '<div class="shelf-section-header" data-section="supplier">' +
        '<div class="shelf-section-title"><span class="section-icon">🏭</span> Supplier <span class="shelf-filter-active-dot" id="supplierActiveDot"></span></div>' +
        '<span class="chevron">▼</span>' +
      '</div>' +
      '<div class="shelf-section-body" data-section-body="supplier">' +
        '<select class="shelf-dropdown" id="shelfSupplierDropdown"><option value="">All Suppliers</option></select>' +
      '</div>' +
    '</div>' +

    // Qty Range
    '<div class="shelf-filters-section">' +
      '<div class="shelf-section-header" data-section="qty">' +
        '<div class="shelf-section-title"><span class="section-icon">📊</span> Qty Range</div>' +
        '<span class="chevron">▼</span>' +
      '</div>' +
      '<div class="shelf-section-body" data-section-body="qty">' +
        '<div class="shelf-qty-range">' +
          '<input type="number" class="shelf-qty-input" id="shelfMinQty" placeholder="Min">' +
          '<span class="shelf-qty-sep">–</span>' +
          '<input type="number" class="shelf-qty-input" id="shelfMaxQty" placeholder="Max">' +
          '<button class="shelf-qty-reset" id="shelfQtyReset">Reset</button>' +
        '</div>' +
      '</div>' +
    '</div>';
  }

  // ═══════════════════════════════════════
  // COLOR PALETTE for bars
  // ═══════════════════════════════════════
  var COLORS = [
    '#1e3a5f','#2563eb','#0891b2','#059669','#65a30d',
    '#ca8a04','#ea580c','#dc2626','#be185d','#7c3aed',
    '#4f46e5','#0d9488','#16a34a','#d97706','#e11d48',
    '#6366f1','#06b6d4','#10b981','#f59e0b','#ef4444',
    '#8b5cf6','#14b8a6','#22c55e','#f97316','#ec4899',
    '#a855f7'
  ];

  // ═══════════════════════════════════════
  // COMMODITY / COLOR TOGGLE
  // ═══════════════════════════════════════
  var currentListMode = 'commodity';

  function wireCommodityColorToggle() {
    var btnCommodity = document.getElementById('shelfShowCommodity');
    var btnColor = document.getElementById('shelfShowColor');
    if (!btnCommodity || !btnColor) return;

    btnCommodity.addEventListener('click', function() {
      currentListMode = 'commodity';
      btnCommodity.classList.add('active');
      btnColor.classList.remove('active');
      document.getElementById('shelfListTitle').textContent = 'Commodity';
      populateCommodityList();
    });

    btnColor.addEventListener('click', function() {
      currentListMode = 'color';
      btnColor.classList.add('active');
      btnCommodity.classList.remove('active');
      document.getElementById('shelfListTitle').textContent = 'Color';
      populateColorList();
    });
  }

  // ═══════════════════════════════════════
  // COMMODITY LIST with color bars
  // ═══════════════════════════════════════
  function populateCommodityList() {
    var list = document.getElementById('shelfCommodityList');
    if (!list || typeof allProducts === 'undefined') return;

    var catCounts = {};
    allProducts.forEach(function(p) {
      var cat = p.category || 'Uncategorized';
      if (!catCounts[cat]) catCounts[cat] = 0;
      (p.colors || []).forEach(function(c) {
        var qty = (typeof qtyMode !== 'undefined' && qtyMode === 'left_to_sell')
          ? (c.left_to_sell || 0) : (c.available_now || c.available_qty || 0);
        catCounts[cat] += qty;
      });
    });

    var sorted = Object.keys(catCounts).sort(function(a, b) { return catCounts[b] - catCounts[a]; });
    var maxVal = sorted.length > 0 ? catCounts[sorted[0]] : 1;

    var html = '<div class="shelf-commodity-item shelf-commodity-all active" data-commodity="all">' +
      '<span class="commodity-name">All</span>' +
      '<span class="commodity-count">' + sorted.length + ' types</span>' +
    '</div>';

    sorted.forEach(function(cat, idx) {
      var count = catCounts[cat];
      var display = count >= 1000 ? (count / 1000).toFixed(1) + 'K' : count.toString();
      var pct = Math.max(2, Math.round((count / maxVal) * 100));
      var color = COLORS[idx % COLORS.length];

      html += '<div class="shelf-commodity-item" data-commodity="' + cat + '">' +
        '<div class="commodity-bar-bg">' +
          '<div class="commodity-bar" style="width:' + pct + '%;background:' + color + '"></div>' +
        '</div>' +
        '<span class="commodity-name">' + cat + '</span>' +
        '<span class="commodity-count">' + display + '</span>' +
      '</div>';
    });

    list.innerHTML = html;
  }

  // ═══════════════════════════════════════
  // COLOR LIST (by color breakdown)
  // ═══════════════════════════════════════
  function populateColorList() {
    var list = document.getElementById('shelfCommodityList');
    if (!list || typeof allProducts === 'undefined') return;

    var colorCounts = {};
    allProducts.forEach(function(p) {
      (p.colors || []).forEach(function(c) {
        var name = c.color_name || 'Unknown';
        if (!colorCounts[name]) colorCounts[name] = 0;
        var qty = (typeof qtyMode !== 'undefined' && qtyMode === 'left_to_sell')
          ? (c.left_to_sell || 0) : (c.available_now || c.available_qty || 0);
        colorCounts[name] += qty;
      });
    });

    var sorted = Object.keys(colorCounts).sort(function(a, b) { return colorCounts[b] - colorCounts[a]; });
    var maxVal = sorted.length > 0 ? colorCounts[sorted[0]] : 1;

    // Show top 30 colors
    var top = sorted.slice(0, 30);

    var html = '<div class="shelf-commodity-item shelf-commodity-all active" data-commodity="all">' +
      '<span class="commodity-name">All Colors</span>' +
      '<span class="commodity-count">' + sorted.length + ' colors</span>' +
    '</div>';

    top.forEach(function(color, idx) {
      var count = colorCounts[color];
      var display = count >= 1000 ? (count / 1000).toFixed(1) + 'K' : count.toString();
      var pct = Math.max(2, Math.round((count / maxVal) * 100));
      var barColor = getColorHex(color) || COLORS[idx % COLORS.length];

      html += '<div class="shelf-commodity-item" data-commodity="' + color + '" data-type="color">' +
        '<div class="commodity-bar-bg">' +
          '<div class="commodity-bar" style="width:' + pct + '%;background:' + barColor + '"></div>' +
        '</div>' +
        '<span class="commodity-name">' + color + '</span>' +
        '<span class="commodity-count">' + display + '</span>' +
      '</div>';
    });

    if (sorted.length > 30) {
      html += '<div style="text-align:center;padding:4px;color:#94a3b8;font-size:0.6875rem;">+' + (sorted.length - 30) + ' more colors</div>';
    }

    list.innerHTML = html;
  }

  function getColorHex(name) {
    var n = name.toLowerCase();
    if (n.indexOf('black') !== -1) return '#1a1a1a';
    if (n.indexOf('white') !== -1) return '#d4d4d4';
    if (n.indexOf('navy') !== -1) return '#1e3a5f';
    if (n.indexOf('blue') !== -1) return '#2563eb';
    if (n.indexOf('red') !== -1) return '#dc2626';
    if (n.indexOf('pink') !== -1) return '#ec4899';
    if (n.indexOf('green') !== -1) return '#16a34a';
    if (n.indexOf('grey') !== -1 || n.indexOf('gray') !== -1) return '#6b7280';
    if (n.indexOf('beige') !== -1 || n.indexOf('cream') !== -1) return '#d2b48c';
    if (n.indexOf('brown') !== -1) return '#92400e';
    if (n.indexOf('purple') !== -1 || n.indexOf('lavender') !== -1) return '#7c3aed';
    if (n.indexOf('orange') !== -1) return '#ea580c';
    if (n.indexOf('yellow') !== -1) return '#ca8a04';
    if (n.indexOf('teal') !== -1) return '#0d9488';
    if (n.indexOf('olive') !== -1) return '#65a30d';
    if (n.indexOf('burgundy') !== -1 || n.indexOf('wine') !== -1 || n.indexOf('maroon') !== -1) return '#881337';
    if (n.indexOf('charcoal') !== -1) return '#374151';
    if (n.indexOf('ivory') !== -1) return '#f5f5dc';
    if (n.indexOf('khaki') !== -1) return '#bdb76b';
    if (n.indexOf('coral') !== -1) return '#f87171';
    if (n.indexOf('sage') !== -1) return '#9caf88';
    if (n.indexOf('rust') !== -1) return '#b45309';
    return null;
  }

  // ═══════════════════════════════════════
  // SEARCH
  // ═══════════════════════════════════════
  function wireSearchFilter() {
    var shelfInput = document.getElementById('shelfSearchInput');
    var shelfClear = document.getElementById('shelfSearchClear');
    var mainInput = document.getElementById('searchInput');
    if (!shelfInput) return;

    if (mainInput && mainInput.value) {
      shelfInput.value = mainInput.value;
      shelfClear.classList.toggle('visible', mainInput.value.length > 0);
    }

    shelfInput.addEventListener('input', function() {
      shelfClear.classList.toggle('visible', shelfInput.value.length > 0);
      if (mainInput) {
        mainInput.value = shelfInput.value;
        mainInput.dispatchEvent(new Event('input', { bubbles: true }));
      }
    });

    shelfInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' && mainInput) {
        mainInput.dispatchEvent(new Event('change', { bubbles: true }));
      }
    });

    shelfClear.addEventListener('click', function() {
      shelfInput.value = '';
      shelfClear.classList.remove('visible');
      if (mainInput) {
        mainInput.value = '';
        mainInput.dispatchEvent(new Event('input', { bubbles: true }));
      }
      var mainClear = document.querySelector('.clear-btn, [onclick*="clearSearch"]');
      if (mainClear) mainClear.click();
    });

    if (mainInput) {
      mainInput.addEventListener('input', function() {
        shelfInput.value = mainInput.value;
        shelfClear.classList.toggle('visible', mainInput.value.length > 0);
      });
    }
  }

  // ═══════════════════════════════════════
  // QUICK FILTERS
  // ═══════════════════════════════════════
  function wireQuickFilters() {
    var buttons = document.querySelectorAll('.shelf-quick-btn[data-quick]');
    updateQuickBadges();

    buttons.forEach(function(btn) {
      btn.addEventListener('click', function() {
        var filter = btn.getAttribute('data-quick');
        var isActive = btn.classList.contains('active');
        buttons.forEach(function(b) { b.classList.remove('active'); });
        if (!isActive) btn.classList.add('active');

        var mainBtn = document.querySelector('[data-special="' + filter + '"]');
        if (mainBtn) {
          mainBtn.click();
        } else if (typeof specialFilter !== 'undefined') {
          specialFilter = isActive ? null : filter;
          if (typeof renderProducts === 'function') renderProducts();
        }
      });
    });
  }

  function updateQuickBadges() {
    if (typeof allProducts === 'undefined') return;
    var newCount = 0, stockCount = 0;
    allProducts.forEach(function(p) {
      if (p.is_new) newCount++;
      var hasStock = false;
      (p.colors || []).forEach(function(c) {
        if ((c.available_now || c.available_qty || 0) > 0) hasStock = true;
      });
      if (hasStock) stockCount++;
    });
    var el;
    el = document.getElementById('shelfBadgeNew'); if (el) el.textContent = newCount;
    el = document.getElementById('shelfBadgeStock'); if (el) el.textContent = stockCount;
  }

  // ═══════════════════════════════════════
  // COMMODITY FILTER (click handler)
  // ═══════════════════════════════════════
  function wireCommodityFilter() {
    var list = document.getElementById('shelfCommodityList');
    if (!list) return;

    list.addEventListener('click', function(e) {
      var item = e.target.closest('.shelf-commodity-item');
      if (!item) return;

      var value = item.getAttribute('data-commodity');
      var isColorMode = item.getAttribute('data-type') === 'color';

      if (value === 'all') {
        list.querySelectorAll('.shelf-commodity-item').forEach(function(i) { i.classList.remove('active'); });
        item.classList.add('active');
        if (isColorMode || currentListMode === 'color') {
          window.colorFilter = null;
          if (typeof renderProducts === 'function') renderProducts();
        } else {
          syncCommodityToMain('all');
        }
      } else {
        var allItem = list.querySelector('[data-commodity="all"]');
        if (allItem) allItem.classList.remove('active');
        // Single select - deselect others first
        list.querySelectorAll('.shelf-commodity-item:not(.shelf-commodity-all)').forEach(function(i) { i.classList.remove('active'); });
        item.classList.add('active');

        if (isColorMode || currentListMode === 'color') {
          window.colorFilter = value;
          if (typeof renderProducts === 'function') renderProducts();
        } else {
          syncCommodityToMain([value]);
        }
      }

      var dot = document.getElementById('commodityActiveDot');
      var hasFilter = !list.querySelector('[data-commodity="all"]').classList.contains('active');
      if (dot) dot.classList.toggle('visible', hasFilter);
    });
  }

  function syncCommodityToMain(value) {
    if (value === 'all') {
      var allBtn = document.querySelector('#categoryFilters [data-cat="all"]');
      if (allBtn) allBtn.click();
      return;
    }
    if (Array.isArray(value)) {
      var allBtn = document.querySelector('#categoryFilters [data-cat="all"]');
      if (allBtn) allBtn.click();
      value.forEach(function(cat) {
        var btn = document.querySelector('#categoryFilters [data-cat="' + cat + '"]');
        if (btn) btn.click();
      });
    }
  }

  // ═══════════════════════════════════════
  // COLOR DROPDOWN
  // ═══════════════════════════════════════
  function populateColorDropdown() {
    var dropdown = document.getElementById('shelfColorDropdown');
    if (!dropdown || typeof allProducts === 'undefined') return;

    var colors = {};
    allProducts.forEach(function(p) {
      (p.colors || []).forEach(function(c) {
        if (c.color_name) {
          if (!colors[c.color_name]) colors[c.color_name] = 0;
          colors[c.color_name]++;
        }
      });
    });

    Object.keys(colors).sort(function(a, b) { return colors[b] - colors[a]; }).forEach(function(color) {
      var opt = document.createElement('option');
      opt.value = color;
      opt.textContent = color + ' (' + colors[color] + ')';
      dropdown.appendChild(opt);
    });
  }

  function wireColorFilter() {
    var dropdown = document.getElementById('shelfColorDropdown');
    if (!dropdown) return;

    dropdown.addEventListener('change', function() {
      var val = dropdown.value;
      window.colorFilter = val || null;
      if (typeof renderProducts === 'function') renderProducts();
      var dot = document.getElementById('colorActiveDot');
      if (dot) dot.classList.toggle('visible', !!val);
    });
  }

  // ═══════════════════════════════════════
  // CUSTOMER (scraped from main dropdown)
  // ═══════════════════════════════════════
  function populateCustomerDropdown() {
    var dropdown = document.getElementById('shelfCustomerDropdown');
    if (!dropdown) return;

    // Scrape from the existing main customer multi-dropdown
    var mainDropdown = document.getElementById('customerFilterBtn');
    if (!mainDropdown) return;
    var parentDiv = mainDropdown.parentElement;
    var labels = parentDiv.querySelectorAll('label');

    labels.forEach(function(label) {
      var checkbox = label.querySelector('input[type="checkbox"]');
      if (!checkbox) return;
      var text = label.textContent.trim();
      // Extract just the customer name (before the style count)
      var name = text.replace(/\d+\s*styles?.*$/i, '').trim();
      if (!name) return;

      var opt = document.createElement('option');
      opt.value = name;
      opt.textContent = text;
      dropdown.appendChild(opt);
    });
  }

  function wireCustomerFilter() {
    var dropdown = document.getElementById('shelfCustomerDropdown');
    if (!dropdown) return;

    dropdown.addEventListener('change', function() {
      var val = dropdown.value;

      // Click the corresponding checkbox in the main customer dropdown
      var mainBtn = document.getElementById('customerFilterBtn');
      if (mainBtn) {
        var parentDiv = mainBtn.parentElement;
        // First clear existing selections
        parentDiv.querySelectorAll('input[type="checkbox"]:checked').forEach(function(cb) { cb.click(); });

        if (val) {
          // Find and check the matching checkbox
          var labels = parentDiv.querySelectorAll('label');
          labels.forEach(function(label) {
            var name = label.textContent.trim().replace(/\d+\s*styles?.*$/i, '').trim();
            if (name === val) {
              var cb = label.querySelector('input[type="checkbox"]');
              if (cb && !cb.checked) cb.click();
            }
          });
          // Click Apply
          var applyBtn = parentDiv.querySelector('.apply-btn, button');
          if (applyBtn && applyBtn.textContent.trim() === 'Apply') applyBtn.click();
        } else {
          // Clear - click the clear button
          var clearBtn = parentDiv.querySelector('.clear-btn');
          if (clearBtn) clearBtn.click();
        }
      }

      var dot = document.getElementById('customerActiveDot');
      if (dot) dot.classList.toggle('visible', !!val);
    });
  }

  // ═══════════════════════════════════════
  // SUPPLIER (scraped from main dropdown)
  // ═══════════════════════════════════════
  function populateSupplierDropdown() {
    var dropdown = document.getElementById('shelfSupplierDropdown');
    if (!dropdown) return;

    var mainBtn = document.getElementById('supplierFilterBtn');
    if (!mainBtn) return;
    var parentDiv = mainBtn.parentElement;
    var labels = parentDiv.querySelectorAll('label');

    labels.forEach(function(label) {
      var checkbox = label.querySelector('input[type="checkbox"]');
      if (!checkbox) return;
      var text = label.textContent.trim();
      var name = text.replace(/\d+\s*styles?.*$/i, '').trim();
      if (!name) return;

      var opt = document.createElement('option');
      opt.value = name;
      opt.textContent = text;
      dropdown.appendChild(opt);
    });
  }

  function wireSupplierFilter() {
    var dropdown = document.getElementById('shelfSupplierDropdown');
    if (!dropdown) return;

    dropdown.addEventListener('change', function() {
      var val = dropdown.value;
      var mainBtn = document.getElementById('supplierFilterBtn');
      if (mainBtn) {
        var parentDiv = mainBtn.parentElement;
        parentDiv.querySelectorAll('input[type="checkbox"]:checked').forEach(function(cb) { cb.click(); });
        if (val) {
          var labels = parentDiv.querySelectorAll('label');
          labels.forEach(function(label) {
            var name = label.textContent.trim().replace(/\d+\s*styles?.*$/i, '').trim();
            if (name === val) {
              var cb = label.querySelector('input[type="checkbox"]');
              if (cb && !cb.checked) cb.click();
            }
          });
          var applyBtn = parentDiv.querySelector('.apply-btn, button');
          if (applyBtn && applyBtn.textContent.trim() === 'Apply') applyBtn.click();
        } else {
          var clearBtn = parentDiv.querySelector('.clear-btn');
          if (clearBtn) clearBtn.click();
        }
      }
      var dot = document.getElementById('supplierActiveDot');
      if (dot) dot.classList.toggle('visible', !!val);
    });
  }

  // ═══════════════════════════════════════
  // QTY RANGE
  // ═══════════════════════════════════════
  function wireQtyRange() {
    var shelfMin = document.getElementById('shelfMinQty');
    var shelfMax = document.getElementById('shelfMaxQty');
    var shelfReset = document.getElementById('shelfQtyReset');
    var mainMin = document.getElementById('minQty');
    var mainMax = document.getElementById('maxQty');
    if (!shelfMin || !shelfMax) return;

    function sync() {
      if (mainMin) { mainMin.value = shelfMin.value; mainMin.dispatchEvent(new Event('input', { bubbles: true })); }
      if (mainMax) { mainMax.value = shelfMax.value; mainMax.dispatchEvent(new Event('input', { bubbles: true })); }
      if (typeof renderProducts === 'function') renderProducts();
    }

    shelfMin.addEventListener('change', sync);
    shelfMax.addEventListener('change', sync);
    shelfMin.addEventListener('keydown', function(e) { if (e.key === 'Enter') sync(); });
    shelfMax.addEventListener('keydown', function(e) { if (e.key === 'Enter') sync(); });

    if (shelfReset) {
      shelfReset.addEventListener('click', function() {
        shelfMin.value = ''; shelfMax.value = '';
        if (mainMin) mainMin.value = '';
        if (mainMax) mainMax.value = '';
        var btn = document.querySelector('[onclick*="resetQty"]');
        if (btn) btn.click();
        else if (typeof renderProducts === 'function') renderProducts();
      });
    }
  }

  // ═══════════════════════════════════════
  // COLLAPSIBLE SECTIONS
  // ═══════════════════════════════════════
  function wireSectionToggles() {
    document.querySelectorAll('.shelf-section-header[data-section]').forEach(function(header) {
      header.addEventListener('click', function() {
        var section = header.getAttribute('data-section');
        var body = document.querySelector('[data-section-body="' + section + '"]');
        if (!body) return;
        body.classList.toggle('collapsed');
        header.classList.toggle('collapsed');
      });
    });
  }

  // ═══════════════════════════════════════
  // SHELF STATE OBSERVER
  // ═══════════════════════════════════════
  function observeShelfState(shelf) {
    var observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(m) {
        if (m.type === 'attributes' && m.attributeName === 'class') {
          document.body.classList.toggle('shelf-open', shelf.classList.contains('open'));
        }
      });
    });
    observer.observe(shelf, { attributes: true });
    document.body.classList.toggle('shelf-open', shelf.classList.contains('open'));
  }

})();
