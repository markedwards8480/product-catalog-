/* ═══════════════════════════════════════════
   ENHANCED SIDEBAR - Filters & Dashboard JS
   Hooks into existing page globals:
     - allProducts, renderProducts, renderFilters
     - colorFilter, qtyMode, specialFilter
     - selectedCategories (if treemap commodity filter)
     - document.getElementById('searchInput')
     - document.getElementById('minQty'), document.getElementById('maxQty')
     - document.getElementById('categoryFilters')
   ═══════════════════════════════════════════ */

(function() {
  'use strict';

  // Wait for DOM and products to be loaded
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
  });

  function loadCSS() {
    // Dynamically load the CSS since the link tag may not be in the HTML
    if (!document.querySelector('link[href*="sidebar-enhanced"]')) {
      var link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = '/sidebar-enhanced.css';
      document.head.appendChild(link);
    }
  }

  function initEnhancedSidebar() {
    var shelf = document.getElementById('treemapShelf');
    if (!shelf) return;

    var inner = shelf.querySelector('.treemap-shelf-inner');
    if (!inner) return;

    // Build the filters HTML
    var filtersHTML = buildFiltersHTML();

    // Append filters below existing treemap content
    var filtersContainer = document.createElement('div');
    filtersContainer.id = 'shelfFiltersContainer';
    filtersContainer.innerHTML = filtersHTML;
    inner.appendChild(filtersContainer);

    // Wire up all the filter interactions
    wireSearchFilter();
    wireQuickFilters();
    wireCommodityFilter();
    wireColorFilter();
    wireCustomerFilter();
    wireSupplierFilter();
    wireQtyRange();
    wireSectionToggles();

    // Toggle body class when shelf opens/closes
    observeShelfState(shelf);

    // Populate dynamic dropdowns
    populateColorDropdown();
    populateCustomerDropdown();
    populateSupplierDropdown();
    populateCommodityList();
  }

  function buildFiltersHTML() {
    return '' +
    // --- Search ---
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

    // --- Quick Filters ---
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

    // --- Commodity ---
    '<div class="shelf-filters-section">' +
      '<div class="shelf-section-header" data-section="commodity">' +
        '<div class="shelf-section-title"><span class="section-icon">📦</span> Commodity <span class="shelf-filter-active-dot" id="commodityActiveDot"></span></div>' +
        '<span class="chevron">▼</span>' +
      '</div>' +
      '<div class="shelf-section-body" data-section-body="commodity">' +
        '<div class="shelf-commodity-list" id="shelfCommodityList"></div>' +
      '</div>' +
    '</div>' +

    // --- Color ---
    '<div class="shelf-filters-section">' +
      '<div class="shelf-section-header" data-section="color">' +
        '<div class="shelf-section-title"><span class="section-icon">🎨</span> Color <span class="shelf-filter-active-dot" id="colorActiveDot"></span></div>' +
        '<span class="chevron">▼</span>' +
      '</div>' +
      '<div class="shelf-section-body" data-section-body="color">' +
        '<select class="shelf-dropdown" id="shelfColorDropdown"><option value="">All Colors</option></select>' +
      '</div>' +
    '</div>' +

    // --- Customer ---
    '<div class="shelf-filters-section">' +
      '<div class="shelf-section-header" data-section="customer">' +
        '<div class="shelf-section-title"><span class="section-icon">👥</span> Customer <span class="shelf-filter-active-dot" id="customerActiveDot"></span></div>' +
        '<span class="chevron">▼</span>' +
      '</div>' +
      '<div class="shelf-section-body" data-section-body="customer">' +
        '<select class="shelf-dropdown" id="shelfCustomerDropdown"><option value="">All Customers</option></select>' +
      '</div>' +
    '</div>' +

    // --- Supplier ---
    '<div class="shelf-filters-section">' +
      '<div class="shelf-section-header" data-section="supplier">' +
        '<div class="shelf-section-title"><span class="section-icon">🏭</span> Supplier <span class="shelf-filter-active-dot" id="supplierActiveDot"></span></div>' +
        '<span class="chevron">▼</span>' +
      '</div>' +
      '<div class="shelf-section-body" data-section-body="supplier">' +
        '<select class="shelf-dropdown" id="shelfSupplierDropdown"><option value="">All Suppliers</option></select>' +
      '</div>' +
    '</div>' +

    // --- Qty Range ---
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

  // ═══ SEARCH ═══
  function wireSearchFilter() {
    var shelfInput = document.getElementById('shelfSearchInput');
    var shelfClear = document.getElementById('shelfSearchClear');
    var mainInput = document.getElementById('searchInput');

    if (!shelfInput) return;

    // Sync from main search if it has a value
    if (mainInput && mainInput.value) {
      shelfInput.value = mainInput.value;
      shelfClear.classList.toggle('visible', mainInput.value.length > 0);
    }

    shelfInput.addEventListener('input', function() {
      var val = shelfInput.value;
      shelfClear.classList.toggle('visible', val.length > 0);
      // Sync to main search input and trigger its behavior
      if (mainInput) {
        mainInput.value = val;
        mainInput.dispatchEvent(new Event('input', { bubbles: true }));
      }
    });

    shelfInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        // Trigger search
        if (mainInput) {
          mainInput.dispatchEvent(new Event('change', { bubbles: true }));
          // Also try triggering the search button if it exists
          var searchBtn = document.querySelector('.search-btn, [onclick*="searchProducts"]');
          if (searchBtn) searchBtn.click();
        }
      }
    });

    shelfClear.addEventListener('click', function() {
      shelfInput.value = '';
      shelfClear.classList.remove('visible');
      if (mainInput) {
        mainInput.value = '';
        mainInput.dispatchEvent(new Event('input', { bubbles: true }));
      }
      // Try clicking the main clear button
      var mainClear = document.querySelector('.clear-btn, [onclick*="clearSearch"]');
      if (mainClear) mainClear.click();
    });

    // Listen for main input changes to sync back
    if (mainInput) {
      mainInput.addEventListener('input', function() {
        shelfInput.value = mainInput.value;
        shelfClear.classList.toggle('visible', mainInput.value.length > 0);
      });
    }
  }

  // ═══ QUICK FILTERS ═══
  function wireQuickFilters() {
    var buttons = document.querySelectorAll('.shelf-quick-btn[data-quick]');

    // Count badges
    updateQuickBadges();

    buttons.forEach(function(btn) {
      btn.addEventListener('click', function() {
        var filter = btn.getAttribute('data-quick');
        var isActive = btn.classList.contains('active');

        // Deactivate all
        buttons.forEach(function(b) { b.classList.remove('active'); });

        if (!isActive) {
          btn.classList.add('active');
        }

        // Map to existing special filter buttons
        var mainBtn = null;
        if (filter === 'new_arrivals') mainBtn = document.querySelector('[data-special="new_arrivals"], [onclick*="new_arrivals"]');
        else if (filter === 'my_picks') mainBtn = document.querySelector('[data-special="my_picks"], [onclick*="my_picks"]');
        else if (filter === 'in_stock') mainBtn = document.querySelector('[data-special="in_stock"], [onclick*="in_stock"]');
        else if (filter === 'has_notes') mainBtn = document.querySelector('[data-special="has_notes"], [onclick*="has_notes"]');

        if (mainBtn) {
          mainBtn.click();
        } else {
          // Fallback: set specialFilter directly
          if (typeof specialFilter !== 'undefined') {
            if (isActive) {
              specialFilter = null;
            } else {
              specialFilter = filter;
            }
            if (typeof renderProducts === 'function') renderProducts();
          }
        }
      });
    });
  }

  function updateQuickBadges() {
    if (typeof allProducts === 'undefined') return;

    var newCount = 0, picksCount = 0, stockCount = 0, notesCount = 0;

    allProducts.forEach(function(p) {
      if (p.is_new || p.first_seen_import === (typeof lastImportId !== 'undefined' ? lastImportId : '')) newCount++;
      if (typeof userPicks !== 'undefined' && userPicks.indexOf(p.id) !== -1) picksCount++;
      if (typeof userNotes !== 'undefined' && userNotes[p.id]) notesCount++;

      // Check if in stock (available_now > 0)
      var hasStock = false;
      (p.colors || []).forEach(function(c) {
        if ((c.available_now || c.available_qty || 0) > 0) hasStock = true;
      });
      if (hasStock) stockCount++;
    });

    var badgeNew = document.getElementById('shelfBadgeNew');
    var badgePicks = document.getElementById('shelfBadgePicks');
    var badgeStock = document.getElementById('shelfBadgeStock');
    var badgeNotes = document.getElementById('shelfBadgeNotes');

    if (badgeNew) badgeNew.textContent = newCount;
    if (badgePicks) badgePicks.textContent = picksCount;
    if (badgeStock) badgeStock.textContent = stockCount;
    if (badgeNotes) badgeNotes.textContent = notesCount;
  }

  // ═══ COMMODITY FILTER ═══
  function populateCommodityList() {
    var list = document.getElementById('shelfCommodityList');
    if (!list || typeof allProducts === 'undefined') return;

    // Build category counts
    var catCounts = {};
    allProducts.forEach(function(p) {
      var cat = p.category || 'Uncategorized';
      if (!catCounts[cat]) catCounts[cat] = 0;
      (p.colors || []).forEach(function(c) {
        var qty = (typeof qtyMode !== 'undefined' && qtyMode === 'left_to_sell')
          ? (c.left_to_sell || 0)
          : (c.available_now || c.available_qty || 0);
        catCounts[cat] += qty;
      });
    });

    var sorted = Object.keys(catCounts).sort(function(a, b) { return catCounts[b] - catCounts[a]; });

    var html = '<div class="shelf-commodity-item shelf-commodity-all active" data-commodity="all">' +
      '<span class="commodity-name">All</span>' +
      '<span class="commodity-count">' + sorted.length + ' types</span>' +
    '</div>';

    sorted.forEach(function(cat) {
      var count = catCounts[cat];
      var display = count >= 1000 ? (count / 1000).toFixed(1) + 'K' : count.toString();
      html += '<div class="shelf-commodity-item" data-commodity="' + cat + '">' +
        '<span class="commodity-name">' + cat + '</span>' +
        '<span class="commodity-count">' + display + '</span>' +
      '</div>';
    });

    list.innerHTML = html;
  }

  function wireCommodityFilter() {
    var list = document.getElementById('shelfCommodityList');
    if (!list) return;

    list.addEventListener('click', function(e) {
      var item = e.target.closest('.shelf-commodity-item');
      if (!item) return;

      var commodity = item.getAttribute('data-commodity');

      if (commodity === 'all') {
        // Clear all selections
        list.querySelectorAll('.shelf-commodity-item').forEach(function(i) { i.classList.remove('active'); });
        item.classList.add('active');

        // Sync to main filter
        syncCommodityToMain('all');
      } else {
        // Remove 'all' active
        var allItem = list.querySelector('[data-commodity="all"]');
        if (allItem) allItem.classList.remove('active');

        // Toggle this item
        item.classList.toggle('active');

        // If nothing selected, reactivate 'all'
        var activeItems = list.querySelectorAll('.shelf-commodity-item.active:not(.shelf-commodity-all)');
        if (activeItems.length === 0) {
          if (allItem) allItem.classList.add('active');
          syncCommodityToMain('all');
        } else {
          var selected = Array.from(activeItems).map(function(i) { return i.getAttribute('data-commodity'); });
          syncCommodityToMain(selected);
        }
      }

      // Update active dot
      var dot = document.getElementById('commodityActiveDot');
      var hasFilter = !list.querySelector('[data-commodity="all"]').classList.contains('active');
      if (dot) dot.classList.toggle('visible', hasFilter);
    });
  }

  function syncCommodityToMain(value) {
    // Try clicking main category filter buttons
    if (value === 'all') {
      var allBtn = document.querySelector('#categoryFilters [data-cat="all"]');
      if (allBtn) allBtn.click();
      return;
    }

    // For array of categories, click each one
    if (Array.isArray(value)) {
      // First click "all" to reset
      var allBtn = document.querySelector('#categoryFilters [data-cat="all"]');
      if (allBtn) allBtn.click();

      // Then click each selected category
      value.forEach(function(cat) {
        var btn = document.querySelector('#categoryFilters [data-cat="' + cat + '"]');
        if (btn) btn.click();
      });
    }
  }

  // ═══ COLOR FILTER ═══
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

    // Sort by frequency
    var sorted = Object.keys(colors).sort(function(a, b) { return colors[b] - colors[a]; });

    sorted.forEach(function(color) {
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

      // Sync to main color filter
      if (typeof colorFilter !== 'undefined') {
        colorFilter = val || null;
      }

      // Try clicking the main color filter button/dropdown
      var mainBtn = document.getElementById('colorFilterBtn');
      if (mainBtn) {
        // The main UI uses a dropdown menu - we need to set the value directly
        if (typeof window.colorFilter !== 'undefined') {
          window.colorFilter = val || null;
        }
        if (typeof renderProducts === 'function') renderProducts();
      }

      // Update active dot
      var dot = document.getElementById('colorActiveDot');
      if (dot) dot.classList.toggle('visible', !!val);
    });
  }

  // ═══ CUSTOMER FILTER ═══
  function populateCustomerDropdown() {
    var dropdown = document.getElementById('shelfCustomerDropdown');
    if (!dropdown) return;

    // Try to get customers from existing filter
    var mainCustomerBtn = document.querySelector('[id*="customerFilter"], [onclick*="customerFilter"]');
    // Customers come from sales data, may not be in allProducts
    // Try fetching from API
    fetch('/api/sales-data/customers')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data && Array.isArray(data)) {
          data.forEach(function(customer) {
            var opt = document.createElement('option');
            opt.value = customer;
            opt.textContent = customer;
            dropdown.appendChild(opt);
          });
        }
      })
      .catch(function() {
        // API not available - hide section
      });
  }

  function wireCustomerFilter() {
    var dropdown = document.getElementById('shelfCustomerDropdown');
    if (!dropdown) return;

    dropdown.addEventListener('change', function() {
      var val = dropdown.value;

      // Try triggering main customer filter
      var mainBtn = document.querySelector('[id*="customerFilter"]');
      if (mainBtn) mainBtn.click();

      // Also try setting directly
      if (typeof window.customerFilter !== 'undefined') {
        window.customerFilter = val || null;
        if (typeof renderProducts === 'function') renderProducts();
      }

      var dot = document.getElementById('customerActiveDot');
      if (dot) dot.classList.toggle('visible', !!val);
    });
  }

  // ═══ SUPPLIER FILTER ═══
  function populateSupplierDropdown() {
    var dropdown = document.getElementById('shelfSupplierDropdown');
    if (!dropdown) return;

    var suppliers = {};
    allProducts.forEach(function(p) {
      if (p.supplier) suppliers[p.supplier] = true;
    });

    Object.keys(suppliers).sort().forEach(function(s) {
      var opt = document.createElement('option');
      opt.value = s;
      opt.textContent = s;
      dropdown.appendChild(opt);
    });
  }

  function wireSupplierFilter() {
    var dropdown = document.getElementById('shelfSupplierDropdown');
    if (!dropdown) return;

    dropdown.addEventListener('change', function() {
      var val = dropdown.value;

      // Try the main supplier filter
      var mainSelect = document.querySelector('select[id*="supplier"], [data-filter="supplier"]');
      if (mainSelect) {
        mainSelect.value = val;
        mainSelect.dispatchEvent(new Event('change', { bubbles: true }));
      }

      // Also try setting directly
      if (typeof window.supplierFilter !== 'undefined') {
        window.supplierFilter = val || null;
        if (typeof renderProducts === 'function') renderProducts();
      }

      var dot = document.getElementById('supplierActiveDot');
      if (dot) dot.classList.toggle('visible', !!val);
    });
  }

  // ═══ QTY RANGE ═══
  function wireQtyRange() {
    var shelfMin = document.getElementById('shelfMinQty');
    var shelfMax = document.getElementById('shelfMaxQty');
    var shelfReset = document.getElementById('shelfQtyReset');
    var mainMin = document.getElementById('minQty');
    var mainMax = document.getElementById('maxQty');

    if (!shelfMin || !shelfMax) return;

    function syncQtyToMain() {
      if (mainMin) {
        mainMin.value = shelfMin.value;
        mainMin.dispatchEvent(new Event('input', { bubbles: true }));
      }
      if (mainMax) {
        mainMax.value = shelfMax.value;
        mainMax.dispatchEvent(new Event('input', { bubbles: true }));
      }
      // Trigger the filter
      if (typeof renderProducts === 'function') renderProducts();
    }

    shelfMin.addEventListener('change', syncQtyToMain);
    shelfMax.addEventListener('change', syncQtyToMain);

    shelfMin.addEventListener('keydown', function(e) { if (e.key === 'Enter') syncQtyToMain(); });
    shelfMax.addEventListener('keydown', function(e) { if (e.key === 'Enter') syncQtyToMain(); });

    if (shelfReset) {
      shelfReset.addEventListener('click', function() {
        shelfMin.value = '';
        shelfMax.value = '';
        if (mainMin) mainMin.value = '';
        if (mainMax) mainMax.value = '';
        // Click main reset button
        var mainReset = document.querySelector('[onclick*="resetQty"], .qty-reset-btn');
        if (mainReset) {
          mainReset.click();
        } else {
          if (typeof renderProducts === 'function') renderProducts();
        }
      });
    }

    // Sync from main
    if (mainMin) {
      mainMin.addEventListener('input', function() { shelfMin.value = mainMin.value; });
    }
    if (mainMax) {
      mainMax.addEventListener('input', function() { shelfMax.value = mainMax.value; });
    }
  }

  // ═══ COLLAPSIBLE SECTIONS ═══
  function wireSectionToggles() {
    document.querySelectorAll('.shelf-section-header[data-section]').forEach(function(header) {
      header.addEventListener('click', function() {
        var section = header.getAttribute('data-section');
        var body = document.querySelector('[data-section-body="' + section + '"]');
        if (!body) return;

        var isCollapsed = body.classList.contains('collapsed');
        body.classList.toggle('collapsed');
        header.classList.toggle('collapsed');
      });
    });
  }

  // ═══ SHELF STATE OBSERVER ═══
  function observeShelfState(shelf) {
    // Watch for shelf open/close to toggle body class
    var observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(m) {
        if (m.type === 'attributes' && m.attributeName === 'class') {
          var isOpen = shelf.classList.contains('open');
          document.body.classList.toggle('shelf-open', isOpen);
        }
      });
    });

    observer.observe(shelf, { attributes: true });

    // Set initial state
    document.body.classList.toggle('shelf-open', shelf.classList.contains('open'));
  }

})();
