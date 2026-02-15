/* ═══════════════════════════════════════════
   ENHANCED SIDEBAR v4
   - Clean commodity/color list (no bars)
   - Delayed customer/supplier population
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
    setTimeout(function() {
      var shelf = document.getElementById('treemapShelf');
      if (shelf && !shelf.classList.contains('open') && typeof openTreemapShelf === 'function') {
        openTreemapShelf();
      }
    }, 200);
    setTimeout(function() {
      document.querySelectorAll('.size-btn').forEach(function(b) {
        if (b.textContent.trim() === 'Small' && !b.classList.contains('active')) b.click();
      });
    }, 500);
    // Delayed population for customer/supplier (main dropdowns load async)
    setTimeout(function() {
      populateCustomerDropdown();
      populateSupplierDropdown();
    }, 2000);
  });

  function loadCSS() {
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

    var titleSpan = inner.querySelector('#treemapTitle');
    if (titleSpan) titleSpan.textContent = 'Filters';

    var closeBtn = document.getElementById('closeTreemapShelf');
    if (closeBtn && typeof closeTreemapShelf === 'function') {
      closeBtn.addEventListener('click', function() { closeTreemapShelf(); });
    }

    var c = document.createElement('div');
    c.id = 'shelfFiltersContainer';
    c.innerHTML = buildHTML();
    inner.appendChild(c);

    wireSearch();
    wireQuickFilters();
    wireCommodityColorToggle();
    wireCommodityClick();
    wireColorDropdown();
    wireCustomerDropdown();
    wireSupplierDropdown();
    wireQtyRange();
    wireSections();
    observeShelf(shelf);

    populateCommodityList();
    populateColorDropdown();
  }

  // ═══ HTML ═══
  function buildHTML() {
    return '' +
    sec('search', '🔍', 'Search',
      '<div class="shelf-search-box">' +
        '<span class="search-icon">🔍</span>' +
        '<input type="text" class="shelf-search-input" id="shelfSearchInput" placeholder="Search styles...">' +
        '<button class="shelf-search-clear" id="shelfSearchClear">&times;</button>' +
      '</div>'
    ) +
    sec('quick', '⚡', 'Quick Filters',
      '<div class="shelf-quick-filters">' +
        '<button class="shelf-quick-btn" data-quick="new_arrivals">New Arrivals <span class="badge" id="shelfBadgeNew">0</span></button>' +
        '<button class="shelf-quick-btn" data-quick="my_picks">My Picks <span class="badge" id="shelfBadgePicks">0</span></button>' +
        '<button class="shelf-quick-btn" data-quick="in_stock">In Stock Now <span class="badge" id="shelfBadgeStock">0</span></button>' +
        '<button class="shelf-quick-btn" data-quick="has_notes">Has Notes <span class="badge" id="shelfBadgeNotes">0</span></button>' +
      '</div>'
    ) +
    sec('commodity', '📦', '<span id="shelfListTitle">Commodity</span>',
      '<div class="shelf-toggle-row">' +
        '<button class="shelf-toggle-btn active" id="shelfShowCommodity">Commodity</button>' +
        '<button class="shelf-toggle-btn" id="shelfShowColor">Color</button>' +
      '</div>' +
      '<div class="shelf-commodity-list" id="shelfCommodityList"></div>'
    ) +
    sec('colorfilter', '🎨', 'Color Filter',
      '<select class="shelf-dropdown" id="shelfColorDropdown"><option value="">All Colors</option></select>'
    ) +
    sec('customer', '👥', 'Customer',
      '<select class="shelf-dropdown" id="shelfCustomerDropdown"><option value="">All Customers</option></select>'
    ) +
    sec('supplier', '🏭', 'Supplier',
      '<select class="shelf-dropdown" id="shelfSupplierDropdown"><option value="">All Suppliers</option></select>'
    ) +
    sec('qty', '📊', 'Qty Range',
      '<div class="shelf-qty-range">' +
        '<input type="number" class="shelf-qty-input" id="shelfMinQty" placeholder="Min">' +
        '<span class="shelf-qty-sep">–</span>' +
        '<input type="number" class="shelf-qty-input" id="shelfMaxQty" placeholder="Max">' +
        '<button class="shelf-qty-reset" id="shelfQtyReset">Reset</button>' +
      '</div>'
    );
  }

  function sec(id, icon, title, body) {
    return '<div class="shelf-filters-section">' +
      '<div class="shelf-section-header" data-section="' + id + '">' +
        '<div class="shelf-section-title"><span class="section-icon">' + icon + '</span> ' + title + '</div>' +
        '<span class="chevron">▼</span>' +
      '</div>' +
      '<div class="shelf-section-body" data-section-body="' + id + '">' + body + '</div>' +
    '</div>';
  }

  // ═══ COMMODITY / COLOR TOGGLE ═══
  var listMode = 'commodity';

  function wireCommodityColorToggle() {
    var btnC = document.getElementById('shelfShowCommodity');
    var btnL = document.getElementById('shelfShowColor');
    if (!btnC || !btnL) return;
    btnC.addEventListener('click', function() {
      listMode = 'commodity';
      btnC.classList.add('active'); btnL.classList.remove('active');
      document.getElementById('shelfListTitle').textContent = 'Commodity';
      populateCommodityList();
    });
    btnL.addEventListener('click', function() {
      listMode = 'color';
      btnL.classList.add('active'); btnC.classList.remove('active');
      document.getElementById('shelfListTitle').textContent = 'Color';
      populateColorAsList();
    });
  }

  // ═══ COMMODITY LIST (clean, no bars) ═══
  function populateCommodityList() {
    var list = document.getElementById('shelfCommodityList');
    if (!list) return;
    var counts = {};
    allProducts.forEach(function(p) {
      var cat = p.category || 'Uncategorized';
      if (!counts[cat]) counts[cat] = 0;
      (p.colors || []).forEach(function(c) {
        counts[cat] += (qtyMode === 'left_to_sell') ? (c.left_to_sell || 0) : (c.available_now || c.available_qty || 0);
      });
    });
    var sorted = Object.keys(counts).sort(function(a, b) { return counts[b] - counts[a]; });
    var h = '<div class="shelf-commodity-item shelf-commodity-all active" data-commodity="all"><span class="commodity-name">All</span><span class="commodity-count">' + sorted.length + ' types</span></div>';
    sorted.forEach(function(cat) {
      var c = counts[cat];
      var d = c >= 1000 ? (c/1000).toFixed(1)+'K' : c.toString();
      h += '<div class="shelf-commodity-item" data-commodity="' + cat + '"><span class="commodity-name">' + cat + '</span><span class="commodity-count">' + d + '</span></div>';
    });
    list.innerHTML = h;
  }

  // ═══ COLOR AS LIST ═══
  function populateColorAsList() {
    var list = document.getElementById('shelfCommodityList');
    if (!list) return;
    var counts = {};
    allProducts.forEach(function(p) {
      (p.colors || []).forEach(function(c) {
        var nm = c.color_name || 'Unknown';
        if (!counts[nm]) counts[nm] = 0;
        counts[nm] += (qtyMode === 'left_to_sell') ? (c.left_to_sell || 0) : (c.available_now || c.available_qty || 0);
      });
    });
    var sorted = Object.keys(counts).sort(function(a, b) { return counts[b] - counts[a]; });
    var top = sorted.slice(0, 30);
    var h = '<div class="shelf-commodity-item shelf-commodity-all active" data-commodity="all" data-type="color"><span class="commodity-name">All Colors</span><span class="commodity-count">' + sorted.length + '</span></div>';
    top.forEach(function(color) {
      var c = counts[color];
      var d = c >= 1000 ? (c/1000).toFixed(1)+'K' : c.toString();
      h += '<div class="shelf-commodity-item" data-commodity="' + color + '" data-type="color"><span class="commodity-name">' + color + '</span><span class="commodity-count">' + d + '</span></div>';
    });
    if (sorted.length > 30) h += '<div style="text-align:center;padding:4px;color:#94a3b8;font-size:0.6875rem">+' + (sorted.length-30) + ' more</div>';
    list.innerHTML = h;
  }

  // ═══ COMMODITY CLICK ═══
  function wireCommodityClick() {
    var list = document.getElementById('shelfCommodityList');
    if (!list) return;
    list.addEventListener('click', function(e) {
      var item = e.target.closest('.shelf-commodity-item');
      if (!item) return;
      var val = item.getAttribute('data-commodity');
      var isColor = item.getAttribute('data-type') === 'color' || listMode === 'color';

      if (val === 'all') {
        list.querySelectorAll('.shelf-commodity-item').forEach(function(i) { i.classList.remove('active'); });
        item.classList.add('active');
        if (isColor) { window.colorFilter = null; if (typeof renderProducts === 'function') renderProducts(); }
        else { var b = document.querySelector('#categoryFilters [data-cat="all"]'); if (b) b.click(); }
      } else {
        var allI = list.querySelector('[data-commodity="all"]');
        if (allI) allI.classList.remove('active');
        list.querySelectorAll('.shelf-commodity-item:not(.shelf-commodity-all)').forEach(function(i) { i.classList.remove('active'); });
        item.classList.add('active');
        if (isColor) { window.colorFilter = val; if (typeof renderProducts === 'function') renderProducts(); }
        else {
          var ab = document.querySelector('#categoryFilters [data-cat="all"]'); if (ab) ab.click();
          var cb = document.querySelector('#categoryFilters [data-cat="' + val + '"]'); if (cb) cb.click();
        }
      }
    });
  }

  // ═══ SEARCH ═══
  function wireSearch() {
    var si = document.getElementById('shelfSearchInput');
    var sc = document.getElementById('shelfSearchClear');
    var mi = document.getElementById('searchInput');
    if (!si) return;
    if (mi && mi.value) { si.value = mi.value; sc.classList.toggle('visible', mi.value.length > 0); }
    si.addEventListener('input', function() {
      sc.classList.toggle('visible', si.value.length > 0);
      if (mi) { mi.value = si.value; mi.dispatchEvent(new Event('input', {bubbles:true})); }
    });
    si.addEventListener('keydown', function(e) { if (e.key === 'Enter' && mi) mi.dispatchEvent(new Event('change', {bubbles:true})); });
    sc.addEventListener('click', function() {
      si.value = ''; sc.classList.remove('visible');
      if (mi) { mi.value = ''; mi.dispatchEvent(new Event('input', {bubbles:true})); }
    });
    if (mi) mi.addEventListener('input', function() { si.value = mi.value; sc.classList.toggle('visible', mi.value.length > 0); });
  }

  // ═══ QUICK FILTERS ═══
  function wireQuickFilters() {
    var btns = document.querySelectorAll('.shelf-quick-btn[data-quick]');
    updateBadges();
    btns.forEach(function(btn) {
      btn.addEventListener('click', function() {
        var f = btn.getAttribute('data-quick');
        var wasActive = btn.classList.contains('active');
        btns.forEach(function(b) { b.classList.remove('active'); });
        if (!wasActive) btn.classList.add('active');
        var mb = document.querySelector('[data-special="' + f + '"]');
        if (mb) mb.click();
        else if (typeof specialFilter !== 'undefined') {
          specialFilter = wasActive ? null : f;
          if (typeof renderProducts === 'function') renderProducts();
        }
      });
    });
  }

  function updateBadges() {
    var n = 0, s = 0;
    allProducts.forEach(function(p) {
      if (p.is_new) n++;
      var hs = false;
      (p.colors||[]).forEach(function(c) { if ((c.available_now||c.available_qty||0) > 0) hs = true; });
      if (hs) s++;
    });
    var e = document.getElementById('shelfBadgeNew'); if (e) e.textContent = n;
    e = document.getElementById('shelfBadgeStock'); if (e) e.textContent = s;
  }

  // ═══ COLOR DROPDOWN ═══
  function populateColorDropdown() {
    var dd = document.getElementById('shelfColorDropdown');
    if (!dd) return;
    var colors = {};
    allProducts.forEach(function(p) {
      (p.colors||[]).forEach(function(c) { if (c.color_name) { if (!colors[c.color_name]) colors[c.color_name] = 0; colors[c.color_name]++; } });
    });
    Object.keys(colors).sort(function(a,b) { return colors[b]-colors[a]; }).forEach(function(color) {
      var o = document.createElement('option'); o.value = color; o.textContent = color + ' (' + colors[color] + ')'; dd.appendChild(o);
    });
  }

  function wireColorDropdown() {
    var dd = document.getElementById('shelfColorDropdown');
    if (!dd) return;
    dd.addEventListener('change', function() {
      window.colorFilter = dd.value || null;
      if (typeof renderProducts === 'function') renderProducts();
    });
  }

  // ═══ CUSTOMER (scrape from main, delayed) ═══
  function populateCustomerDropdown() {
    var dd = document.getElementById('shelfCustomerDropdown');
    if (!dd || dd.options.length > 1) return; // already populated

    var mainBtn = document.getElementById('customerFilterBtn');
    if (!mainBtn) return;
    var parentDiv = mainBtn.parentElement;
    var labels = parentDiv.querySelectorAll('label');

    labels.forEach(function(label) {
      var cb = label.querySelector('input[type="checkbox"]');
      if (!cb) return;
      var text = label.textContent.trim();
      var name = text.replace(/\d+\s*styles?.*$/i, '').trim();
      if (!name || name.length < 2) return;
      var o = document.createElement('option');
      o.value = name;
      o.textContent = name;
      dd.appendChild(o);
    });

    // If still empty, retry in 2 seconds
    if (dd.options.length <= 1) {
      setTimeout(populateCustomerDropdown, 2000);
    }
  }

  function wireCustomerDropdown() {
    var dd = document.getElementById('shelfCustomerDropdown');
    if (!dd) return;
    dd.addEventListener('change', function() {
      var val = dd.value;
      var mainBtn = document.getElementById('customerFilterBtn');
      if (!mainBtn) return;
      var parentDiv = mainBtn.parentElement;

      // Clear existing
      parentDiv.querySelectorAll('input[type="checkbox"]:checked').forEach(function(cb) { cb.click(); });

      if (val) {
        parentDiv.querySelectorAll('label').forEach(function(label) {
          var name = label.textContent.trim().replace(/\d+\s*styles?.*$/i, '').trim();
          if (name === val) {
            var cb = label.querySelector('input[type="checkbox"]');
            if (cb && !cb.checked) cb.click();
          }
        });
        // Find and click Apply
        parentDiv.querySelectorAll('button').forEach(function(b) { if (b.textContent.trim() === 'Apply') b.click(); });
      } else {
        parentDiv.querySelectorAll('button').forEach(function(b) { if (b.textContent.trim() === 'Clear') b.click(); });
      }
    });
  }

  // ═══ SUPPLIER (scrape from main, delayed) ═══
  function populateSupplierDropdown() {
    var dd = document.getElementById('shelfSupplierDropdown');
    if (!dd || dd.options.length > 1) return;

    var mainBtn = document.getElementById('supplierFilterBtn');
    if (!mainBtn) return;
    var parentDiv = mainBtn.parentElement;
    var labels = parentDiv.querySelectorAll('label');

    labels.forEach(function(label) {
      var cb = label.querySelector('input[type="checkbox"]');
      if (!cb) return;
      var text = label.textContent.trim();
      var name = text.replace(/\d+\s*styles?.*$/i, '').trim();
      if (!name || name.length < 2) return;
      var o = document.createElement('option');
      o.value = name;
      o.textContent = name;
      dd.appendChild(o);
    });

    if (dd.options.length <= 1) {
      setTimeout(populateSupplierDropdown, 2000);
    }
  }

  function wireSupplierDropdown() {
    var dd = document.getElementById('shelfSupplierDropdown');
    if (!dd) return;
    dd.addEventListener('change', function() {
      var val = dd.value;
      var mainBtn = document.getElementById('supplierFilterBtn');
      if (!mainBtn) return;
      var parentDiv = mainBtn.parentElement;
      parentDiv.querySelectorAll('input[type="checkbox"]:checked').forEach(function(cb) { cb.click(); });
      if (val) {
        parentDiv.querySelectorAll('label').forEach(function(label) {
          var name = label.textContent.trim().replace(/\d+\s*styles?.*$/i, '').trim();
          if (name === val) {
            var cb = label.querySelector('input[type="checkbox"]');
            if (cb && !cb.checked) cb.click();
          }
        });
        parentDiv.querySelectorAll('button').forEach(function(b) { if (b.textContent.trim() === 'Apply') b.click(); });
      } else {
        parentDiv.querySelectorAll('button').forEach(function(b) { if (b.textContent.trim() === 'Clear') b.click(); });
      }
    });
  }

  // ═══ QTY RANGE ═══
  function wireQtyRange() {
    var sMin = document.getElementById('shelfMinQty'), sMax = document.getElementById('shelfMaxQty');
    var sReset = document.getElementById('shelfQtyReset');
    var mMin = document.getElementById('minQty'), mMax = document.getElementById('maxQty');
    if (!sMin || !sMax) return;
    function sync() {
      if (mMin) { mMin.value = sMin.value; mMin.dispatchEvent(new Event('input', {bubbles:true})); }
      if (mMax) { mMax.value = sMax.value; mMax.dispatchEvent(new Event('input', {bubbles:true})); }
      if (typeof renderProducts === 'function') renderProducts();
    }
    sMin.addEventListener('change', sync); sMax.addEventListener('change', sync);
    sMin.addEventListener('keydown', function(e) { if (e.key==='Enter') sync(); });
    sMax.addEventListener('keydown', function(e) { if (e.key==='Enter') sync(); });
    if (sReset) sReset.addEventListener('click', function() {
      sMin.value=''; sMax.value='';
      if (mMin) mMin.value=''; if (mMax) mMax.value='';
      var b = document.querySelector('[onclick*="resetQty"]');
      if (b) b.click(); else if (typeof renderProducts === 'function') renderProducts();
    });
  }

  // ═══ COLLAPSIBLE SECTIONS ═══
  function wireSections() {
    document.querySelectorAll('.shelf-section-header[data-section]').forEach(function(h) {
      h.addEventListener('click', function() {
        var body = document.querySelector('[data-section-body="' + h.getAttribute('data-section') + '"]');
        if (body) { body.classList.toggle('collapsed'); h.classList.toggle('collapsed'); }
      });
    });
  }

  // ═══ SHELF STATE ═══
  function observeShelf(shelf) {
    var obs = new MutationObserver(function(muts) {
      muts.forEach(function(m) {
        if (m.attributeName === 'class') document.body.classList.toggle('shelf-open', shelf.classList.contains('open'));
      });
    });
    obs.observe(shelf, {attributes: true});
    document.body.classList.toggle('shelf-open', shelf.classList.contains('open'));
  }
})();
