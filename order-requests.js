// ==========================================
// ORDER REQUESTS - Frontend Module (Per-Style PO)
// ==========================================
// Each base style gets its own Import PO dropdown + size grid
// Shared fields (account, buyer, CXL, price, tickets, repack, labels, notes) apply to whole order

(function() {
    var orderMode = false;
    var orderSelectedProducts = [];

    // ---- Order Selection Mode ----
    window.toggleOrderMode = function() {
        orderMode = !orderMode;
        var btn = document.getElementById('orderModeBtn');
        if (orderMode) {
            btn.textContent = '\u2715 Exit Order Mode';
            btn.classList.add('active');
            updateOrderBar();
        } else {
            btn.textContent = '\ud83d\udccb Create Order';
            btn.classList.remove('active');
            orderSelectedProducts = [];
            updateOrderBar();
        }
        renderProducts();
    };

    window.isOrderMode = function() { return orderMode; };
    window.getOrderSelectedProducts = function() { return orderSelectedProducts; };

    window.handleOrderCardClick = function(id) {
        if (!orderMode) return false;
        var idx = orderSelectedProducts.indexOf(id);
        if (idx === -1) { orderSelectedProducts.push(id); }
        else { orderSelectedProducts.splice(idx, 1); }
        updateOrderBar();
        renderProducts();
        return true;
    };

    window.handleOrderGroupClick = function(baseStyle) {
        if (!orderMode) return false;
        var variants = allProducts.filter(function(p) { return p.style_id.split('-')[0] === baseStyle; });
        var variantIds = variants.map(function(v) { return v.id; });
        var allSelected = variantIds.every(function(id) { return orderSelectedProducts.indexOf(id) !== -1; });
        if (allSelected) {
            variantIds.forEach(function(id) {
                var idx = orderSelectedProducts.indexOf(id);
                if (idx !== -1) orderSelectedProducts.splice(idx, 1);
            });
        } else {
            variantIds.forEach(function(id) {
                if (orderSelectedProducts.indexOf(id) === -1) orderSelectedProducts.push(id);
            });
        }
        updateOrderBar();
        renderProducts();
        return true;
    };

    window.isOrderSelected = function(id) { return orderSelectedProducts.indexOf(id) !== -1; };
    window.isOrderGroupSelected = function(baseStyle) {
        var variants = allProducts.filter(function(p) { return p.style_id.split('-')[0] === baseStyle; });
        return variants.length > 0 && variants.every(function(v) { return orderSelectedProducts.indexOf(v.id) !== -1; });
    };

    window.removeFromOrder = function(id) {
        var idx = orderSelectedProducts.indexOf(id);
        if (idx !== -1) {
            orderSelectedProducts.splice(idx, 1);
            updateOrderBar();
            renderProducts();
            showOrderReview();
        }
    };

    function updateOrderBar() {
        var bar = document.getElementById('orderBar');
        var count = document.getElementById('orderSelectedCount');
        if (!bar || !count) return;
        count.textContent = orderSelectedProducts.length;
        if (orderSelectedProducts.length > 0 && orderMode) {
            bar.classList.add('visible');
        } else {
            bar.classList.remove('visible');
        }
    }

    window.clearOrderSelection = function() {
        orderSelectedProducts = [];
        updateOrderBar();
        renderProducts();
    };

    // ---- Helpers ----
    function radioGroup(name, label) {
        var h = '<div class="or-radio-row">';
        h += '<span class="or-radio-label">' + label + '</span>';
        h += '<label class="or-radio"><input type="radio" name="' + name + '" value="yes"><span>Yes</span></label>';
        h += '<label class="or-radio"><input type="radio" name="' + name + '" value="no"><span>No</span></label>';
        h += '<label class="or-radio"><input type="radio" name="' + name + '" value="na"><span>N/A</span></label>';
        h += '</div>';
        return h;
    }

    function getRadioVal(name) {
        var el = document.querySelector('input[name="' + name + '"]:checked');
        return el ? el.value : '';
    }

    // ---- Per-style PO data store ----
    var poDataByStyle = {};

    // ---- Order Review Screen ----
    window.showOrderReview = function() {
        var overlay = document.getElementById('orderReviewOverlay');
        var content = document.getElementById('orderReviewContent');
        if (!overlay || !content) return;

        // Group products by base style
        var styles = {};
        var totalQty = 0;
        var allStyleIds = [];
        orderSelectedProducts.forEach(function(id) {
            var pr = allProducts.find(function(p) { return p.id === id; });
            if (!pr) return;
            var baseStyle = pr.style_id.split('-')[0];
            if (!styles[baseStyle]) {
                styles[baseStyle] = { name: pr.name, variants: [], image: pr.image_url, baseStyle: baseStyle };
            }
            if (allStyleIds.indexOf(pr.style_id) === -1) allStyleIds.push(pr.style_id);
            var qty = 0;
            (pr.colors || []).forEach(function(c) {
                qty += (qtyMode === 'left_to_sell' ? (c.left_to_sell || 0) : (c.available_now || c.available_qty || 0));
            });
            totalQty += qty;
            styles[baseStyle].variants.push({
                id: pr.id, style_id: pr.style_id, name: pr.name, qty: qty,
                colors: (pr.colors || []).map(function(c) { return c.color_name; }).join(', '),
                image: pr.image_url
            });
        });

        var styleKeys = Object.keys(styles);

        // ===== Build HTML =====
        var h = '';
        h += '<div class="or-review-header">';
        h += '<h2>Stock Order Request</h2>';
        h += '<p>' + styleKeys.length + ' style' + (styleKeys.length !== 1 ? 's' : '') + ' \u2022 ' + orderSelectedProducts.length + ' SKU' + (orderSelectedProducts.length !== 1 ? 's' : '') + ' \u2022 ' + totalQty.toLocaleString() + ' total units</p>';
        h += '</div>';

        // ===== SHARED FIELDS - COMPACT 2-COLUMN LAYOUT =====
        h += '<div class="or-form-section">';
        h += '<h3>Order Information</h3>';
        h += '<p style="font-size:0.8rem;color:#999;margin:-0.5rem 0 0.75rem">These fields apply to the entire order.</p>';

        // Top rows: Account + Buyer, then Customer PO + CXL Date
        h += '<div style="display:grid;grid-template-columns:1.5fr 1fr;gap:0.75rem">';
        h += '<div class="or-field"><label>Account Name *</label>';
        h += '<select id="orCustomerSelect" style="min-width:0"><option value="">Select customer...</option></select></div>';
        h += '<div class="or-field"><label>Buyer Name</label>';
        h += '<input type="text" id="orBuyerName" placeholder="Buyer name"></div>';
        h += '</div>';
        h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem">';
        h += '<div class="or-field"><label>Customer PO #</label>';
        h += '<input type="text" id="orCustomerPO" placeholder="Customer PO"></div>';
        h += '<div class="or-field"><label>CXL Date *</label>';
        h += '<input type="date" id="orCxlDate"></div>';
        h += '</div>';

        // Radio grids in 3 columns side by side
        h += '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:0.75rem;margin-top:0.5rem">';

        // Price Tickets column
        h += '<div>';
        h += '<div class="or-section-header">Price Tickets *</div>';
        h += '<div class="or-radio-grid">';
        h += '<div class="or-radio-grid-header"><span></span><span>Y</span><span>N</span><span>N/A</span></div>';
        h += radioGroup('pt_has_tickets', 'Has Price Tickets');
        h += radioGroup('pt_keep_tickets', 'Keep tickets');
        h += radioGroup('pt_remove_tickets', 'Just remove tickets');
        h += radioGroup('pt_new_tickets', 'New Tickets Required');
        h += radioGroup('pt_changes_in_price', 'Changes in cust. price?');
        h += '</div></div>';

        // Re-Packaging column
        h += '<div>';
        h += '<div class="or-section-header">Re-Packaging *</div>';
        h += '<div class="or-radio-grid">';
        h += '<div class="or-radio-grid-header"><span></span><span>Y</span><span>N</span><span>N/A</span></div>';
        h += radioGroup('rp_required', 'Re-packaging required?');
        h += radioGroup('rp_changes_in_price', 'Changes in cust. price?');
        h += '</div></div>';

        // Label Marketing column
        h += '<div>';
        h += '<div class="or-section-header">Label Marketing *</div>';
        h += '<div class="or-radio-grid">';
        h += '<div class="or-radio-grid-header"><span></span><span>Y</span><span>N</span><span>N/A</span></div>';
        h += radioGroup('lm_keep_existing', 'Keep existing labels');
        h += radioGroup('lm_new_required', 'New labels (replace)');
        h += radioGroup('lm_changes_in_price', 'Changes in cust. price?');
        h += '</div></div>';

        h += '</div>'; // end 3-col radio grid

        // Notes - compact
        h += '<div class="or-field" style="margin-top:0.75rem"><label>Additional Notes / Instructions</label>';
        h += '<textarea id="orNotes" rows="2" placeholder="Any additional instructions, ship dates, special requirements..."></textarea></div>';
        h += '</div>';

        // ===== PER-STYLE SECTIONS =====
        h += '<div class="or-form-section" style="margin-top:1rem">';
        h += '<h3>Import PO & Size Breakdown by Style</h3>';

        // 2-column grid for style cards
        h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem">';

        styleKeys.forEach(function(bs) {
            var s = styles[bs];
            var imgUrl = typeof getImageUrl === 'function' ? getImageUrl(s.image) : s.image;
            var variantCount = s.variants.length;

            h += '<div class="or-style-card" data-base-style="' + bs + '">';

            // Compact header: image + name + PO badge
            h += '<div class="or-style-card-header" onclick="toggleStyleCard(\'' + bs + '\')" style="padding:0.5rem 0.75rem">';
            h += '<div style="display:flex;align-items:center;gap:0.5rem;flex:1;min-width:0">';
            h += '<img src="' + (imgUrl || '') + '" onerror="this.style.display=\'none\'" style="width:36px;height:36px;object-fit:contain;border-radius:6px;background:#f8f9fa;flex-shrink:0">';
            h += '<div style="min-width:0;overflow:hidden">';
            h += '<div style="font-weight:700;color:#1e3a5f;font-size:0.85rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + bs + ' \u2014 ' + s.name + '</div>';
            h += '<div style="font-size:0.7rem;color:#666">' + variantCount + ' color' + (variantCount !== 1 ? 's' : '') + '</div>';
            h += '</div></div>';
            h += '<div style="display:flex;align-items:center;gap:0.4rem">';
            h += '<span class="or-style-po-badge" id="poLabel_' + bs + '" style="font-size:0.68rem">No PO</span>';
            h += '<span class="or-style-toggle" id="toggle_' + bs + '" style="font-size:0.7rem">\u25BC</span>';
            h += '</div></div>';

            // Card body
            h += '<div class="or-style-card-body" id="styleBody_' + bs + '" style="padding:0.6rem 0.75rem">';

            // PO + Price inline
            h += '<div style="display:flex;gap:0.5rem;align-items:end;margin-bottom:0.4rem">';
            h += '<div style="flex:1;position:relative">';
            h += '<label style="font-size:0.7rem;font-weight:600;color:#666;display:block;margin-bottom:0.2rem">Import PO *</label>';
            h += '<div style="display:flex;gap:0.4rem;align-items:center">';
            h += '<input type="text" id="orStylePO_' + bs + '" placeholder="Select PO..." autocomplete="off" style="flex:1;padding:0.4rem 0.6rem;font-size:0.82rem;border:1.5px solid #e0e0e0;border-radius:8px" oninput="filterStylePODropdown(\'' + bs + '\', this.value)" onfocus="showStylePODropdown(\'' + bs + '\')">';
            h += '<a id="orStylePOLink_' + bs + '" href="#" target="_blank" style="display:none;font-size:0.68rem;white-space:nowrap;color:#0088c2;text-decoration:none;font-weight:600;padding:0.3rem 0.5rem;border:1px solid #0088c2;border-radius:4px;background:#f0f8ff">Zoho\u2197</a>';
            h += '</div>';
            h += '<div class="or-style-po-dropdown" id="poDropdown_' + bs + '"></div>';
            h += '</div>';
            h += '<div style="width:85px">';
            h += '<label style="font-size:0.7rem;font-weight:600;color:#666;display:block;margin-bottom:0.2rem">Price *</label>';
            h += '<input type="number" id="orStylePrice_' + bs + '" step="0.01" value="0.00" min="0" style="width:100%;padding:0.4rem 0.5rem;font-size:0.82rem;text-align:right;border:1.5px solid #e0e0e0;border-radius:8px;box-sizing:border-box">';
            h += '</div>';
            h += '</div>';

            // Size grid container
            h += '<div id="orStyleSizeGrid_' + bs + '" class="or-style-size-grid"></div>';

            h += '</div></div>';
        });

        h += '</div>'; // end 2-col grid
        h += '</div>';

        // Actions
        h += '<div class="or-review-actions">';
        h += '<button class="btn btn-secondary" onclick="closeOrderReview()">Back to Selection</button>';
        h += '<button class="btn btn-primary" id="orSubmitOrderBtn" onclick="submitOrder()" style="background:#34a853;border-color:#34a853">Submit Stock Order Request</button>';
        h += '</div>';

        content.innerHTML = h;
        overlay.classList.add('active');

        // Load shared data
        loadOrderCustomers();

        // Load POs per style
        poDataByStyle = {};
        styleKeys.forEach(function(bs) { loadStyleImportPOs(bs, styles[bs]); });

        // Close dropdowns on outside click
        document.addEventListener('click', function(e) {
            styleKeys.forEach(function(bs) {
                var dd = document.getElementById('poDropdown_' + bs);
                var input = document.getElementById('orStylePO_' + bs);
                if (dd && e.target !== input && !dd.contains(e.target)) dd.style.display = 'none';
            });
        });
    };

    // ---- Style card toggle ----
    window.toggleStyleCard = function(bs) {
        var body = document.getElementById('styleBody_' + bs);
        var toggle = document.getElementById('toggle_' + bs);
        if (!body) return;
        if (body.style.display === 'none') { body.style.display = ''; if (toggle) toggle.textContent = '\u25BC'; }
        else { body.style.display = 'none'; if (toggle) toggle.textContent = '\u25B6'; }
    };

    // ---- Load Import POs for a specific base style ----
    function loadStyleImportPOs(bs, styleData) {
        var input = document.getElementById('orStylePO_' + bs);
        if (!input) return;
        var styleIds = styleData.variants.map(function(v) { return v.style_id; });

        fetch('/api/import-pos-for-styles?styles=' + encodeURIComponent(styleIds.join(',')))
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (!d.success || !d.importPOs || d.importPOs.length === 0) {
                    input.placeholder = 'No import POs found \u2014 type manually';
                    poDataByStyle[bs] = { importPOs: [], selectedPO: '' };
                    return;
                }
                input.placeholder = 'Click to select Import PO...';
                poDataByStyle[bs] = { importPOs: d.importPOs, selectedPO: '' };
                renderStylePODropdown(bs, '');
            })
            .catch(function(e) {
                console.error('Error loading POs for ' + bs + ':', e);
                input.placeholder = 'Type Import PO # manually';
                poDataByStyle[bs] = { importPOs: [], selectedPO: '' };
            });
    }

    function renderStylePODropdown(bs, filter) {
        var dd = document.getElementById('poDropdown_' + bs);
        if (!dd || !poDataByStyle[bs]) return;
        var f = (filter || '').toLowerCase();
        var all = poDataByStyle[bs].importPOs || [];
        var filtered = all.filter(function(po) {
            return !f || po.document_number.toLowerCase().indexOf(f) !== -1 || (po.customer_vendor || '').toLowerCase().indexOf(f) !== -1;
        });
        if (filtered.length === 0) {
            dd.innerHTML = '<div style="padding:0.75rem;color:#999;font-size:0.8rem">No matching POs</div>';
            dd.style.display = 'block'; return;
        }
        var h = '';
        filtered.forEach(function(po) {
            var dateStr = po.doc_date ? new Date(po.doc_date).toLocaleDateString() : '';
            h += '<div class="po-dd-item" data-po="' + po.document_number + '" data-bs="' + bs + '" style="padding:0.5rem 0.75rem;cursor:pointer;border-bottom:1px solid #f0f0f0">';
            h += '<div style="display:flex;justify-content:space-between;align-items:center">';
            h += '<span style="font-weight:700;color:#1e3a5f;font-size:0.88rem">' + po.document_number + '</span>';
            h += '<span style="font-size:0.72rem;color:#999">' + (po.status || '') + '</span>';
            h += '</div>';
            if (po.customer_vendor) h += '<div style="font-size:0.74rem;color:#666;margin-top:0.1rem">' + po.customer_vendor + (dateStr ? ' \u2014 ' + dateStr : '') + '</div>';
            if (po.size_ratio) h += '<div style="font-size:0.72rem;color:#0088c2;margin-top:0.15rem;font-weight:500">Sizes: ' + po.size_ratio + '</div>';
            if (po.total_units) h += '<div style="font-size:0.7rem;color:#999;margin-top:0.1rem">' + parseInt(po.total_units).toLocaleString() + ' total units</div>';
            h += '</div>';
        });
        dd.innerHTML = h;
        dd.style.display = 'block';
        dd.querySelectorAll('.po-dd-item').forEach(function(el) {
            el.addEventListener('click', function() { selectStylePO(this.dataset.bs, this.dataset.po); });
        });
    }

    window.showStylePODropdown = function(bs) {
        var input = document.getElementById('orStylePO_' + bs);
        renderStylePODropdown(bs, input ? input.value : '');
    };
    window.filterStylePODropdown = function(bs, val) { renderStylePODropdown(bs, val); };

    window.selectStylePO = function(bs, poNum) {
        var input = document.getElementById('orStylePO_' + bs);
        if (input) input.value = poNum;
        var dd = document.getElementById('poDropdown_' + bs);
        if (dd) dd.style.display = 'none';
        var badge = document.getElementById('poLabel_' + bs);
        if (badge) { badge.textContent = 'PO ' + poNum; badge.className = 'or-style-po-badge selected'; }
        if (poDataByStyle[bs]) poDataByStyle[bs].selectedPO = poNum;
        updateStylePOZohoLink(bs, poNum);
        if (typeof loadStyleSizeGrid === 'function') loadStyleSizeGrid(bs, poNum);
    };

    function updateStylePOZohoLink(bs, poNum) {
        var link = document.getElementById('orStylePOLink_' + bs);
        if (!link) return;
        if (!poNum || poNum.length < 3) { link.style.display = 'none'; return; }
        link.style.display = ''; link.textContent = 'Looking up...'; link.href = '#';
        fetch('/api/zoho-link/purchaseorder/' + encodeURIComponent(poNum))
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.success && d.url) { link.href = d.url; link.style.display = ''; link.textContent = 'View PO in Zoho \u2197'; }
                else { link.style.display = 'none'; }
            }).catch(function() { link.style.display = 'none'; });
    }

    // ---- Customer dropdown ----
    var orderCustomersLoaded = false;
    var orderCustomerList = [];

    function loadOrderCustomers() {
        if (orderCustomersLoaded && orderCustomerList.length > 0) { populateCustomerDropdown(); return; }
        fetch('/api/customers').then(function(r) { return r.json(); }).then(function(d) {
            if (d.success) { orderCustomerList = d.customers.map(function(c) { return c.name; }); orderCustomersLoaded = true; populateCustomerDropdown(); }
        }).catch(function(e) { console.error('Error loading customers:', e); });
    }

    function populateCustomerDropdown() {
        var sel = document.getElementById('orCustomerSelect');
        if (!sel) return;
        var current = sel.value;
        sel.innerHTML = '<option value="">Select a customer...</option>';
        orderCustomerList.forEach(function(name) {
            var opt = document.createElement('option'); opt.value = name; opt.textContent = name; sel.appendChild(opt);
        });
        var otherOpt = document.createElement('option'); otherOpt.value = '__OTHER__'; otherOpt.textContent = '-- OTHER (type below) --'; sel.appendChild(otherOpt);
        if (current) sel.value = current;
        sel.addEventListener('change', function() {
            var otherInput = document.getElementById('orCustomerOther');
            if (sel.value === '__OTHER__') {
                if (!otherInput) {
                    var inp = document.createElement('input'); inp.type = 'text'; inp.id = 'orCustomerOther';
                    inp.placeholder = 'Enter account name...'; inp.style.marginTop = '0.5rem';
                    sel.parentNode.appendChild(inp); inp.focus();
                }
            } else if (otherInput) { otherInput.remove(); }
        });
    }

    window.closeOrderReview = function() {
        var overlay = document.getElementById('orderReviewOverlay');
        if (overlay) overlay.classList.remove('active');
    };

    // ---- Submit Order ----
    window.submitOrder = function() {
        var customerSel = document.getElementById('orCustomerSelect');
        var customer = customerSel.value;
        if (customer === '__OTHER__') {
            var otherInput = document.getElementById('orCustomerOther');
            customer = otherInput ? otherInput.value.trim() : '';
        }
        if (!customer) { alert('Please select or enter a customer/account name'); return; }
        if (orderSelectedProducts.length === 0) { alert('No products selected'); return; }

        var cxlDate = (document.getElementById('orCxlDate') || {}).value || null;
        var stylePoSelections = {};
        var allImportPOs = [];
        var allPrices = [];

        Object.keys(poDataByStyle).forEach(function(bs) {
            var input = document.getElementById('orStylePO_' + bs);
            var priceInput = document.getElementById('orStylePrice_' + bs);
            var poVal = input ? input.value.trim() : '';
            var priceVal = priceInput ? parseFloat(priceInput.value) || 0 : 0;
            stylePoSelections[bs] = { import_po: poVal, customer_price: priceVal };
            if (poVal && allImportPOs.indexOf(poVal) === -1) allImportPOs.push(poVal);
            if (priceVal > 0) allPrices.push(priceVal);
            if (typeof getStyleSizeGridData === 'function') {
                var gridData = getStyleSizeGridData(bs);
                if (gridData) stylePoSelections[bs].size_grid = gridData;
            }
        });

        var formData = {
            customer_name: customer,
            product_ids: orderSelectedProducts,
            buyer_name: (document.getElementById('orBuyerName') || {}).value || '',
            import_po_numbers: allImportPOs.join(', '),
            customer_po_number: (document.getElementById('orCustomerPO') || {}).value || '',
            customer_price: allPrices.length > 0 ? allPrices[0] : 0,
            cxl_date: cxlDate, cancel_date: cxlDate,
            unit_color_breakdown: '',
            notes: (document.getElementById('orNotes') || {}).value || '',
            price_tickets: { has_tickets: getRadioVal('pt_has_tickets'), keep_tickets: getRadioVal('pt_keep_tickets'), remove_tickets: getRadioVal('pt_remove_tickets'), new_tickets: getRadioVal('pt_new_tickets'), changes_in_price: getRadioVal('pt_changes_in_price') },
            repackaging: { required: getRadioVal('rp_required'), changes_in_price: getRadioVal('rp_changes_in_price') },
            label_marketing: { keep_existing: getRadioVal('lm_keep_existing'), new_required: getRadioVal('lm_new_required'), changes_in_price: getRadioVal('lm_changes_in_price') },
            style_po_selections: stylePoSelections
        };

        // Build aggregated size_grid_data and unit_color_breakdown text from all styles
        var allGridData = { styles: {} };
        var breakdownLines = [];
        Object.keys(stylePoSelections).forEach(function(bs) {
            if (stylePoSelections[bs].size_grid) {
                allGridData.styles[bs] = stylePoSelections[bs].size_grid;
                stylePoSelections[bs].size_grid.rows.forEach(function(row) {
                    if (row.total > 0) {
                        var sizeParts = [];
                        Object.keys(row.sizes).forEach(function(s) { if (row.sizes[s] > 0) sizeParts.push(s + ':' + row.sizes[s]); });
                        breakdownLines.push(row.style_id + ' ' + row.color + ' = ' + row.total + (sizeParts.length > 0 ? ' (' + sizeParts.join(', ') + ')' : ''));
                    }
                });
            }
        });
        if (Object.keys(allGridData.styles).length > 0) formData.size_grid_data = allGridData;
        if (breakdownLines.length > 0) formData.unit_color_breakdown = breakdownLines.join('\n');

        var btn = document.getElementById('orSubmitOrderBtn');
        btn.disabled = true; btn.textContent = 'Submitting...';

        fetch('/api/order-requests', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        }).then(function(r) { return r.json(); }).then(function(d) {
            btn.disabled = false; btn.textContent = 'Submit Stock Order Request';
            if (d.success) showOrderSuccess(d.order);
            else alert('Error: ' + (d.error || 'Unknown error'));
        }).catch(function(e) {
            btn.disabled = false; btn.textContent = 'Submit Stock Order Request';
            alert('Error: ' + e.message);
        });
    };

    function showOrderSuccess(order) {
        var content = document.getElementById('orderReviewContent');
        if (!content) return;
        var detailFullUrl = (order.app_url || window.location.origin) + order.detail_url;
        var subject = 'Stock Order Request ' + order.request_number + ' - ' + order.customer_name;
        var body = 'New Stock Order Request: ' + order.request_number + '\n\nAccount: ' + order.customer_name + '\n';
        if (order.buyer_name) body += 'Buyer: ' + order.buyer_name + '\n';
        body += 'Products: ' + (order.product_count || 'N/A') + ' items\n';
        if (order.import_po_numbers) body += 'Import PO(s): ' + order.import_po_numbers + '\n';
        if (order.customer_po_number) body += 'Customer PO: ' + order.customer_po_number + '\n';
        if (order.customer_price > 0) body += 'Customer Price: $' + parseFloat(order.customer_price).toFixed(2) + '\n';
        if (order.cxl_date) body += 'CXL Date: ' + order.cxl_date + '\n';
        body += 'Submitted by: ' + (order.user_name || 'Unknown') + '\n';
        if (order.notes) body += '\nNotes:\n' + order.notes + '\n';
        body += '\nView full order details:\n' + detailFullUrl + '\n';
        var toEmail = order.notify_email || '';
        var mailtoUrl = 'mailto:' + encodeURIComponent(toEmail) + '?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body);

        var h = '<div class="or-success"><div class="or-success-icon">\u2705</div>';
        h += '<h2>Stock Order Request Saved!</h2>';
        h += '<div class="or-success-number">' + order.request_number + '</div>';
        h += '<p style="color:#666;margin:0.5rem 0 1.5rem">Your order request has been saved and the order entry team has been notified.</p>';
        h += '<div style="display:flex;flex-direction:column;gap:0.75rem;align-items:center">';
        h += '<a href="' + mailtoUrl + '" class="btn btn-primary" style="background:#0088c2;border-color:#0088c2;text-decoration:none;padding:0.75rem 2rem;font-size:1rem;display:inline-block">\ud83d\udce7 Email Order Details</a>';
        h += '<a href="' + detailFullUrl + '" target="_blank" class="or-detail-link">View Order Details \u2192</a>';
        h += '</div><button class="btn btn-secondary" onclick="finishOrder()" style="margin-top:1.5rem">Done</button></div>';
        content.innerHTML = h;
    }

    window.finishOrder = function() {
        orderMode = false; orderSelectedProducts = [];
        var btn = document.getElementById('orderModeBtn');
        if (btn) { btn.textContent = '\ud83d\udccb Create Order'; btn.classList.remove('active'); }
        updateOrderBar(); closeOrderReview(); renderProducts();
    };

    // ---- Orders List ----
    var ordersCustomersLoaded = false;
    window.toggleOrdersList = function() {
        var panel = document.getElementById('ordersListPanel');
        if (!panel) {
            var main = document.querySelector('.main'); if (!main) return;
            var div = document.createElement('div'); div.id = 'ordersListPanel'; div.className = 'orders-list-panel';
            div.innerHTML = '<div class="orders-list-header"><h2>\ud83d\udccb Order Requests</h2><button class="btn btn-secondary btn-sm" onclick="closeOrdersList()">\u2715 Close</button></div><div class="orders-list-filters"><select id="ordersStatusFilter" onchange="loadOrdersList()"><option value="all">All Status</option><option value="pending">Pending</option><option value="processing">Processing</option><option value="completed">Completed</option><option value="cancelled">Cancelled</option></select><select id="ordersCustomerFilter" onchange="loadOrdersList()"><option value="all">All Customers</option></select><span id="ordersResultCount" style="font-size:0.8rem;color:#999;margin-left:0.5rem"></span></div><div id="ordersListContent">Loading...</div>';
            main.insertBefore(div, main.firstChild); loadOrdersCustomerFilter(); loadOrdersList();
        } else { panel.style.display = panel.style.display === 'none' ? '' : 'none'; if (panel.style.display !== 'none') loadOrdersList(); }
    };
    function loadOrdersCustomerFilter() {
        if (ordersCustomersLoaded) return;
        fetch('/api/order-requests/customers').then(function(r) { return r.json(); }).then(function(d) {
            if (d.success && d.customers) {
                var sel = document.getElementById('ordersCustomerFilter'); if (!sel) return;
                d.customers.forEach(function(c) { var opt = document.createElement('option'); opt.value = c; opt.textContent = c; sel.appendChild(opt); });
                ordersCustomersLoaded = true;
            }
        }).catch(function() {});
    }
    window.closeOrdersList = function() { var panel = document.getElementById('ordersListPanel'); if (panel) panel.style.display = 'none'; };
    window.loadOrdersList = function() {
        var statusEl = document.getElementById('ordersStatusFilter'); var customerEl = document.getElementById('ordersCustomerFilter');
        var status = statusEl ? statusEl.value : 'all'; var customer = customerEl ? customerEl.value : 'all';
        var url = '/api/order-requests?status=' + encodeURIComponent(status);
        if (customer !== 'all') url += '&customer=' + encodeURIComponent(customer);
        fetch(url).then(function(r) { return r.json(); }).then(function(d) {
            var container = document.getElementById('ordersListContent'); var countEl = document.getElementById('ordersResultCount');
            if (!container) return;
            if (!d.success || !d.orders || d.orders.length === 0) { container.innerHTML = '<p class="or-empty">No order requests found.</p>'; if (countEl) countEl.textContent = '0 orders'; return; }
            if (countEl) countEl.textContent = d.orders.length + ' order' + (d.orders.length !== 1 ? 's' : '');
            var h = '';
            d.orders.forEach(function(o) {
                var dt = new Date(o.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' });
                h += '<div class="or-list-card"><div class="or-list-card-header"><span class="or-list-num">' + o.request_number + '</span><span class="or-status ' + o.status + '">' + o.status + '</span></div>';
                h += '<div class="or-list-card-body">';
                h += '<div class="or-list-row"><span class="or-list-label">Account</span><span class="or-list-val" style="font-weight:700">' + o.customer_name + '</span></div>';
                if (o.buyer_name) h += '<div class="or-list-row"><span class="or-list-label">Buyer</span><span class="or-list-val">' + o.buyer_name + '</span></div>';
                h += '<div class="or-list-row"><span class="or-list-label">Products</span><span class="or-list-val">' + (o.product_count || 0) + ' items</span></div>';
                if (o.import_po_numbers) h += '<div class="or-list-row"><span class="or-list-label">Import PO(s)</span><span class="or-list-val">' + o.import_po_numbers + '</span></div>';
                if (o.customer_po_number) h += '<div class="or-list-row"><span class="or-list-label">Customer PO</span><span class="or-list-val">' + o.customer_po_number + '</span></div>';
                if (o.customer_price && parseFloat(o.customer_price) > 0) h += '<div class="or-list-row"><span class="or-list-label">Price</span><span class="or-list-val">$' + parseFloat(o.customer_price).toFixed(2) + '</span></div>';
                if (o.cxl_date || o.cancel_date) { var cd = o.cxl_date || o.cancel_date; h += '<div class="or-list-row"><span class="or-list-label">CXL Date</span><span class="or-list-val">' + new Date(cd).toLocaleDateString() + '</span></div>'; }
                h += '<div class="or-list-row"><span class="or-list-label">Submitted</span><span class="or-list-val">' + dt + '</span></div>';
                h += '<div class="or-list-row"><span class="or-list-label">Rep</span><span class="or-list-val">' + (o.user_name || 'Unknown') + '</span></div>';
                if (o.notes) { var tn = o.notes.length > 150 ? o.notes.substring(0, 150) + '...' : o.notes; h += '<div class="or-list-notes">' + tn.replace(/</g, '&lt;').replace(/\n/g, '<br>') + '</div>'; }
                if (o.zoho_so_number) h += '<div class="or-list-so">Zoho SO: ' + o.zoho_so_number + '</div>';
                h += '<div class="or-list-actions">'; if (o.detail_id) h += '<a href="/order/' + o.detail_id + '" target="_blank" class="or-action-link">View Details \u2192</a>'; h += '</div></div>';
                if (o.can_admin && (o.status === 'pending' || o.status === 'processing')) {
                    h += '<div class="or-admin-controls"><input type="text" placeholder="Zoho SO #" id="soInput' + o.id + '" value="' + (o.zoho_so_number || '') + '" class="or-admin-input"><input type="text" placeholder="Admin note" id="noteInput' + o.id + '" value="' + (o.admin_notes || '') + '" class="or-admin-input" style="flex:1">';
                    if (o.status === 'pending') h += '<button class="or-admin-btn processing" onclick="updateOrderStatus(' + o.id + ',\'processing\')">Processing</button>';
                    h += '<button class="or-admin-btn complete" onclick="completeOrderAdmin(' + o.id + ')">Complete</button><button class="or-admin-btn cancel" onclick="updateOrderStatus(' + o.id + ',\'cancelled\')">Cancel</button></div>';
                }
                h += '</div>';
            });
            container.innerHTML = h;
        }).catch(function(e) { console.error('Error loading orders:', e); var c = document.getElementById('ordersListContent'); if (c) c.innerHTML = '<p class="or-empty">Error loading orders.</p>'; });
    };
    window.updateOrderStatus = function(id, status) {
        fetch('/api/order-requests/' + id, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: status }) }).then(function(r) { return r.json(); }).then(function(d) { if (d.success) loadOrdersList(); else alert('Error: ' + d.error); }).catch(function(e) { alert(e.message); });
    };
    window.completeOrderAdmin = function(id) {
        var so = document.getElementById('soInput' + id); var note = document.getElementById('noteInput' + id);
        fetch('/api/order-requests/' + id, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: 'completed', zoho_so_number: (so ? so.value.trim() : '') || null, admin_notes: (note ? note.value.trim() : '') || null }) }).then(function(r) { return r.json(); }).then(function(d) { if (d.success) loadOrdersList(); else alert('Error: ' + d.error); }).catch(function(e) { alert(e.message); });
    };
})();
