// ==========================================
// ORDER REQUESTS - Frontend Module (Enhanced)
// ==========================================
// Loaded via <script src="/order-requests.js">
// Depends on: allProducts, qtyMode, getImageUrl, userPicks, userNotes (from main app)

(function() {
    // State
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

    // ---- Helper: build radio group for Yes/No/N/A ----
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

    // ---- Order Review Screen (Enhanced Stock Order Request) ----

    window.showOrderReview = function() {
        var overlay = document.getElementById('orderReviewOverlay');
        var content = document.getElementById('orderReviewContent');
        if (!overlay || !content) return;

        // Build product list
        var styles = {};
        var totalQty = 0;
        var allStyleIds = [];
        orderSelectedProducts.forEach(function(id) {
            var pr = allProducts.find(function(p) { return p.id === id; });
            if (!pr) return;
            var baseStyle = pr.style_id.split('-')[0];
            if (!styles[baseStyle]) {
                styles[baseStyle] = { name: pr.name, variants: [], image: pr.image_url };
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

        // Build HTML
        var h = '';
        h += '<div class="or-review-header">';
        h += '<h2>Stock Order Request</h2>';
        h += '<p>' + styleKeys.length + ' style' + (styleKeys.length !== 1 ? 's' : '') + ' \u2022 ' + orderSelectedProducts.length + ' SKU' + (orderSelectedProducts.length !== 1 ? 's' : '') + ' \u2022 ' + totalQty.toLocaleString() + ' total units</p>';
        h += '</div>';

        // Selected products list (collapsible)
        h += '<details class="or-products-details" open>';
        h += '<summary style="cursor:pointer;font-weight:600;margin-bottom:0.5rem;color:#1e3a5f">Selected Products (' + orderSelectedProducts.length + ')</summary>';
        h += '<div class="or-products-list">';
        styleKeys.forEach(function(bs) {
            var s = styles[bs];
            s.variants.forEach(function(v) {
                var imgUrl = typeof getImageUrl === 'function' ? getImageUrl(v.image) : v.image;
                h += '<div class="or-product-row">';
                h += '<img src="' + (imgUrl || '') + '" onerror="this.style.display=\'none\'" class="or-product-thumb">';
                h += '<div class="or-product-info">';
                h += '<div class="or-product-style">' + v.style_id + '</div>';
                h += '<div class="or-product-name">' + v.name + '</div>';
                if (v.colors) h += '<div class="or-product-colors">' + v.colors + '</div>';
                h += '</div>';
                h += '<div class="or-product-qty">' + v.qty.toLocaleString() + ' units</div>';
                h += '<button class="or-remove-btn" onclick="removeFromOrder(' + v.id + ')">\u2715</button>';
                h += '</div>';
            });
        });
        h += '</div></details>';

        // ===== STOCK ORDER REQUEST FORM =====
        h += '<div class="or-form-section">';
        h += '<h3>Stock Order Request</h3>';
        h += '<p style="font-size:0.8rem;color:#999;margin:-0.5rem 0 1rem">Fields marked with * are required</p>';

        // Row: Account Name + Buyer Name
        h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">';
        h += '<div class="or-field"><label>Account Name *</label>';
        h += '<select id="orCustomerSelect"><option value="">Select a customer...</option></select>';
        h += '<span style="font-size:0.7rem;color:#999">Select from dropdown, use OTHER if not in list</span></div>';
        h += '<div class="or-field"><label>Buyer Name</label>';
        h += '<input type="text" id="orBuyerName" placeholder="Who are you selling to?"></div>';
        h += '</div>';

        // Import PO #(s) - dropdown with typeahead
        h += '<div class="or-field"><label>Import PO #(s) *</label>';
        h += '<div style="position:relative">';
        h += '<input type="text" id="orImportPO" placeholder="Loading import POs..." list="importPOList" autocomplete="off">';
        h += '<datalist id="importPOList"></datalist>';
        h += '</div>';
        h += '<span style="font-size:0.7rem;color:#999">Select from dropdown or type manually. Shows Import POs for selected styles.</span></div>';

        // Customer PO Number
        h += '<div class="or-field"><label>Customer PO Number</label>';
        h += '<input type="text" id="orCustomerPO" placeholder="Customer PO number"></div>';

        // Row: Customer Price + CXL Date
        h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">';
        h += '<div class="or-field"><label>Customer Price *</label>';
        h += '<input type="number" id="orCustomerPrice" step="0.01" value="0.00" min="0"></div>';
        h += '<div class="or-field"><label>CXL Date *</label>';
        h += '<input type="date" id="orCxlDate">';
        h += '<span style="font-size:0.7rem;color:#999">dd-MMM-yyyy</span></div>';
        h += '</div>';

        // Unit Color Breakdown
        h += '<div class="or-field"><label>Unit Color Breakdown</label>';
        h += '<textarea id="orUnitColorBreakdown" rows="4" placeholder="Enter here, free form\n\nExample:\nNavy: S-50, M-100, L-100, XL-50\nBlack: S-25, M-75, L-75, XL-25"></textarea></div>';

        // ===== PRICE TICKETS SECTION =====
        h += '<div class="or-section-header">Price Tickets *</div>';
        h += '<div class="or-radio-grid">';
        h += radioGroup('pt_has_tickets', 'Does Stock have Price Tickets *');
        h += radioGroup('pt_keep_tickets', 'Keep tickets *');
        h += radioGroup('pt_remove_tickets', 'Just remove tickets *');
        h += radioGroup('pt_new_tickets', 'New Tickets Required *');
        h += radioGroup('pt_changes_in_price', 'Are changes included in customer price? *');
        h += '</div>';

        // ===== RE-PACKAGING SECTION =====
        h += '<div class="or-section-header">Re-Packaging *</div>';
        h += '<div class="or-radio-grid">';
        h += radioGroup('rp_required', 'Re-packaging required? *');
        h += radioGroup('rp_changes_in_price', 'Are changes included in customer price? *');
        h += '</div>';

        // ===== LABEL MARKETING SECTION =====
        h += '<div class="or-section-header">Label Marketing *</div>';
        h += '<div class="or-radio-grid">';
        h += radioGroup('lm_keep_existing', 'Keep existing Label Marketing *');
        h += radioGroup('lm_new_required', 'New Label Marketing Required (replace labels) *');
        h += radioGroup('lm_changes_in_price', 'Are changes included in customer price? *');
        h += '</div>';

        // Notes
        h += '<div class="or-field" style="margin-top:1rem"><label>Additional Notes / Instructions</label>';
        h += '<textarea id="orNotes" rows="4" placeholder="Any additional instructions, ship dates, special requirements..."></textarea></div>';

        h += '</div>';

        // Actions
        h += '<div class="or-review-actions">';
        h += '<button class="btn btn-secondary" onclick="closeOrderReview()">Back to Selection</button>';
        h += '<button class="btn btn-primary" id="orSubmitOrderBtn" onclick="submitOrder()" style="background:#34a853;border-color:#34a853">Submit Stock Order Request</button>';
        h += '</div>';

        content.innerHTML = h;
        overlay.classList.add('active');

        // Load data
        loadOrderCustomers();
        loadImportPOs(allStyleIds);
    };

    // ---- Load Import POs for the selected styles ----
    function loadImportPOs(styleIds) {
        var input = document.getElementById('orImportPO');
        if (!input) return;
        if (styleIds.length === 0) {
            input.placeholder = 'No styles selected';
            return;
        }
        fetch('/api/import-pos-for-styles?styles=' + encodeURIComponent(styleIds.join(',')))
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (!d.success || !d.importPOs || d.importPOs.length === 0) {
                    input.placeholder = 'No import POs found - type manually';
                    return;
                }
                input.placeholder = 'Select or type Import PO #...';
                var datalist = document.getElementById('importPOList');
                if (!datalist) return;
                datalist.innerHTML = '';
                d.importPOs.forEach(function(po) {
                    var opt = document.createElement('option');
                    var dateStr = po.doc_date ? new Date(po.doc_date).toLocaleDateString() : '';
                    var label = po.document_number;
                    if (po.customer_vendor) label += ' - ' + po.customer_vendor;
                    if (dateStr) label += ' (' + dateStr + ')';
                    if (po.status) label += ' [' + po.status + ']';
                    opt.value = po.document_number;
                    opt.label = label;
                    opt.textContent = label;
                    datalist.appendChild(opt);
                });
            })
            .catch(function(e) {
                console.error('Error loading import POs:', e);
                input.placeholder = 'Type Import PO # manually';
            });
    }

    var orderCustomersLoaded = false;
    var orderCustomerList = [];

    function loadOrderCustomers() {
        if (orderCustomersLoaded && orderCustomerList.length > 0) {
            populateCustomerDropdown();
            return;
        }
        fetch('/api/customers').then(function(r) { return r.json(); }).then(function(d) {
            if (d.success) {
                orderCustomerList = d.customers.map(function(c) { return c.name; });
                orderCustomersLoaded = true;
                populateCustomerDropdown();
            }
        }).catch(function(e) { console.error('Error loading customers:', e); });
    }

    function populateCustomerDropdown() {
        var sel = document.getElementById('orCustomerSelect');
        if (!sel) return;
        var current = sel.value;
        sel.innerHTML = '<option value="">Select a customer...</option>';
        orderCustomerList.forEach(function(name) {
            var opt = document.createElement('option');
            opt.value = name;
            opt.textContent = name;
            sel.appendChild(opt);
        });
        // Add OTHER option
        var otherOpt = document.createElement('option');
        otherOpt.value = '__OTHER__';
        otherOpt.textContent = '-- OTHER (type below) --';
        sel.appendChild(otherOpt);
        if (current) sel.value = current;

        // Handle OTHER selection
        sel.addEventListener('change', function() {
            var otherInput = document.getElementById('orCustomerOther');
            if (sel.value === '__OTHER__') {
                if (!otherInput) {
                    var inp = document.createElement('input');
                    inp.type = 'text';
                    inp.id = 'orCustomerOther';
                    inp.placeholder = 'Enter account name...';
                    inp.style.marginTop = '0.5rem';
                    sel.parentNode.appendChild(inp);
                    inp.focus();
                }
            } else if (otherInput) {
                otherInput.remove();
            }
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
        if (!customer) {
            alert('Please select or enter a customer/account name');
            return;
        }
        if (orderSelectedProducts.length === 0) {
            alert('No products selected');
            return;
        }

        var importPO = (document.getElementById('orImportPO') || {}).value || '';
        var cxlDate = (document.getElementById('orCxlDate') || {}).value || null;

        // Collect all form data
        var formData = {
            customer_name: customer,
            product_ids: orderSelectedProducts,
            buyer_name: (document.getElementById('orBuyerName') || {}).value || '',
            import_po_numbers: importPO,
            customer_po_number: (document.getElementById('orCustomerPO') || {}).value || '',
            customer_price: parseFloat((document.getElementById('orCustomerPrice') || {}).value) || 0,
            cxl_date: cxlDate,
            cancel_date: cxlDate,
            unit_color_breakdown: (document.getElementById('orUnitColorBreakdown') || {}).value || '',
            notes: (document.getElementById('orNotes') || {}).value || '',
            price_tickets: {
                has_tickets: getRadioVal('pt_has_tickets'),
                keep_tickets: getRadioVal('pt_keep_tickets'),
                remove_tickets: getRadioVal('pt_remove_tickets'),
                new_tickets: getRadioVal('pt_new_tickets'),
                changes_in_price: getRadioVal('pt_changes_in_price')
            },
            repackaging: {
                required: getRadioVal('rp_required'),
                changes_in_price: getRadioVal('rp_changes_in_price')
            },
            label_marketing: {
                keep_existing: getRadioVal('lm_keep_existing'),
                new_required: getRadioVal('lm_new_required'),
                changes_in_price: getRadioVal('lm_changes_in_price')
            }
        };

        var btn = document.getElementById('orSubmitOrderBtn');
        btn.disabled = true;
        btn.textContent = 'Submitting...';

        fetch('/api/order-requests', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        }).then(function(r) { return r.json(); }).then(function(d) {
            btn.disabled = false;
            btn.textContent = 'Submit Stock Order Request';
            if (d.success) {
                showOrderSuccess(d.order);
            } else {
                alert('Error: ' + (d.error || 'Unknown error'));
            }
        }).catch(function(e) {
            btn.disabled = false;
            btn.textContent = 'Submit Stock Order Request';
            alert('Error: ' + e.message);
        });
    };

    function showOrderSuccess(order) {
        var content = document.getElementById('orderReviewContent');
        if (!content) return;

        var detailFullUrl = (order.app_url || window.location.origin) + order.detail_url;
        var subject = 'Stock Order Request ' + order.request_number + ' - ' + order.customer_name;
        var body = 'New Stock Order Request: ' + order.request_number + '\n\n';
        body += 'Account: ' + order.customer_name + '\n';
        if (order.buyer_name) body += 'Buyer: ' + order.buyer_name + '\n';
        body += 'Products: ' + (order.product_count || 'N/A') + ' items\n';
        if (order.import_po_numbers) body += 'Import PO: ' + order.import_po_numbers + '\n';
        if (order.customer_po_number) body += 'Customer PO: ' + order.customer_po_number + '\n';
        if (order.customer_price > 0) body += 'Customer Price: $' + parseFloat(order.customer_price).toFixed(2) + '\n';
        if (order.cxl_date) body += 'CXL Date: ' + order.cxl_date + '\n';
        body += 'Submitted by: ' + (order.user_name || 'Unknown') + '\n';
        if (order.notes) body += '\nNotes:\n' + order.notes + '\n';
        body += '\nView full order details:\n' + detailFullUrl + '\n';

        var toEmail = order.notify_email || '';
        var mailtoUrl = 'mailto:' + encodeURIComponent(toEmail) + '?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body);

        var h = '<div class="or-success">';
        h += '<div class="or-success-icon">\u2705</div>';
        h += '<h2>Stock Order Request Saved!</h2>';
        h += '<div class="or-success-number">' + order.request_number + '</div>';
        h += '<p style="color:#666;margin:0.5rem 0 1.5rem">Your order request has been saved and the order entry team has been notified. You can also email the details:</p>';
        h += '<div style="display:flex;flex-direction:column;gap:0.75rem;align-items:center">';
        h += '<a href="' + mailtoUrl + '" class="btn btn-primary" style="background:#0088c2;border-color:#0088c2;text-decoration:none;padding:0.75rem 2rem;font-size:1rem;display:inline-block">\ud83d\udce7 Email Order Details</a>';
        h += '<a href="' + detailFullUrl + '" target="_blank" class="or-detail-link">View Order Details \u2192</a>';
        h += '</div>';
        h += '<button class="btn btn-secondary" onclick="finishOrder()" style="margin-top:1.5rem">Done</button>';
        h += '</div>';
        content.innerHTML = h;
    }

    window.finishOrder = function() {
        orderMode = false;
        orderSelectedProducts = [];
        var btn = document.getElementById('orderModeBtn');
        if (btn) {
            btn.textContent = '\ud83d\udccb Create Order';
            btn.classList.remove('active');
        }
        updateOrderBar();
        closeOrderReview();
        renderProducts();
    };

    // ---- Orders List (for viewing past orders) ----

    var ordersCustomersLoaded = false;

    window.toggleOrdersList = function() {
        var panel = document.getElementById('ordersListPanel');
        if (!panel) {
            var main = document.querySelector('.main');
            if (!main) return;
            var div = document.createElement('div');
            div.id = 'ordersListPanel';
            div.className = 'orders-list-panel';
            div.innerHTML = '<div class="orders-list-header"><h2>\ud83d\udccb Order Requests</h2><button class="btn btn-secondary btn-sm" onclick="closeOrdersList()">\u2715 Close</button></div>' +
                '<div class="orders-list-filters">' +
                '<select id="ordersStatusFilter" onchange="loadOrdersList()"><option value="all">All Status</option><option value="pending">Pending</option><option value="processing">Processing</option><option value="completed">Completed</option><option value="cancelled">Cancelled</option></select>' +
                '<select id="ordersCustomerFilter" onchange="loadOrdersList()"><option value="all">All Customers</option></select>' +
                '<span id="ordersResultCount" style="font-size:0.8rem;color:#999;margin-left:0.5rem"></span>' +
                '</div>' +
                '<div id="ordersListContent">Loading...</div>';
            main.insertBefore(div, main.firstChild);
            loadOrdersCustomerFilter();
            loadOrdersList();
        } else {
            panel.style.display = panel.style.display === 'none' ? '' : 'none';
            if (panel.style.display !== 'none') loadOrdersList();
        }
    };

    function loadOrdersCustomerFilter() {
        if (ordersCustomersLoaded) return;
        fetch('/api/order-requests/customers')
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.success && d.customers) {
                    var sel = document.getElementById('ordersCustomerFilter');
                    if (!sel) return;
                    d.customers.forEach(function(c) {
                        var opt = document.createElement('option');
                        opt.value = c;
                        opt.textContent = c;
                        sel.appendChild(opt);
                    });
                    ordersCustomersLoaded = true;
                }
            }).catch(function() {});
    }

    window.closeOrdersList = function() {
        var panel = document.getElementById('ordersListPanel');
        if (panel) panel.style.display = 'none';
    };

    window.loadOrdersList = function() {
        var statusEl = document.getElementById('ordersStatusFilter');
        var customerEl = document.getElementById('ordersCustomerFilter');
        var status = statusEl ? statusEl.value : 'all';
        var customer = customerEl ? customerEl.value : 'all';
        var url = '/api/order-requests?status=' + encodeURIComponent(status);
        if (customer !== 'all') url += '&customer=' + encodeURIComponent(customer);

        fetch(url)
            .then(function(r) { return r.json(); })
            .then(function(d) {
                var container = document.getElementById('ordersListContent');
                var countEl = document.getElementById('ordersResultCount');
                if (!container) return;
                if (!d.success || !d.orders || d.orders.length === 0) {
                    container.innerHTML = '<p class="or-empty">No order requests found.</p>';
                    if (countEl) countEl.textContent = '0 orders';
                    return;
                }
                if (countEl) countEl.textContent = d.orders.length + ' order' + (d.orders.length !== 1 ? 's' : '');

                var h = '';
                d.orders.forEach(function(o) {
                    var dt = new Date(o.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' });
                    h += '<div class="or-list-card">';
                    h += '<div class="or-list-card-header">';
                    h += '<span class="or-list-num">' + o.request_number + '</span>';
                    h += '<span class="or-status ' + o.status + '">' + o.status + '</span>';
                    h += '</div>';
                    h += '<div class="or-list-card-body">';
                    h += '<div class="or-list-row"><span class="or-list-label">Account</span><span class="or-list-val" style="font-weight:700">' + o.customer_name + '</span></div>';
                    if (o.buyer_name) {
                        h += '<div class="or-list-row"><span class="or-list-label">Buyer</span><span class="or-list-val">' + o.buyer_name + '</span></div>';
                    }
                    h += '<div class="or-list-row"><span class="or-list-label">Products</span><span class="or-list-val">' + (o.product_count || 0) + ' items</span></div>';
                    if (o.import_po_numbers) {
                        h += '<div class="or-list-row"><span class="or-list-label">Import PO</span><span class="or-list-val">' + o.import_po_numbers + '</span></div>';
                    }
                    if (o.customer_po_number) {
                        h += '<div class="or-list-row"><span class="or-list-label">Customer PO</span><span class="or-list-val">' + o.customer_po_number + '</span></div>';
                    }
                    if (o.customer_price && parseFloat(o.customer_price) > 0) {
                        h += '<div class="or-list-row"><span class="or-list-label">Price</span><span class="or-list-val">$' + parseFloat(o.customer_price).toFixed(2) + '</span></div>';
                    }
                    if (o.cxl_date || o.cancel_date) {
                        var cd = o.cxl_date || o.cancel_date;
                        h += '<div class="or-list-row"><span class="or-list-label">CXL Date</span><span class="or-list-val">' + new Date(cd).toLocaleDateString() + '</span></div>';
                    }
                    h += '<div class="or-list-row"><span class="or-list-label">Submitted</span><span class="or-list-val">' + dt + '</span></div>';
                    h += '<div class="or-list-row"><span class="or-list-label">Rep</span><span class="or-list-val">' + (o.user_name || 'Unknown') + '</span></div>';
                    if (o.unit_color_breakdown) {
                        h += '<div class="or-list-notes" style="background:#e3f2fd"><strong>Unit/Color Breakdown:</strong><br>' + o.unit_color_breakdown.replace(/</g, '&lt;').replace(/\n/g, '<br>') + '</div>';
                    }
                    if (o.notes) {
                        var truncNotes = o.notes.length > 150 ? o.notes.substring(0, 150) + '...' : o.notes;
                        h += '<div class="or-list-notes">' + truncNotes.replace(/</g, '&lt;').replace(/\n/g, '<br>') + '</div>';
                    }
                    if (o.zoho_so_number) {
                        h += '<div class="or-list-so">Zoho SO: ' + o.zoho_so_number + '</div>';
                    }

                    // Action buttons row
                    h += '<div class="or-list-actions">';
                    if (o.detail_id) {
                        h += '<a href="/order/' + o.detail_id + '" target="_blank" class="or-action-link">View Details \u2192</a>';
                    }
                    h += '</div>';

                    h += '</div>';

                    // Admin controls
                    if (o.can_admin && (o.status === 'pending' || o.status === 'processing')) {
                        h += '<div class="or-admin-controls">';
                        h += '<input type="text" placeholder="Zoho SO #" id="soInput' + o.id + '" value="' + (o.zoho_so_number || '') + '" class="or-admin-input">';
                        h += '<input type="text" placeholder="Admin note" id="noteInput' + o.id + '" value="' + (o.admin_notes || '') + '" class="or-admin-input" style="flex:1">';
                        if (o.status === 'pending') {
                            h += '<button class="or-admin-btn processing" onclick="updateOrderStatus(' + o.id + ',\'processing\')">Processing</button>';
                        }
                        h += '<button class="or-admin-btn complete" onclick="completeOrderAdmin(' + o.id + ')">Complete</button>';
                        h += '<button class="or-admin-btn cancel" onclick="updateOrderStatus(' + o.id + ',\'cancelled\')">Cancel</button>';
                        h += '</div>';
                    }

                    h += '</div>';
                });
                container.innerHTML = h;
            })
            .catch(function(e) {
                console.error('Error loading orders:', e);
                var container = document.getElementById('ordersListContent');
                if (container) container.innerHTML = '<p class="or-empty">Error loading orders.</p>';
            });
    };

    window.updateOrderStatus = function(id, status) {
        fetch('/api/order-requests/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: status })
        }).then(function(r) { return r.json(); }).then(function(d) {
            if (d.success) loadOrdersList();
            else alert('Error: ' + d.error);
        }).catch(function(e) { alert(e.message); });
    };

    window.completeOrderAdmin = function(id) {
        var so = document.getElementById('soInput' + id);
        var note = document.getElementById('noteInput' + id);
        var soVal = so ? so.value.trim() : '';
        var noteVal = note ? note.value.trim() : '';

        fetch('/api/order-requests/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                status: 'completed',
                zoho_so_number: soVal || null,
                admin_notes: noteVal || null
            })
        }).then(function(r) { return r.json(); }).then(function(d) {
            if (d.success) loadOrdersList();
            else alert('Error: ' + d.error);
        }).catch(function(e) { alert(e.message); });
    };
})();
