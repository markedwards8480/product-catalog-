// ==========================================
// ORDER SIZE GRID - Inline size breakdown for order request form
// ==========================================
// Loaded dynamically when rep selects an Import PO
// Shows size grid so rep can enter totals and see size distribution before submitting

(function() {
    var orSizeCurve = null;
    var orSizeRows = [];
    var orAllSizes = [];
    var orSizeOrder = {"XXS":0,"XS":1,"S":2,"M":3,"L":4,"XL":5,"XXL":6,"2XL":6,"3XL":7,"4XL":8,"5XL":9,"1X":5,"2X":6,"3X":7,"0T":0,"2T":1,"3T":2,"4T":3,"5":4,"6":5,"6X":6,"7":7,"8":8,"10":9,"12":10,"14":11,"16":12};

    // Called when Import PO changes — loads size curve and builds grid
    window.loadOrderSizeGrid = function(poNumber) {
        var container = document.getElementById('orSizeGridContainer');
        if (!container) return;

        if (!poNumber || poNumber.length < 3) {
            container.innerHTML = '';
            container.style.display = 'none';
            return;
        }

        container.style.display = '';
        container.innerHTML = '<div style="padding:1rem;color:#666;font-size:0.85rem"><span style="display:inline-block;animation:spin 1s linear infinite;margin-right:0.5rem">⏳</span> Loading size breakdown from Import PO ' + poNumber + '...</div>';

        // Get selected products info
        var selectedProducts = [];
        if (typeof orderSelectedProducts !== 'undefined' && typeof allProducts !== 'undefined') {
            orderSelectedProducts.forEach(function(id) {
                var p = allProducts.find(function(pr) { return pr.id === id; });
                if (p) selectedProducts.push(p);
            });
        }

        // Try loading from PO curve first, fallback to product sizes
        fetch('/api/zoho/po-size-curve/' + encodeURIComponent(poNumber))
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.success && d.curve && d.curve.length > 0) {
                    orSizeCurve = d.curve;
                    buildSizeGrid(container, selectedProducts, d.curve, d.source);
                } else {
                    // Fallback: load sizes from product inventory
                    loadProductSizes(container, selectedProducts);
                }
            })
            .catch(function(e) {
                console.error('PO curve error:', e);
                loadProductSizes(container, selectedProducts);
            });
    };

    function loadProductSizes(container, selectedProducts) {
        var styleIds = [];
        selectedProducts.forEach(function(p) {
            if (styleIds.indexOf(p.style_id) === -1) styleIds.push(p.style_id);
        });

        if (styleIds.length === 0) {
            container.innerHTML = '<div style="padding:0.75rem;color:#e65100;font-size:0.85rem">⚠ No size data available. Use the Unit Color Breakdown field below instead.</div>';
            return;
        }

        fetch('/api/product-sizes-for-so?styles=' + encodeURIComponent(styleIds.join(',')))
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.success && d.data && d.data.length > 0) {
                    // Build pseudo-curve from inventory data
                    var curve = [];
                    d.data.forEach(function(item) {
                        var totalInv = item.sizes.reduce(function(sum, s) { return sum + (s.left_to_sell || s.available_now || 0); }, 0);
                        var ratios = {};
                        var sizes = {};
                        item.sizes.forEach(function(s) {
                            var qty = s.left_to_sell || s.available_now || 0;
                            sizes[s.size] = qty;
                            ratios[s.size] = totalInv > 0 ? qty / totalInv : 0;
                        });
                        curve.push({ base_style: item.style_id.split('-')[0], color: item.color, sizes: sizes, ratios: ratios, total_qty: totalInv, source: 'inventory' });
                    });
                    orSizeCurve = curve;
                    buildSizeGrid(container, selectedProducts, curve, 'inventory');
                } else {
                    container.innerHTML = '<div style="padding:0.75rem;color:#e65100;font-size:0.85rem">⚠ Could not load size data. Use the Unit Color Breakdown field below instead.</div>';
                }
            })
            .catch(function(e) {
                container.innerHTML = '<div style="padding:0.75rem;color:#c62828;font-size:0.85rem">Error loading sizes: ' + e.message + '</div>';
            });
    }

    function buildSizeGrid(container, selectedProducts, curve, source) {
        // Build rows: one per style/color from selected products
        orSizeRows = [];
        selectedProducts.forEach(function(p) {
            var colors = (p.colors || []).map(function(c) { return c.color_name || c; }).filter(Boolean);
            if (colors.length > 0) {
                colors.forEach(function(c) {
                    var colorName = typeof c === 'string' ? c : (c.color_name || 'Default');
                    var curveMatch = curve.find(function(cv) { return cv.base_style === p.base_style && cv.color.toLowerCase() === colorName.toLowerCase(); });
                    if (!curveMatch) curveMatch = curve.find(function(cv) { return cv.base_style === p.base_style; });
                    orSizeRows.push({ style_id: p.style_id, base_style: p.base_style, name: p.name, color: colorName, curve: curveMatch });
                });
            } else {
                var curveMatch = curve.find(function(cv) { return cv.base_style === p.base_style; });
                orSizeRows.push({ style_id: p.style_id, base_style: p.base_style, name: p.name, color: 'Default', curve: curveMatch });
            }
        });

        // Collect all sizes
        orAllSizes = [];
        curve.forEach(function(cv) {
            Object.keys(cv.ratios || cv.sizes || {}).forEach(function(s) {
                if (orAllSizes.indexOf(s) === -1) orAllSizes.push(s);
            });
        });
        if (orAllSizes.length === 0) orAllSizes = ['OS'];

        // Sort sizes
        orAllSizes.sort(function(a, b) {
            var ra = orSizeOrder[a] !== undefined ? orSizeOrder[a] : 50;
            var rb = orSizeOrder[b] !== undefined ? orSizeOrder[b] : 50;
            return ra - rb;
        });

        // Build HTML
        var sourceLabel = source === 'zoho' ? 'Import PO' : (source === 'local' ? 'local data' : 'product inventory');
        var h = '';
        h += '<div style="margin-bottom:0.5rem;font-size:0.82rem;color:#2e7d32">✓ Size breakdown loaded from ' + sourceLabel + ' — ' + curve.length + ' color group(s). Enter total qty per color to auto-distribute.</div>';

        h += '<div style="overflow-x:auto">';
        h += '<table style="width:100%;border-collapse:collapse;font-size:0.8rem;border:1px solid #e0e0e0">';

        // Header
        h += '<thead><tr style="background:#1e3a5f;color:white">';
        h += '<th style="text-align:left;padding:0.5rem 0.6rem;font-weight:600;font-size:0.75rem;min-width:90px">STYLE</th>';
        h += '<th style="text-align:left;padding:0.5rem 0.4rem;font-weight:600;font-size:0.75rem;min-width:70px">COLOR</th>';
        orAllSizes.forEach(function(s) {
            h += '<th style="text-align:center;padding:0.5rem 0.2rem;font-weight:600;font-size:0.72rem;min-width:50px">' + s + '</th>';
        });
        h += '<th style="text-align:center;padding:0.5rem 0.4rem;font-weight:700;font-size:0.75rem;min-width:60px;background:#163350">TOTAL</th>';
        h += '</tr></thead><tbody>';

        // Rows
        orSizeRows.forEach(function(row, idx) {
            var bgColor = idx % 2 === 0 ? '#fff' : '#f8f9fb';
            h += '<tr style="background:' + bgColor + ';border-bottom:1px solid #eee">';
            h += '<td style="padding:0.4rem 0.6rem;font-weight:600;color:#0088c2;font-size:0.78rem;white-space:nowrap">' + row.style_id + '</td>';
            h += '<td style="padding:0.4rem 0.4rem;color:#333;font-size:0.76rem">' + row.color + '</td>';

            orAllSizes.forEach(function(s) {
                var ratio = (row.curve && row.curve.ratios && row.curve.ratios[s]) ? row.curve.ratios[s] : 0;
                h += '<td style="padding:0.2rem 0.1rem;text-align:center">';
                h += '<input type="number" id="orSz_' + idx + '_' + s + '" value="" min="0" data-ratio="' + ratio + '" data-row="' + idx + '" ';
                h += 'style="width:48px;text-align:center;padding:0.2rem;border:1px solid #d0d0d0;border-radius:4px;font-size:0.76rem;background:' + (ratio > 0 ? '#f0f7ff' : '#fff') + '" ';
                h += 'onchange="orRecalcRow(' + idx + ')" onkeyup="orRecalcRow(' + idx + ')">';
                h += '</td>';
            });

            // Total column
            h += '<td style="padding:0.2rem 0.1rem;text-align:center;background:#f0f4f8">';
            h += '<input type="number" id="orSzTotal_' + idx + '" value="" min="0" ';
            h += 'style="width:58px;text-align:center;padding:0.25rem;border:1.5px solid #b0bec5;border-radius:4px;font-size:0.8rem;font-weight:700;color:#1e3a5f;background:#f0f4f8" ';
            h += 'onchange="orAutoDistribute(' + idx + ', parseInt(this.value)||0)" onkeyup="orAutoDistribute(' + idx + ', parseInt(this.value)||0)">';
            h += '</td>';
            h += '</tr>';
        });

        // Totals row
        h += '<tr style="background:#e8ecf0;font-weight:700;border-top:2px solid #1e3a5f">';
        h += '<td style="padding:0.5rem 0.6rem;font-size:0.8rem">TOTALS</td>';
        h += '<td></td>';
        orAllSizes.forEach(function(s) {
            h += '<td style="text-align:center;padding:0.5rem 0.2rem;font-size:0.76rem" id="orSzColTotal_' + s + '">0</td>';
        });
        h += '<td style="text-align:center;padding:0.5rem 0.4rem;font-size:0.9rem;color:#1e3a5f;background:#dce3eb;font-weight:700" id="orSzGrandTotal">0</td>';
        h += '</tr>';

        h += '</tbody></table></div>';
        h += '<p style="font-size:0.72rem;color:#0088c2;margin-top:0.4rem">💡 Enter a total in the TOTAL column and sizes will auto-distribute based on the Import PO ratio.</p>';

        container.innerHTML = h;
    }

    // Auto-distribute total across sizes by ratio
    window.orAutoDistribute = function(rowIdx, totalQty) {
        if (totalQty === 0) {
            orAllSizes.forEach(function(s) {
                var el = document.getElementById('orSz_' + rowIdx + '_' + s);
                if (el) el.value = '';
            });
            orRecalcRow(rowIdx);
            return;
        }

        var totalRatio = 0;
        orAllSizes.forEach(function(s) {
            var el = document.getElementById('orSz_' + rowIdx + '_' + s);
            if (el) totalRatio += parseFloat(el.dataset.ratio || 0);
        });

        if (totalRatio === 0) {
            // Even distribution
            var perSize = Math.floor(totalQty / orAllSizes.length);
            var remainder = totalQty - (perSize * orAllSizes.length);
            orAllSizes.forEach(function(s, i) {
                var el = document.getElementById('orSz_' + rowIdx + '_' + s);
                if (el) el.value = perSize + (i < remainder ? 1 : 0);
            });
        } else {
            // Largest remainder method
            var allocated = 0;
            var items = [];
            orAllSizes.forEach(function(s) {
                var el = document.getElementById('orSz_' + rowIdx + '_' + s);
                if (!el) return;
                var ratio = parseFloat(el.dataset.ratio || 0);
                var exact = totalQty * (ratio / totalRatio);
                var floor = Math.floor(exact);
                items.push({ size: s, floor: floor, remainder: exact - floor, el: el });
                allocated += floor;
            });
            var remaining = totalQty - allocated;
            items.sort(function(a, b) { return b.remainder - a.remainder; });
            items.forEach(function(it, i) { it.el.value = it.floor + (i < remaining ? 1 : 0); });
        }
        orRecalcRow(rowIdx);
    };

    // Recalculate row and column totals
    window.orRecalcRow = function(rowIdx) {
        var rowTotal = 0;
        orAllSizes.forEach(function(s) {
            var el = document.getElementById('orSz_' + rowIdx + '_' + s);
            if (el && el.value) rowTotal += parseInt(el.value) || 0;
        });
        var totalEl = document.getElementById('orSzTotal_' + rowIdx);
        if (totalEl) totalEl.value = rowTotal || '';

        // Recalc column totals
        var grandTotal = 0;
        orAllSizes.forEach(function(s) {
            var colTotal = 0;
            for (var i = 0; i < orSizeRows.length; i++) {
                var el = document.getElementById('orSz_' + i + '_' + s);
                if (el && el.value) colTotal += parseInt(el.value) || 0;
            }
            var colEl = document.getElementById('orSzColTotal_' + s);
            if (colEl) colEl.textContent = colTotal > 0 ? colTotal.toLocaleString() : '0';
            grandTotal += colTotal;
        });
        var gtEl = document.getElementById('orSzGrandTotal');
        if (gtEl) gtEl.textContent = grandTotal > 0 ? grandTotal.toLocaleString() : '0';
    };

    // Collect size grid data for submission
    window.getOrderSizeGridData = function() {
        if (!orSizeRows || orSizeRows.length === 0 || orAllSizes.length === 0) return null;

        var hasData = false;
        var gridData = {
            sizes: orAllSizes,
            rows: orSizeRows.map(function(row, idx) {
                var sizeBreakdown = {};
                var rowTotal = 0;
                orAllSizes.forEach(function(s) {
                    var el = document.getElementById('orSz_' + idx + '_' + s);
                    var qty = el ? (parseInt(el.value) || 0) : 0;
                    if (qty > 0) {
                        sizeBreakdown[s] = qty;
                        hasData = true;
                    }
                    rowTotal += qty;
                });
                return {
                    style_id: row.style_id,
                    base_style: row.base_style,
                    color: row.color,
                    sizes: sizeBreakdown,
                    total: rowTotal
                };
            })
        };

        return hasData ? gridData : null;
    };
})();
