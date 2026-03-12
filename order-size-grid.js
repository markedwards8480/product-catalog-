// ==========================================
// ORDER SIZE GRID - Per-Style size grids
// ==========================================
// Each base style gets its own size grid, loaded when Import PO is selected
// Container ID pattern: orStyleSizeGrid_{baseStyle}

(function() {
    // Per-style data store
    // styleGridData[bs] = { sizeRows: [], allSizes: [], curve: [] }
    var styleGridData = {};
    var sizeOrder = {"XXS":0,"XS":1,"S":2,"M":3,"L":4,"XL":5,"XXL":6,"2XL":6,"3XL":7,"4XL":8,"5XL":9,"1X":5,"2X":6,"3X":7,"0T":0,"2T":1,"3T":2,"4T":3,"5":4,"6":5,"6X":6,"7":7,"8":8,"10":9,"12":10,"14":11,"16":12};

    // Called when a style's Import PO is selected
    window.loadStyleSizeGrid = function(bs, poNumber) {
        var container = document.getElementById('orStyleSizeGrid_' + bs);
        if (!container) return;

        if (!poNumber || poNumber.length < 3) {
            container.innerHTML = '';
            container.style.display = 'none';
            return;
        }

        container.style.display = '';
        container.innerHTML = '<div style="padding:0.75rem;color:#666;font-size:0.82rem"><span style="display:inline-block;animation:spin 1s linear infinite;margin-right:0.5rem">\u23f3</span> Loading size breakdown for ' + bs + ' from PO ' + poNumber + '...</div>';

        // Get selected products for this base style
        var selectedProducts = [];
        if (typeof getOrderSelectedProducts === 'function' && typeof allProducts !== 'undefined') {
            var selectedIds = getOrderSelectedProducts();
            selectedIds.forEach(function(id) {
                var p = allProducts.find(function(pr) { return pr.id === id; });
                if (p && p.style_id.split('-')[0] === bs) selectedProducts.push(p);
            });
        }

        // Try PO curve first, fallback to product sizes
        fetch('/api/zoho/po-size-curve/' + encodeURIComponent(poNumber))
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.success && d.curve && d.curve.length > 0) {
                    buildStyleSizeGrid(bs, container, selectedProducts, d.curve, d.source);
                } else {
                    loadStyleProductSizes(bs, container, selectedProducts);
                }
            })
            .catch(function(e) {
                console.error('PO curve error for ' + bs + ':', e);
                loadStyleProductSizes(bs, container, selectedProducts);
            });
    };

    function loadStyleProductSizes(bs, container, selectedProducts) {
        var styleIds = [];
        selectedProducts.forEach(function(p) {
            if (styleIds.indexOf(p.style_id) === -1) styleIds.push(p.style_id);
        });

        if (styleIds.length === 0) {
            container.innerHTML = '<div style="padding:0.5rem;color:#e65100;font-size:0.82rem">\u26a0 No size data available for ' + bs + '.</div>';
            return;
        }

        fetch('/api/product-sizes-for-so?styles=' + encodeURIComponent(styleIds.join(',')))
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.success && d.data && d.data.length > 0) {
                    var curve = [];
                    d.data.forEach(function(item) {
                        var totalInv = item.sizes.reduce(function(sum, s) { return sum + (s.left_to_sell || s.available_now || 0); }, 0);
                        var ratios = {}; var sizes = {};
                        item.sizes.forEach(function(s) {
                            var qty = s.left_to_sell || s.available_now || 0;
                            sizes[s.size] = qty;
                            ratios[s.size] = totalInv > 0 ? qty / totalInv : 0;
                        });
                        curve.push({ base_style: item.style_id.split('-')[0], color: item.color, sizes: sizes, ratios: ratios, total_qty: totalInv, source: 'inventory' });
                    });
                    buildStyleSizeGrid(bs, container, selectedProducts, curve, 'inventory');
                } else {
                    container.innerHTML = '<div style="padding:0.5rem;color:#e65100;font-size:0.82rem">\u26a0 No size data for ' + bs + '.</div>';
                }
            })
            .catch(function(e) {
                container.innerHTML = '<div style="padding:0.5rem;color:#c62828;font-size:0.82rem">Error loading sizes for ' + bs + ': ' + e.message + '</div>';
            });
    }

    function buildStyleSizeGrid(bs, container, selectedProducts, curve, source) {
        var sizeRows = [];
        selectedProducts.forEach(function(p) {
            var colors = (p.colors || []).map(function(c) { return c.color_name || c; }).filter(Boolean);
            if (colors.length > 0) {
                colors.forEach(function(c) {
                    var colorName = typeof c === 'string' ? c : (c.color_name || 'Default');
                    var curveMatch = curve.find(function(cv) { return cv.base_style === p.base_style && cv.color.toLowerCase() === colorName.toLowerCase(); });
                    if (!curveMatch) curveMatch = curve.find(function(cv) { return cv.base_style === p.base_style; });
                    sizeRows.push({ style_id: p.style_id, base_style: p.base_style, name: p.name, color: colorName, curve: curveMatch });
                });
            } else {
                var curveMatch = curve.find(function(cv) { return cv.base_style === p.base_style; });
                sizeRows.push({ style_id: p.style_id, base_style: p.base_style, name: p.name, color: 'Default', curve: curveMatch });
            }
        });

        // Collect all sizes
        var allSizes = [];
        curve.forEach(function(cv) {
            Object.keys(cv.ratios || cv.sizes || {}).forEach(function(s) {
                if (allSizes.indexOf(s) === -1) allSizes.push(s);
            });
        });
        if (allSizes.length === 0) allSizes = ['OS'];
        allSizes.sort(function(a, b) {
            var ra = sizeOrder[a] !== undefined ? sizeOrder[a] : 50;
            var rb = sizeOrder[b] !== undefined ? sizeOrder[b] : 50;
            return ra - rb;
        });

        // Store for data collection
        styleGridData[bs] = { sizeRows: sizeRows, allSizes: allSizes, curve: curve };

        var sourceLabel = source === 'zoho' ? 'Import PO' : (source === 'local' ? 'local data' : 'product inventory');
        var h = '';
        h += '<div style="margin-bottom:0.4rem;font-size:0.78rem;color:#2e7d32">\u2713 Size breakdown loaded from ' + sourceLabel + ' \u2014 ' + sizeRows.length + ' row(s). Enter total qty per row to auto-distribute.</div>';

        h += '<div style="overflow-x:auto">';
        h += '<table style="width:100%;border-collapse:collapse;font-size:0.78rem;border:1px solid #e0e0e0">';

        // Header
        h += '<thead><tr style="background:#1e3a5f;color:white">';
        h += '<th style="text-align:left;padding:0.4rem 0.5rem;font-weight:600;font-size:0.73rem;min-width:80px">STYLE</th>';
        h += '<th style="text-align:left;padding:0.4rem 0.3rem;font-weight:600;font-size:0.73rem;min-width:60px">COLOR</th>';
        allSizes.forEach(function(s) {
            h += '<th style="text-align:center;padding:0.4rem 0.2rem;font-weight:600;font-size:0.7rem;min-width:46px">' + s + '</th>';
        });
        h += '<th style="text-align:center;padding:0.4rem 0.3rem;font-weight:700;font-size:0.73rem;min-width:55px;background:#163350">TOTAL</th>';
        h += '</tr></thead><tbody>';

        // Rows — use bs-prefixed IDs to avoid conflicts between styles
        sizeRows.forEach(function(row, idx) {
            var bgColor = idx % 2 === 0 ? '#fff' : '#f8f9fb';
            h += '<tr style="background:' + bgColor + ';border-bottom:1px solid #eee">';
            h += '<td style="padding:0.3rem 0.5rem;font-weight:600;color:#0088c2;font-size:0.76rem;white-space:nowrap">' + row.style_id + '</td>';
            h += '<td style="padding:0.3rem 0.3rem;color:#333;font-size:0.74rem">' + row.color + '</td>';

            allSizes.forEach(function(s) {
                var ratio = (row.curve && row.curve.ratios && row.curve.ratios[s]) ? row.curve.ratios[s] : 0;
                h += '<td style="padding:0.15rem 0.1rem;text-align:center">';
                h += '<input type="number" id="orSz_' + bs + '_' + idx + '_' + s + '" value="" min="0" data-ratio="' + ratio + '" ';
                h += 'style="width:46px;text-align:center;padding:0.2rem;border:1px solid #d0d0d0;border-radius:4px;font-size:0.74rem;background:' + (ratio > 0 ? '#f0f7ff' : '#fff') + '" ';
                h += 'onchange="orStyleRecalcRow(\'' + bs + '\',' + idx + ')" onkeyup="orStyleRecalcRow(\'' + bs + '\',' + idx + ')">';
                h += '</td>';
            });

            // Total column
            h += '<td style="padding:0.15rem 0.1rem;text-align:center;background:#f0f4f8">';
            h += '<input type="number" id="orSzTotal_' + bs + '_' + idx + '" value="" min="0" ';
            h += 'style="width:54px;text-align:center;padding:0.2rem;border:1.5px solid #b0bec5;border-radius:4px;font-size:0.78rem;font-weight:700;color:#1e3a5f;background:#f0f4f8" ';
            h += 'onchange="orStyleAutoDistribute(\'' + bs + '\',' + idx + ',parseInt(this.value)||0)" onkeyup="orStyleAutoDistribute(\'' + bs + '\',' + idx + ',parseInt(this.value)||0)">';
            h += '</td></tr>';
        });

        // Totals row
        h += '<tr style="background:#e8ecf0;font-weight:700;border-top:2px solid #1e3a5f">';
        h += '<td style="padding:0.4rem 0.5rem;font-size:0.78rem">TOTALS</td><td></td>';
        allSizes.forEach(function(s) {
            h += '<td style="text-align:center;padding:0.4rem 0.2rem;font-size:0.74rem" id="orSzColTotal_' + bs + '_' + s + '">0</td>';
        });
        h += '<td style="text-align:center;padding:0.4rem 0.3rem;font-size:0.85rem;color:#1e3a5f;background:#dce3eb;font-weight:700" id="orSzGrandTotal_' + bs + '">0</td>';
        h += '</tr></tbody></table></div>';
        h += '<p style="font-size:0.7rem;color:#0088c2;margin-top:0.3rem">\ud83d\udca1 Enter a total in the TOTAL column to auto-distribute by PO ratio.</p>';

        container.innerHTML = h;
    }

    // Auto-distribute total across sizes by ratio (per-style)
    window.orStyleAutoDistribute = function(bs, rowIdx, totalQty) {
        var data = styleGridData[bs];
        if (!data) return;

        if (totalQty === 0) {
            data.allSizes.forEach(function(s) {
                var el = document.getElementById('orSz_' + bs + '_' + rowIdx + '_' + s);
                if (el) el.value = '';
            });
            orStyleRecalcRow(bs, rowIdx);
            return;
        }

        var totalRatio = 0;
        data.allSizes.forEach(function(s) {
            var el = document.getElementById('orSz_' + bs + '_' + rowIdx + '_' + s);
            if (el) totalRatio += parseFloat(el.dataset.ratio || 0);
        });

        if (totalRatio === 0) {
            var perSize = Math.floor(totalQty / data.allSizes.length);
            var remainder = totalQty - (perSize * data.allSizes.length);
            data.allSizes.forEach(function(s, i) {
                var el = document.getElementById('orSz_' + bs + '_' + rowIdx + '_' + s);
                if (el) el.value = perSize + (i < remainder ? 1 : 0);
            });
        } else {
            var allocated = 0;
            var items = [];
            data.allSizes.forEach(function(s) {
                var el = document.getElementById('orSz_' + bs + '_' + rowIdx + '_' + s);
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
        orStyleRecalcRow(bs, rowIdx);
    };

    // Recalculate row and column totals (per-style)
    window.orStyleRecalcRow = function(bs, rowIdx) {
        var data = styleGridData[bs];
        if (!data) return;

        var rowTotal = 0;
        data.allSizes.forEach(function(s) {
            var el = document.getElementById('orSz_' + bs + '_' + rowIdx + '_' + s);
            if (el && el.value) rowTotal += parseInt(el.value) || 0;
        });
        var totalEl = document.getElementById('orSzTotal_' + bs + '_' + rowIdx);
        if (totalEl) totalEl.value = rowTotal || '';

        // Recalc column totals
        var grandTotal = 0;
        data.allSizes.forEach(function(s) {
            var colTotal = 0;
            for (var i = 0; i < data.sizeRows.length; i++) {
                var el = document.getElementById('orSz_' + bs + '_' + i + '_' + s);
                if (el && el.value) colTotal += parseInt(el.value) || 0;
            }
            var colEl = document.getElementById('orSzColTotal_' + bs + '_' + s);
            if (colEl) colEl.textContent = colTotal > 0 ? colTotal.toLocaleString() : '0';
            grandTotal += colTotal;
        });
        var gtEl = document.getElementById('orSzGrandTotal_' + bs);
        if (gtEl) gtEl.textContent = grandTotal > 0 ? grandTotal.toLocaleString() : '0';
    };

    // Collect size grid data for a specific style (called during form submission)
    window.getStyleSizeGridData = function(bs) {
        var data = styleGridData[bs];
        if (!data || !data.sizeRows || data.sizeRows.length === 0 || data.allSizes.length === 0) return null;

        var hasData = false;
        var gridData = {
            sizes: data.allSizes,
            rows: data.sizeRows.map(function(row, idx) {
                var sizeBreakdown = {};
                var rowTotal = 0;
                data.allSizes.forEach(function(s) {
                    var el = document.getElementById('orSz_' + bs + '_' + idx + '_' + s);
                    var qty = el ? (parseInt(el.value) || 0) : 0;
                    if (qty > 0) { sizeBreakdown[s] = qty; hasData = true; }
                    rowTotal += qty;
                });
                return { style_id: row.style_id, base_style: row.base_style, color: row.color, sizes: sizeBreakdown, total: rowTotal };
            })
        };

        return hasData ? gridData : null;
    };
})();
