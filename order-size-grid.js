// ==========================================
// ORDER SIZE GRID - Per-Style (Total-First UX)
// ==========================================
// Total qty is prominent, tab goes total-to-total
// Size breakdown shown below each color in smaller text

(function() {
    var styleGridData = {};
    var sizeOrder = {"XXS":0,"XS":1,"S":2,"M":3,"L":4,"XL":5,"XXL":6,"2XL":6,"3XL":7,"4XL":8,"5XL":9,"1X":5,"2X":6,"3X":7,"0T":0,"2T":1,"3T":2,"4T":3,"5":4,"6":5,"6X":6,"7":7,"8":8,"10":9,"12":10,"14":11,"16":12};

    window.loadStyleSizeGrid = function(bs, poNumber) {
        var container = document.getElementById('orStyleSizeGrid_' + bs);
        if (!container) return;
        if (!poNumber || poNumber.length < 3) { container.innerHTML = ''; return; }

        container.innerHTML = '<div style="padding:0.5rem;color:#666;font-size:0.82rem">\u23f3 Loading sizes for ' + bs + '...</div>';

        var selectedProducts = [];
        if (typeof getOrderSelectedProducts === 'function' && typeof allProducts !== 'undefined') {
            getOrderSelectedProducts().forEach(function(id) {
                var p = allProducts.find(function(pr) { return pr.id === id; });
                if (p && p.style_id.split('-')[0] === bs) selectedProducts.push(p);
            });
        }

        fetch('/api/zoho/po-size-curve/' + encodeURIComponent(poNumber))
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.success && d.curve && d.curve.length > 0) {
                    buildStyleSizeGrid(bs, container, selectedProducts, d.curve, d.source);
                } else {
                    loadStyleProductSizes(bs, container, selectedProducts);
                }
            })
            .catch(function() { loadStyleProductSizes(bs, container, selectedProducts); });
    };

    function loadStyleProductSizes(bs, container, selectedProducts) {
        var styleIds = [];
        selectedProducts.forEach(function(p) { if (styleIds.indexOf(p.style_id) === -1) styleIds.push(p.style_id); });
        if (styleIds.length === 0) { container.innerHTML = '<div style="padding:0.5rem;color:#e65100;font-size:0.82rem">\u26a0 No size data for ' + bs + '.</div>'; return; }

        fetch('/api/product-sizes-for-so?styles=' + encodeURIComponent(styleIds.join(',')))
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (d.success && d.data && d.data.length > 0) {
                    var curve = [];
                    d.data.forEach(function(item) {
                        var totalInv = item.sizes.reduce(function(sum, s) { return sum + (s.left_to_sell || s.available_now || 0); }, 0);
                        var ratios = {}, sizes = {};
                        item.sizes.forEach(function(s) { var qty = s.left_to_sell || s.available_now || 0; sizes[s.size] = qty; ratios[s.size] = totalInv > 0 ? qty / totalInv : 0; });
                        curve.push({ base_style: item.style_id.split('-')[0], color: item.color, sizes: sizes, ratios: ratios, total_qty: totalInv, source: 'inventory' });
                    });
                    buildStyleSizeGrid(bs, container, selectedProducts, curve, 'inventory');
                } else { container.innerHTML = '<div style="padding:0.5rem;color:#e65100;font-size:0.82rem">\u26a0 No size data for ' + bs + '.</div>'; }
            })
            .catch(function(e) { container.innerHTML = '<div style="padding:0.5rem;color:#c62828;font-size:0.82rem">Error: ' + e.message + '</div>'; });
    }

    function buildStyleSizeGrid(bs, container, selectedProducts, curve, source) {
        var sizeRows = [];
        selectedProducts.forEach(function(p) {
            var imgUrl = (typeof getImageUrl === 'function' && p.image_url) ? getImageUrl(p.image_url) : (p.image_url || '');
            var colors = (p.colors || []).map(function(c) { return c.color_name || c; }).filter(Boolean);
            if (colors.length > 0) {
                colors.forEach(function(c) {
                    var colorName = typeof c === 'string' ? c : (c.color_name || 'Default');
                    var curveMatch = curve.find(function(cv) { return cv.base_style === p.base_style && cv.color.toLowerCase() === colorName.toLowerCase(); });
                    if (!curveMatch) curveMatch = curve.find(function(cv) { return cv.base_style === p.base_style; });
                    sizeRows.push({ style_id: p.style_id, base_style: p.base_style, name: p.name, color: colorName, curve: curveMatch, image: imgUrl });
                });
            } else {
                var curveMatch = curve.find(function(cv) { return cv.base_style === p.base_style; });
                sizeRows.push({ style_id: p.style_id, base_style: p.base_style, name: p.name, color: 'Default', curve: curveMatch, image: imgUrl });
            }
        });

        var allSizes = [];
        curve.forEach(function(cv) {
            Object.keys(cv.ratios || cv.sizes || {}).forEach(function(s) { if (allSizes.indexOf(s) === -1) allSizes.push(s); });
        });
        if (allSizes.length === 0) allSizes = ['OS'];
        allSizes.sort(function(a, b) { return (sizeOrder[a] !== undefined ? sizeOrder[a] : 50) - (sizeOrder[b] !== undefined ? sizeOrder[b] : 50); });

        styleGridData[bs] = { sizeRows: sizeRows, allSizes: allSizes, curve: curve };

        var sourceLabel = source === 'zoho' ? 'Import PO' : (source === 'local' ? 'local data' : 'inventory');
        var h = '';
        h += '<div style="font-size:0.72rem;color:#2e7d32;margin-bottom:0.25rem">\u2713 ' + sizeRows.length + ' color(s). Enter qty \u2014 sizes auto-distribute.</div>';

        // Compact color rows
        h += '<div style="border:1px solid #e0e0e0;border-radius:6px;overflow:hidden">';

        // Header
        h += '<div style="display:flex;align-items:center;padding:0.2rem 0.5rem;background:#1e3a5f;color:white;font-size:0.65rem;font-weight:600">';
        h += '<div style="width:28px"></div>';
        h += '<div style="flex:1">COLOR</div>';
        h += '<div style="width:80px;text-align:center">QTY</div>';
        h += '<div style="width:24px"></div>';
        h += '</div>';

        sizeRows.forEach(function(row, idx) {
            var tabIdx = (idx + 1) * 100;
            var bgColor = idx % 2 === 0 ? '#fff' : '#f8f9fb';

            h += '<div style="background:' + bgColor + '">';
            h += '<div style="display:flex;align-items:center;padding:0.15rem 0.5rem;border-bottom:1px solid #f0f0f0">';
            h += '<div style="width:28px;flex-shrink:0"><img src="' + (row.image || '') + '" onerror="this.style.display=\'none\'" style="width:24px;height:24px;object-fit:contain;border-radius:3px;background:#f0f0f0;display:block"></div>';
            h += '<div style="flex:1;font-size:0.74rem;color:#333"><span style="color:#0088c2;font-weight:600">' + row.style_id.split('-').pop() + '</span> ' + row.color + '</div>';
            h += '<div style="width:80px;text-align:center">';
            h += '<input type="number" id="orSzTotal_' + bs + '_' + idx + '" tabindex="' + tabIdx + '" value="" min="0" placeholder="0" ';
            h += 'style="width:65px;text-align:center;padding:0.2rem;border:2px solid #0088c2;border-radius:4px;font-size:0.88rem;font-weight:700;color:#1e3a5f;background:#f0f8ff" ';
            h += 'onchange="orStyleAutoDistribute(\'' + bs + '\',' + idx + ',parseInt(this.value)||0)" onkeyup="orStyleAutoDistribute(\'' + bs + '\',' + idx + ',parseInt(this.value)||0)">';
            h += '</div>';
            h += '<div style="width:24px;text-align:center">';
            h += '<button type="button" onclick="toggleSizeDetail(\'' + bs + '\',' + idx + ')" style="background:none;border:none;cursor:pointer;font-size:0.6rem;color:#999;padding:0.1rem" title="Size detail">\u25BC</button>';
            h += '</div>';
            h += '</div>';

            // Size detail (collapsed)
            h += '<div id="orSzDetail_' + bs + '_' + idx + '" style="display:none;padding:0.15rem 0.5rem 0.25rem;background:#fafbfc;border-bottom:1px solid #eee">';
            h += '<div style="display:flex;gap:0.15rem;flex-wrap:wrap;align-items:center">';
            allSizes.forEach(function(s) {
                var ratio = (row.curve && row.curve.ratios && row.curve.ratios[s]) ? row.curve.ratios[s] : 0;
                h += '<div style="text-align:center">';
                h += '<div style="font-size:0.58rem;color:#999;font-weight:600">' + s + '</div>';
                h += '<input type="number" id="orSz_' + bs + '_' + idx + '_' + s + '" value="" min="0" tabindex="-1" data-ratio="' + ratio + '" ';
                h += 'style="width:34px;text-align:center;padding:0.12rem;border:1px solid ' + (ratio > 0 ? '#b3d4fc' : '#ddd') + ';border-radius:3px;font-size:0.65rem;background:' + (ratio > 0 ? '#f0f7ff' : '#fff') + '" ';
                h += 'onchange="orStyleRecalcRow(\'' + bs + '\',' + idx + ')" onkeyup="orStyleRecalcRow(\'' + bs + '\',' + idx + ')">';
                h += '</div>';
            });
            h += '</div></div>';

            h += '</div>'; // end row wrapper
        });

        h += '</div>'; // end table

        // Grand total - compact
        h += '<div style="display:flex;justify-content:flex-end;align-items:center;gap:0.3rem;padding:0.2rem 0.5rem;margin-top:0.15rem">';
        h += '<span style="font-size:0.72rem;font-weight:600;color:#1e3a5f">Total:</span>';
        h += '<span id="orSzGrandTotal_' + bs + '" style="font-size:0.9rem;font-weight:700;color:#1e3a5f">0</span>';
        h += '</div>';

        container.innerHTML = h;
    }

    // Toggle size detail visibility
    window.toggleSizeDetail = function(bs, rowIdx) {
        var el = document.getElementById('orSzDetail_' + bs + '_' + rowIdx);
        if (el) el.style.display = el.style.display === 'none' ? '' : 'none';
    };

    // Auto-distribute total across sizes by ratio
    window.orStyleAutoDistribute = function(bs, rowIdx, totalQty) {
        var data = styleGridData[bs];
        if (!data) return;

        // Show size detail when they enter a qty
        if (totalQty > 0) {
            var detail = document.getElementById('orSzDetail_' + bs + '_' + rowIdx);
            if (detail) detail.style.display = '';
        }

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
            var allocated = 0, items = [];
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

    // Recalculate from individual sizes back to total
    window.orStyleRecalcRow = function(bs, rowIdx) {
        var data = styleGridData[bs];
        if (!data) return;

        var rowTotal = 0;
        data.allSizes.forEach(function(s) {
            var el = document.getElementById('orSz_' + bs + '_' + rowIdx + '_' + s);
            if (el && el.value) rowTotal += parseInt(el.value) || 0;
        });
        var totalEl = document.getElementById('orSzTotal_' + bs + '_' + rowIdx);
        if (totalEl && document.activeElement !== totalEl) {
            totalEl.value = rowTotal || '';
        }

        // Grand total
        var grandTotal = 0;
        for (var i = 0; i < data.sizeRows.length; i++) {
            var t = document.getElementById('orSzTotal_' + bs + '_' + i);
            if (t && t.value) grandTotal += parseInt(t.value) || 0;
        }
        var gtEl = document.getElementById('orSzGrandTotal_' + bs);
        if (gtEl) gtEl.textContent = grandTotal > 0 ? grandTotal.toLocaleString() : '0';
    };

    // Collect size grid data for a specific style
    window.getStyleSizeGridData = function(bs) {
        var data = styleGridData[bs];
        if (!data || !data.sizeRows || data.sizeRows.length === 0) return null;

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
                // Also check the total input directly
                var totalEl = document.getElementById('orSzTotal_' + bs + '_' + idx);
                var totalVal = totalEl ? (parseInt(totalEl.value) || 0) : 0;
                if (totalVal > 0) hasData = true;
                return { style_id: row.style_id, base_style: row.base_style, color: row.color, sizes: sizeBreakdown, total: totalVal || rowTotal };
            })
        };

        return hasData ? gridData : null;
    };
})();
