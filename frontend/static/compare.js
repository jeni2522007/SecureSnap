// Compare page client script – loaded as an external file (CSP-safe).
console.log("[compare.js] Script loaded");
/* ============================================================
   SecureSnap - image comparison workbench
   ============================================================ */

document.addEventListener("DOMContentLoaded", () => {
    console.log("[compare.js] DOMContentLoaded fired");
    "use strict";

    const firstInput = document.getElementById("firstInput");
    const secondInput = document.getElementById("secondInput");
    const compareBtn = document.getElementById("compareBtn");
    const status = document.getElementById("status");
    const progress = document.getElementById("progress");
    const result = document.getElementById("result");
    (function () {
        function init() {
            const firstInput = document.getElementById("firstInput");
            const secondInput = document.getElementById("secondInput");
            const compareBtn = document.getElementById("compareBtn");
            const status = document.getElementById("status");
            const progress = document.getElementById("progress");
            const result = document.getElementById("result");

            console.log("[compare.js] compareBtn:", compareBtn);

            if (!compareBtn) {
                console.error("[compare.js] #compareBtn not found – listener not attached");
                return;
            }

            compareBtn.addEventListener("click", async () => {
                console.log("[compare.js] Run comparison clicked");
                if (!firstInput.files.length || !secondInput.files.length) {
                    status.className = "status-line error";
                    status.textContent = "Both a reference image and a comparison image are required.";
                    if (!compareBtn) {
                        console.error("[compare] #compareBtn element not found in DOM");
                        return;
                    }

                    const form = new FormData();
                    form.append("first", firstInput.files[0]);
                    form.append("second", secondInput.files[0]);
                    compareBtn.addEventListener("click", async () => {
                        if (!firstInput || !firstInput.files.length || !secondInput || !secondInput.files.length) {
                            if (status) {
                                status.className = "status-line error";
                                status.textContent = "Both a reference image and a comparison image are required.";
                            }
                            return;
                        }

                        compareBtn.disabled = true;
                        compareBtn.textContent = "Comparing…";
                        status.className = "status-line";
                        status.textContent = "Aligning and measuring the two frames.";
                        progress.style.display = "block";
                        const form = new FormData();
                        form.append("first", firstInput.files[0]);
                        form.append("second", secondInput.files[0]);

                        try {
                            const data = await SS.request("/api/compare", {
                                method: "POST",
                                body: form
                            });
                            compareBtn.disabled = true;
                            compareBtn.textContent = "Comparing…";
                            if (status) {
                                status.className = "status-line";
                                status.textContent = "Aligning and measuring the two frames.";
                            }
                            if (progress) {
                                progress.style.display = "block";
                            }

                            const comparison = data.comparison;
                            try {
                                const data = await SS.request("/api/compare", {
                                    method: "POST",
                                    body: form
                                });

                                if (!comparison.available) {
                                    status.className = "status-line error";
                                    status.textContent = comparison.reason;
                                } else {
                                    status.className = "status-line success";
                                    status.textContent = "Comparison complete.";
                                    render(comparison);
                                    const comparison = data.comparison;

                                    if (!comparison || !comparison.available) {
                                        if (status) {
                                            status.className = "status-line error";
                                            status.textContent = (comparison && comparison.reason) || "Comparison unavailable.";
                                        }
                                    } else {
                                        if (status) {
                                            status.className = "status-line success";
                                            status.textContent = "Comparison complete.";
                                        }
                                        render(comparison);
                                    }

                                } catch (error) {
                                    if (status) {
                                        status.className = "status-line error";
                                        status.textContent = error.message;
                                    }
                                    if (typeof SS !== "undefined" && SS.toast) {
                                        SS.toast(error.message, "error");
                                    }
                                } finally {
                                    compareBtn.disabled = false;
                                    compareBtn.textContent = "Run comparison";
                                    if (progress) {
                                        progress.style.display = "none";
                                    }
                                }
                            });

                } catch (error) {
                    status.className = "status-line error";
                    status.textContent = error.message;
                    SS.toast(error.message, "error");
                } finally {
                    compareBtn.disabled = false;
                    compareBtn.textContent = "Run comparison";
                    progress.style.display = "none";
                }
            });
            function render(comparison) {
                if (!result) return;
                result.style.display = "block";

                function render(comparison) {
                    result.style.display = "block";
                    // Verdict banner
                    const holder = SS.clear(document.getElementById("verdictHolder"));
                    const banner = SS.el("div", "verdict-banner");
                    banner.style.margin = "20px 20px 0";

                    // Verdict banner.
                    const holder = SS.clear(document.getElementById("verdictHolder"));
                    const banner = SS.el("div", "verdict-banner");
                    banner.style.margin = "20px 20px 0";
                    const ssim = comparison.ssim;
                    const band = ssim >= 0.97 ? "low" : ssim >= 0.85 ? "medium" : "high";
                    banner.classList.add(band);

                    const ssim = comparison.ssim;
                    const band = ssim >= 0.97 ? "low" : ssim >= 0.85 ? "medium" : "high";
                    banner.classList.add(band);
                    const dial = SS.el("div", "risk-dial");
                    dial.style.setProperty("--value", Math.round(ssim * 100));
                    dial.style.setProperty(
                        "--dial-color",
                        ssim >= 0.97 ? "var(--good)" : ssim >= 0.85 ? "var(--medium)" : "var(--high)"
                    );
                    dial.appendChild(SS.el("span", null, (ssim * 100).toFixed(0)));

                    const dial = SS.el("div", "risk-dial");
                    dial.style.setProperty("--value", Math.round(ssim * 100));
                    dial.style.setProperty("--dial-color",
                        ssim >= 0.97 ? "var(--good)" : ssim >= 0.85 ? "var(--medium)" : "var(--high)");
                    dial.appendChild(SS.el("span", null, (ssim * 100).toFixed(0)));
                    const text = SS.el("div", "vb-text");
                    text.appendChild(SS.el("h3", null, "Structural similarity " + (ssim * 100).toFixed(1) + "%"));
                    text.appendChild(SS.el("p", null, comparison.interpretation));
                    banner.append(dial, text);
                    holder.appendChild(banner);

                    const text = SS.el("div", "vb-text");
                    text.appendChild(SS.el("h3", null, "Structural similarity " + (ssim * 100).toFixed(1) + "%"));
                    text.appendChild(SS.el("p", null, comparison.interpretation));
                    banner.append(dial, text);
                    holder.appendChild(banner);
                    // Summary tab
                    const summary = SS.clear(document.getElementById("tab-summary"));
                    const metrics = SS.el("div", "metric-grid");
                    metrics.appendChild(SS.metric("SSIM", ssim.toFixed(4), "structural similarity index"));
                    metrics.appendChild(SS.metric("Correlation", comparison.correlation.toFixed(4), "pixel correlation"));
                    metrics.appendChild(SS.metric("Changed pixels", SS.pct(comparison.changed_pixel_ratio), "of the frame"));
                    metrics.appendChild(SS.metric("Shift", comparison.estimated_shift.x + ", " + comparison.estimated_shift.y, "estimated translation"));
                    summary.appendChild(metrics);

                    // Summary.
                    const summary = SS.clear(document.getElementById("tab-summary"));
                    const metrics = SS.el("div", "metric-grid");
                    metrics.appendChild(SS.metric("SSIM", ssim.toFixed(4), "structural similarity index"));
                    metrics.appendChild(SS.metric("Correlation", comparison.correlation.toFixed(4), "pixel correlation"));
                    metrics.appendChild(SS.metric("Changed pixels", SS.pct(comparison.changed_pixel_ratio), "of the frame"));
                    metrics.appendChild(SS.metric("Shift", comparison.estimated_shift.x + ", " + comparison.estimated_shift.y, "estimated translation"));
                    summary.appendChild(metrics);
                    const details = SS.el("div", "card");
                    details.style.marginTop = "18px";
                    const head = SS.el("div", "card-head");
                    head.appendChild(SS.el("h3", null, "Pair details"));
                    details.appendChild(head);
                    const body = SS.el("div", "card-body tight");
                    body.appendChild(SS.dl([
                        ["Reference dimensions", comparison.first.width + " × " + comparison.first.height],
                        ["Comparison dimensions", comparison.second.width + " × " + comparison.second.height],
                        ["Same dimensions", comparison.dimension_change.same_dimensions ? "Yes" : "No"],
                        ["Width change", comparison.dimension_change.width_delta + " px"],
                        ["Height change", comparison.dimension_change.height_delta + " px"],
                        ["Changed pixels", comparison.changed_pixels + " of " + comparison.total_pixels]
                    ]));
                    details.appendChild(body);
                    summary.appendChild(details);

                    const details = SS.el("div", "card");
                    details.style.marginTop = "18px";
                    const head = SS.el("div", "card-head");
                    head.appendChild(SS.el("h3", null, "Pair details"));
                    details.appendChild(head);
                    const body = SS.el("div", "card-body tight");
                    body.appendChild(SS.dl([
                        ["Reference dimensions", comparison.first.width + " × " + comparison.first.height],
                        ["Comparison dimensions", comparison.second.width + " × " + comparison.second.height],
                        ["Same dimensions", comparison.dimension_change.same_dimensions ? "Yes" : "No"],
                        ["Width change", comparison.dimension_change.width_delta + " px"],
                        ["Height change", comparison.dimension_change.height_delta + " px"],
                        ["Changed pixels", comparison.changed_pixels + " of " + comparison.total_pixels]
                    ]));
                    details.appendChild(body);
                    summary.appendChild(details);
                    if (comparison.difference_regions && comparison.difference_regions.length) {
                        const regionCard = SS.el("div", "card");
                        regionCard.style.marginTop = "18px";
                        const regionHead = SS.el("div", "card-head");
                        regionHead.appendChild(SS.el("h3", null, "Regions of divergence"));
                        regionCard.appendChild(regionHead);
                        const regionBody = SS.el("div", "card-body tight");

                        if (comparison.difference_regions && comparison.difference_regions.length) {
                            const regionCard = SS.el("div", "card");
                            regionCard.style.marginTop = "18px";
                            const regionHead = SS.el("div", "card-head");
                            regionHead.appendChild(SS.el("h3", null, "Regions of divergence"));
                            regionCard.appendChild(regionHead);
                            const regionBody = SS.el("div", "card-body tight");
                            const list = SS.el("dl", "dl");
                            comparison.difference_regions.forEach((region, index) => {
                                const row = SS.el("div", "dl-row");
                                row.appendChild(SS.el("dt", null, "Region " + (index + 1)));
                                row.appendChild(SS.el("dd", "mono",
                                    `x${region.x} y${region.y} · ${region.width}×${region.height}`));
                                list.appendChild(row);
                            });
                            regionBody.appendChild(list);
                            regionCard.appendChild(regionBody);
                            summary.appendChild(regionCard);
                        }

                        const list = SS.el("dl", "dl");
                        comparison.difference_regions.forEach((region, index) => {
                            const row = SS.el("div", "dl-row");
                            row.appendChild(SS.el("dt", null, "Region " + (index + 1)));
                            row.appendChild(SS.el("dd", "mono",
                                `x${region.x} y${region.y} · ${region.width}×${region.height}`));
                            list.appendChild(row);
                        });
                        regionBody.appendChild(list);
                        regionCard.appendChild(regionBody);
                        summary.appendChild(regionCard);
                    }
                    // Maps tab
                    const maps = SS.clear(document.getElementById("tab-maps"));
                    const grid = SS.el("div", "grid grid-2");

                    // Maps.
                    const maps = SS.clear(document.getElementById("tab-maps"));
                    const grid = SS.el("div", "grid grid-2");
                    const diffCard = SS.el("div", "card");
                    const diffHead = SS.el("div", "card-head");
                    diffHead.appendChild(SS.el("h3", null, "Difference map"));
                    diffCard.appendChild(diffHead);
                    const diffBody = SS.el("div", "card-body");
                    const diffPreview = SS.el("div", "preview");
                    diffPreview.appendChild(SS.el("h4", null, "Absolute difference"));
                    const diffImage = SS.el("img");
                    diffImage.src = "/analysis/compare/" + comparison.difference_map;
                    diffPreview.appendChild(diffImage);
                    diffBody.appendChild(diffPreview);
                    diffCard.appendChild(diffBody);
                    grid.appendChild(diffCard);

                    const diffCard = SS.el("div", "card");
                    const diffHead = SS.el("div", "card-head");
                    diffHead.appendChild(SS.el("h3", null, "Difference map"));
                    diffCard.appendChild(diffHead);
                    const diffBody = SS.el("div", "card-body");
                    const diffPreview = SS.el("div", "preview");
                    diffPreview.appendChild(SS.el("h4", null, "Absolute difference"));
                    const diffImage = SS.el("img");
                    diffImage.src = "/analysis/compare/" + comparison.difference_map;
                    diffPreview.appendChild(diffImage);
                    diffBody.appendChild(diffPreview);
                    diffCard.appendChild(diffBody);
                    grid.appendChild(diffCard);
                    const ssimCard = SS.el("div", "card");
                    const ssimHead = SS.el("div", "card-head");
                    ssimHead.appendChild(SS.el("h3", null, "Similarity map"));
                    ssimCard.appendChild(ssimHead);
                    const ssimBody = SS.el("div", "card-body");
                    const ssimPreview = SS.el("div", "preview");
                    ssimPreview.appendChild(SS.el("h4", null, "Divergence from the reference"));
                    const ssimImage = SS.el("img");
                    ssimImage.src = "/analysis/compare/" + comparison.similarity_map;
                    ssimPreview.appendChild(ssimImage);
                    ssimBody.appendChild(ssimPreview);
                    ssimCard.appendChild(ssimBody);
                    grid.appendChild(ssimCard);

                    const ssimCard = SS.el("div", "card");
                    const ssimHead = SS.el("div", "card-head");
                    ssimHead.appendChild(SS.el("h3", null, "Similarity map"));
                    ssimCard.appendChild(ssimHead);
                    const ssimBody = SS.el("div", "card-body");
                    const ssimPreview = SS.el("div", "preview");
                    ssimPreview.appendChild(SS.el("h4", null, "Divergence from the reference"));
                    const ssimImage = SS.el("img");
                    ssimImage.src = "/analysis/compare/" + comparison.similarity_map;
                    ssimPreview.appendChild(ssimImage);
                    ssimBody.appendChild(ssimPreview);
                    ssimCard.appendChild(ssimBody);
                    grid.appendChild(ssimCard);
                    maps.appendChild(grid);
                    SS.initTabs(result);
                    result.scrollIntoView({ behavior: "smooth", block: "start" });
                }
            }

            maps.appendChild(grid);
            SS.initTabs(result);
            result.scrollIntoView({ behavior: "smooth", block: "start" });
            // Initialize when DOM is ready or immediately if already loaded
            if (document.readyState === "loading") {
                document.addEventListener("DOMContentLoaded", init);
            } else {
                init();
            }
        });

})();
