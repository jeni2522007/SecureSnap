/* ============================================================
   SecureSnap - analysis workbench
   ============================================================ */

"use strict";

(function () {

    const state = {
        file: null,
        result: null
    };

    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("fileInput");
    const filelist = document.getElementById("filelist");
    const statusLine = document.getElementById("statusLine");
    const progressTrack = document.getElementById("progressTrack");
    const progressFill = document.getElementById("progressFill");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const resetBtn = document.getElementById("resetBtn");
    const results = document.getElementById("results");
    const saveCheckbox = document.getElementById("saveEvidence");
    const registerFields = document.getElementById("registerFields");

    /* ---------- File selection ---------- */

    function setFile(file) {
        if (!file) return;
        state.file = file;

        const list = SS.clear(filelist);
        const item = SS.el("div", "fileitem");
        const name = SS.el("span", "name", file.name);
        const size = SS.el("span", "size", SS.bytes(file.size));
        item.append(name, size);
        list.appendChild(item);

        statusLine.className = "status-line";
        statusLine.textContent = file.name + " selected.";
    }

    fileInput.addEventListener("change", () => setFile(fileInput.files[0]));

    ["dragenter", "dragover"].forEach((eventName) => {
        dropzone.addEventListener(eventName, (event) => {
            event.preventDefault();
            dropzone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach((eventName) => {
        dropzone.addEventListener(eventName, (event) => {
            event.preventDefault();
            dropzone.classList.remove("dragover");
        });
    });

    dropzone.addEventListener("drop", (event) => {
        const files = event.dataTransfer.files;
        if (files.length) {
            fileInput.files = files;
            setFile(files[0]);
        }
    });

    saveCheckbox.addEventListener("change", () => {
        registerFields.style.display = saveCheckbox.checked ? "block" : "none";
    });

    resetBtn.addEventListener("click", () => {
        fileInput.value = "";
        state.file = null;
        state.result = null;
        SS.clear(filelist);
        results.style.display = "none";
        statusLine.className = "status-line";
        statusLine.textContent = "";
        progressTrack.style.display = "none";
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = "Run examination";
    });

    /* ---------- Run ---------- */

    analyzeBtn.addEventListener("click", run);

    async function run() {
        if (!state.file) {
            statusLine.className = "status-line error";
            statusLine.textContent = "Select a file before running the examination.";
            return;
        }

        if (saveCheckbox.checked && !document.getElementById("caseRef").value.trim()) {
            statusLine.className = "status-line error";
            statusLine.textContent = "A case reference is required to register evidence.";
            return;
        }

        const form = new FormData();
        form.append("image", state.file);
        form.append("save", saveCheckbox.checked ? "true" : "false");

        if (saveCheckbox.checked) {
            form.append("case_ref", document.getElementById("caseRef").value.trim());
            form.append("exhibit_ref", document.getElementById("exhibitRef").value.trim());
            form.append("title", document.getElementById("title").value.trim());
            form.append("description", document.getElementById("description").value.trim());
            form.append("source", document.getElementById("source").value.trim());
            form.append("collected_by", document.getElementById("collectedBy").value.trim());
        }

        analyzeBtn.disabled = true;
        analyzeBtn.textContent = "Examining…";
        statusLine.className = "status-line";
        statusLine.textContent = "Running the forensic pipeline. Large images take a moment.";
        progressTrack.style.display = "block";
        progressFill.className = "progress-fill indeterminate";

        try {
            const data = await SS.request("/api/analyze", {
                method: "POST",
                body: form
            });

            state.result = data;
            render(data);

            progressFill.className = "progress-fill";
            progressFill.style.width = "100%";
            statusLine.className = "status-line success";
            statusLine.textContent = "Examination complete.";

            if (data.evidence) {
                const duplicates = data.evidence.duplicate_count;
                SS.toast(
                    "Registered as evidence #" + data.evidence.id +
                    (duplicates ? " — identical copy already on file." : "."),
                    duplicates ? "error" : "success"
                );
            }

        } catch (error) {
            statusLine.className = "status-line error";
            statusLine.textContent = error.message;
            progressTrack.style.display = "none";
            SS.toast(error.message, "error");
        } finally {
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = "Run examination";
        }
    }

    /* ---------- Rendering ---------- */

    function render(data) {
        const analysis = data.analysis;

        results.style.display = "block";
        renderVerdict(analysis);
        renderOverview(analysis, data);
        renderFindings(analysis);
        renderMetadata(analysis);
        renderPixels(analysis);
        renderHidden(analysis);
        renderContent(analysis);
        renderRules(data);
        renderFingerprint(analysis, data);

        SS.initTabs(results);

        const downloadBtn = document.getElementById("downloadJsonBtn");
        const reportBtn = document.getElementById("reportBtn");

        if (data.evidence) {
            downloadBtn.style.display = "inline-flex";
            reportBtn.style.display = "inline-flex";
            downloadBtn.href = "/api/report/" + data.evidence.id + "/json";
            reportBtn.href = "/report/" + data.evidence.id;
        } else {
            downloadBtn.style.display = "none";
            reportBtn.style.display = "none";
        }

        results.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function renderVerdict(analysis) {
        const holder = SS.clear(document.getElementById("verdictHolder"));
        const summary = analysis.summary;
        const band = SS.verdictBand(summary.score);

        const banner = SS.el("div", "verdict-banner " + band);
        banner.style.margin = "20px 20px 0";

        const dial = SS.el("div", "risk-dial");
        dial.style.setProperty("--value", summary.score);
        dial.style.setProperty("--dial-color", SS.riskColour(summary.score));
        const value = SS.el("span", null, summary.score);
        dial.appendChild(value);

        const text = SS.el("div", "vb-text");
        text.appendChild(SS.el("h3", null, summary.verdict));
        text.appendChild(SS.el("p", null, summary.reasoning));

        const counts = SS.el("div");
        counts.style.marginTop = "8px";
        counts.style.display = "flex";
        counts.style.gap = "8px";
        counts.style.flexWrap = "wrap";

        const severities = Object.keys(summary.by_severity || {});
        if (severities.length) {
            severities.forEach((severity) => {
                counts.appendChild(SS.badge(
                    summary.by_severity[severity] + " " + severity.toLowerCase(),
                    severity
                ));
            });
        } else {
            counts.appendChild(SS.badge("no findings", "good"));
        }
        text.appendChild(counts);

        banner.append(dial, text);
        holder.appendChild(banner);
    }

    function renderOverview(analysis, data) {
        const panel = SS.clear(document.getElementById("tab-overview"));
        const summary = analysis.summary;

        const metrics = SS.el("div", "metric-grid");
        metrics.style.marginBottom = "20px";

        metrics.appendChild(SS.metric(
            "Risk score", summary.score + " / 100", summary.risk_band + " band"));
        metrics.appendChild(SS.metric(
            "Findings", summary.finding_count, "across all techniques"));
        metrics.appendChild(SS.metric(
            "Policy rules triggered", (analysis.rules || {}).triggered_count || 0,
            "from the configured rule set"));
        metrics.appendChild(SS.metric(
            "File size", SS.bytes(data.fingerprints.size_bytes), "as submitted"));
        metrics.appendChild(SS.metric(
            "Format", analysis.format.format || "Unknown", analysis.format.category || ""));
        metrics.appendChild(SS.metric(
            "GPS", analysis.metadata.gps && analysis.metadata.gps.latitude
                ? "Present" : "Absent",
            analysis.metadata.gps && analysis.metadata.gps.latitude
                ? "Location recoverable" : "No coordinates embedded"));

        panel.appendChild(metrics);

        // Identity summary.
        const identityCard = SS.el("div", "card");
        identityCard.style.marginBottom = "18px";
        const identityHead = SS.el("div", "card-head");
        identityHead.appendChild(SS.el("h3", null, "File identity"));
        identityCard.appendChild(identityHead);

        const identityBody = SS.el("div", "card-body tight");
        const identity = analysis.identity;

        identityBody.appendChild(SS.dl([
            ["Claimed extension", identity.claimed_extension || "none", true],
            ["Actual content", identity.detected.format],
            ["Detected extension", identity.detected.extension || "-", true],
            ["MIME type", identity.detected.mime, true],
            ["Detection basis", identity.detected.basis],
            ["Embedded payloads",
                (identity.detected.embedded_payloads || []).length
                    ? identity.detected.embedded_payloads.map(p => p.type).join(", ")
                    : "None detected"],
            ["Overall entropy",
                analysis.entropy.overall_bits_per_byte + " bits/byte"],
        ]));

        identityCard.appendChild(identityBody);
        panel.appendChild(identityCard);

        // Top findings preview.
        const topCard = SS.el("div", "card");
        const topHead = SS.el("div", "card-head");
        topHead.appendChild(SS.el("h3", null, "Principal findings"));
        const topLink = SS.el("button", "btn btn-ghost btn-sm", "See all");
        topLink.addEventListener("click", () => {
            const tab = document.querySelector('.tab[data-target="tab-findings"]');
            if (tab) tab.click();
        });
        topHead.appendChild(topLink);
        topCard.appendChild(topHead);

        const topBody = SS.el("div", "card-body tight");

        if (!analysis.findings.length) {
            topBody.appendChild(SS.el(
                "p", null,
                "No material indicators were produced by the pipeline."
            ));
            topBody.lastChild.style.color = "var(--ink-faint)";
            topBody.lastChild.style.fontSize = "13.5px";
        } else {
            analysis.findings.slice(0, 4).forEach((finding) => {
                topBody.appendChild(findingNode(finding));
            });
        }

        topCard.appendChild(topBody);
        panel.appendChild(topCard);
    }

    function findingNode(finding) {
        const node = SS.el("div", "finding sev-" + finding.severity);

        const head = SS.el("div", "finding-head");
        head.appendChild(SS.badge(finding.severity, finding.severity));
        head.appendChild(SS.el("strong", null, finding.title));
        node.appendChild(head);

        node.appendChild(SS.el("p", null, finding.explanation));

        if (finding.source) {
            node.appendChild(SS.el("div", "source", "Source: " + finding.source));
        }

        return node;
    }

    function renderFindings(analysis) {
        const panel = SS.clear(document.getElementById("tab-findings"));

        if (!analysis.findings.length) {
            const note = SS.el("p", null,
                "The pipeline produced no findings against this file. This means " +
                "nothing tested was contradicted - it is not a positive certificate " +
                "of authenticity.");
            note.style.color = "var(--ink-soft)";
            panel.appendChild(note);
            return;
        }

        analysis.findings.forEach((finding) => {
            panel.appendChild(findingNode(finding));
        });
    }

    function renderMetadata(analysis) {
        const panel = SS.clear(document.getElementById("tab-metadata"));
        const meta = analysis.metadata;

        const grid = SS.el("div", "grid grid-2");

        // Device and capture.
        const device = SS.el("div", "card");
        const deviceHead = SS.el("div", "card-head");
        deviceHead.appendChild(SS.el("h3", null, "Device &amp; capture"));
        device.appendChild(deviceHead);
        const deviceBody = SS.el("div", "card-body tight");

        const camera = meta.camera || {};
        const timestamps = meta.timestamps || {};

        deviceBody.appendChild(SS.dl([
            ["Camera make", camera.make],
            ["Camera model", camera.model],
            ["Lens", camera.lens],
            ["Body serial", camera.body_serial],
            ["Software", camera.software],
            ["Original filename", camera.description],
            ["Captured (original)", timestamps.datetime_original],
            ["Digitised", timestamps.datetime_digitized],
            ["Modified", timestamps.datetime],
            ["Time zone offset", timestamps.offset_time_original || timestamps.offset_time],
        ]));

        device.appendChild(deviceBody);
        grid.appendChild(device);

        // Location.
        const location = SS.el("div", "card");
        const locationHead = SS.el("div", "card-head");
        locationHead.appendChild(SS.el("h3", null, "Location"));
        location.appendChild(locationHead);
        const locationBody = SS.el("div", "card-body tight");

        const gps = meta.gps || {};
        locationBody.appendChild(SS.dl([
            ["Latitude", gps.latitude !== undefined ? gps.latitude : null],
            ["Longitude", gps.longitude !== undefined ? gps.longitude : null],
            ["Altitude (m)", gps.altitude_metres],
            ["GPS timestamp", gps.GPSDateStamp],
        ]));

        if (gps.map_url) {
            const link = SS.el("a", "btn btn-ghost btn-sm", "Open in OpenStreetMap");
            link.href = gps.map_url;
            link.target = "_blank";
            link.rel = "noopener";
            link.style.marginTop = "12px";
            locationBody.appendChild(link);
        }

        location.appendChild(locationBody);
        grid.appendChild(location);

        panel.appendChild(grid);

        // Anomalies.
        const anomalyCard = SS.el("div", "card");
        anomalyCard.style.marginTop = "18px";
        const anomalyHead = SS.el("div", "card-head");
        anomalyHead.appendChild(SS.el("h3", null, "Contradictions &amp; anomalies"));
        anomalyCard.appendChild(anomalyHead);
        const anomalyBody = SS.el("div", "card-body tight");

        const anomalies = meta.anomalies || [];
        if (!anomalies.length) {
            const note = SS.el("p", null,
                "The metadata contains no internal contradictions.");
            note.style.color = "var(--ink-soft)";
            anomalyBody.appendChild(note);
        } else {
            anomalies.forEach((anomaly) => {
                anomalyBody.appendChild(findingNode({
                    severity: anomaly.severity,
                    title: anomaly.title,
                    explanation: anomaly.explanation,
                    source: "metadata forensics"
                }));
            });
        }

        anomalyCard.appendChild(anomalyBody);
        panel.appendChild(anomalyCard);

        // XMP.
        if (meta.xmp && Object.keys(meta.xmp).length) {
            const xmpCard = SS.el("div", "card");
            xmpCard.style.marginTop = "18px";
            const xmpHead = SS.el("div", "card-head");
            xmpHead.appendChild(SS.el("h3", null, "XMP packet"));
            xmpCard.appendChild(xmpHead);
            const xmpBody = SS.el("div", "card-body tight");

            const rows = [];
            Object.entries(meta.xmp).forEach(([key, value]) => {
                if (key === "history_actions") {
                    rows.push(["Editing history", value.join(" | ")]);
                } else if (typeof value === "object") {
                    Object.entries(value).forEach(([inner, innerValue]) => {
                        rows.push([key + "." + inner, innerValue]);
                    });
                } else {
                    rows.push([key, value]);
                }
            });
            xmpBody.appendChild(SS.dl(rows));
            xmpCard.appendChild(xmpBody);
            panel.appendChild(xmpCard);
        }
    }

    function renderPixels(analysis) {
        const panel = SS.clear(document.getElementById("tab-pixels"));

        const ela = analysis.ela || {};
        const measurements = ela.measurements || {};

        const elaCard = SS.el("div", "card");
        const elaHead = SS.el("div", "card-head");
        elaHead.appendChild(SS.el("h3", null, "Error level analysis"));
        elaCard.appendChild(elaHead);
        const elaBody = SS.el("div", "card-body");

        const elaMetrics = SS.el("div", "metric-grid");
        elaMetrics.appendChild(SS.metric(
            "Mean error", measurements.mean_error !== undefined
                ? measurements.mean_error : "-", "compression residual"));
        elaMetrics.appendChild(SS.metric(
            "Hot block ratio", measurements.hot_block_ratio !== undefined
                ? SS.pct(measurements.hot_block_ratio) : "-", "above 2σ threshold"));
        elaMetrics.appendChild(SS.metric(
            "Error uniformity", measurements.error_uniformity !== undefined
                ? measurements.error_uniformity : "-", "0 = perfectly uniform"));
        elaMetrics.appendChild(SS.metric(
            "Candidate regions", (measurements.hot_regions || []).length,
                "clustered hot blocks"));
        elaBody.appendChild(elaMetrics);

        if (ela.heatmap) {
            const preview = SS.el("div", "preview");
            preview.style.marginTop = "16px";
            preview.style.maxWidth = "420px";
            preview.appendChild(SS.el("h4", null, "ELA heat map"));
            const image = SS.el("img");
            image.src = "/analysis/" + folderOf(analysis) + "/" + ela.heatmap;
            image.alt = "Error level analysis heat map";
            preview.appendChild(image);
            preview.appendChild(SS.el(
                "div", "cap",
                "Brighter areas carry a compression error unlike their surroundings."
            ));
            elaBody.appendChild(preview);
        }

        (ela.notes || []).forEach((note) => {
            const p = SS.el("p", null, note);
            p.style.cssText = "font-size:13px;color:var(--ink-soft);margin:10px 0 0";
            elaBody.appendChild(p);
        });

        elaCard.appendChild(elaBody);
        panel.appendChild(elaCard);

        // Copy-move.
        const copyMove = analysis.copy_move || {};
        const copyCard = SS.el("div", "card");
        copyCard.style.marginTop = "18px";
        const copyHead = SS.el("div", "card-head");
        copyHead.appendChild(SS.el("h3", null, "Copy-move (cloning) detection"));
        copyCard.appendChild(copyHead);
        const copyBody = SS.el("div", "card-body");

        if (!copyMove.available) {
            const note = SS.el("p", null, copyMove.reason || "Not available.");
            note.style.color = "var(--ink-faint)";
            copyBody.appendChild(note);
        } else {
            const copyMetrics = SS.el("div", "metric-grid");
            copyMetrics.appendChild(SS.metric(
                "Blocks compared", copyMove.blocks_compared, "DCT perceptual hashes"));
            copyMetrics.appendChild(SS.metric(
                "Matching pairs", copyMove.match_count, "hamming distance ≤ 2"));
            copyMetrics.appendChild(SS.metric(
                "Duplicated regions", (copyMove.regions || []).length, "clustered matches"));
            copyMetrics.appendChild(SS.metric(
                "Duplicated area", SS.pct(copyMove.duplicated_area_ratio),
                "of the frame"));
            copyBody.appendChild(copyMetrics);

            if (copyMove.match_map) {
                const preview = SS.el("div", "preview");
                preview.style.marginTop = "16px";
                preview.style.maxWidth = "420px";
                preview.appendChild(SS.el("h4", null, "Duplicate region map"));
                const image = SS.el("img");
                image.src = "/analysis/" + folderOf(analysis) + "/" + copyMove.match_map;
                image.alt = "Copy-move match map";
                preview.appendChild(image);
                copyBody.appendChild(preview);
            }
        }
        copyCard.appendChild(copyBody);
        panel.appendChild(copyCard);

        // Noise and resampling.
        const noise = analysis.noise || {};
        const resampling = analysis.resampling || {};

        const grid = SS.el("div", "grid grid-2");
        grid.style.marginTop = "18px";

        const noiseCard = SS.el("div", "card");
        const noiseHead = SS.el("div", "card-head");
        noiseHead.appendChild(SS.el("h3", null, "Noise &amp; splice boundaries"));
        noiseCard.appendChild(noiseHead);
        const noiseBody = SS.el("div", "card-body tight");
        noiseBody.appendChild(SS.dl([
            ["Global noise level", noise.global_noise_std],
            ["Lowest block", noise.noise_std_min],
            ["Highest block", noise.noise_std_max],
            ["Discontinuities", noise.discontinuity_count],
            ["Grid", noise.grid ? noise.grid.join(" × ") : null],
        ]));
        noiseCard.appendChild(noiseBody);
        grid.appendChild(noiseCard);

        const resampleCard = SS.el("div", "card");
        const resampleHead = SS.el("div", "card-head");
        resampleHead.appendChild(SS.el("h3", null, "Resampling"));
        resampleCard.appendChild(resampleHead);
        const resampleBody = SS.el("div", "card-body tight");
        resampleBody.appendChild(SS.dl([
            ["Upscaling suspected",
                resampling.upscaling_suspected ? "Yes" : "No"],
            ["High-frequency energy",
                resampling.high_frequency_energy_ratio],
            ["Spectral periodicity", resampling.spectrum_periodicity],
            ["Dimensions", resampling.dimensions
                ? resampling.dimensions.join(" × ") : null],
        ]));
        if (resampling.interpretation) {
            const p = SS.el("p", null, resampling.interpretation);
            p.style.cssText = "font-size:12.5px;color:var(--ink-soft);margin:12px 0 0";
            resampleBody.appendChild(p);
        }
        resampleCard.appendChild(resampleBody);
        grid.appendChild(resampleCard);

        panel.appendChild(grid);
    }

    function renderHidden(analysis) {
        const panel = SS.clear(document.getElementById("tab-hidden"));
        const stego = analysis.steganography || {};

        const card = SS.el("div", "card");
        const head = SS.el("div", "card-head");
        head.appendChild(SS.el("h3", null, "Hidden data (steganography)"));
        card.appendChild(head);
        const body = SS.el("div", "card-body");

        if (!stego.available) {
            const note = SS.el("p", null, stego.reason || "Not available.");
            note.style.color = "var(--ink-faint)";
            body.appendChild(note);
        } else {
            const metrics = SS.el("div", "metric-grid");
            metrics.appendChild(SS.metric(
                "Verdict", stego.suspicious ? "Suspicious" : "Clean",
                stego.suspicious ? "statistical evidence of embedding"
                                  : "no embedding detected"));
            metrics.appendChild(SS.metric(
                "LSB plane entropy", stego.lsb_plane_entropy,
                "8.0 would be fully random"));
            metrics.appendChild(SS.metric(
                "Suspicious channels",
                (stego.suspicious_channels || []).length
                    ? stego.suspicious_channels.join(", ") : "none"));
            metrics.appendChild(SS.metric(
                "Appended payload", stego.appended_payload ? "Yes" : "No",
                "data after the image stream"));
            body.appendChild(metrics);

            if (stego.interpretation) {
                const p = SS.el("p", null, stego.interpretation);
                p.style.cssText = "font-size:13.5px;color:var(--ink-soft);margin:14px 0 0";
                body.appendChild(p);
            }

            if (stego.lsb_plane) {
                const preview = SS.el("div", "preview");
                preview.style.marginTop = "16px";
                preview.style.maxWidth = "420px";
                preview.appendChild(SS.el("h4", null, "Least significant bit plane"));
                const image = SS.el("img");
                image.src = "/analysis/" + folderOf(analysis) + "/" + stego.lsb_plane;
                image.alt = "Least significant bit plane";
                preview.appendChild(image);
                preview.appendChild(SS.el(
                    "div", "cap",
                    "Visible structure means the plane carries image detail; " +
                    "uniform noise suggests embedded data."
                ));
                body.appendChild(preview);
            }
        }

        card.appendChild(body);
        panel.appendChild(card);

        // Container notes.
        if (stego.container_notes && stego.container_notes.length) {
            const noteCard = SS.el("div", "card");
            noteCard.style.marginTop = "18px";
            const noteHead = SS.el("div", "card-head");
            noteHead.appendChild(SS.el("h3", null, "Container structure"));
            noteCard.appendChild(noteHead);
            const noteBody = SS.el("div", "card-body tight");
            stego.container_notes.forEach((note) => {
                const p = SS.el("p", null, note);
                p.style.cssText = "font-size:13.5px;color:var(--ink-soft);margin:0 0 8px";
                noteBody.appendChild(p);
            });
            noteCard.appendChild(noteBody);
            panel.appendChild(noteCard);
        }
    }

    function renderContent(analysis) {
        const panel = SS.clear(document.getElementById("tab-content"));
        const classification = analysis.classification || {};

        const card = SS.el("div", "card");
        const head = SS.el("div", "card-head");
        head.appendChild(SS.el("h3", null, "Content classification"));
        card.appendChild(head);
        const body = SS.el("div", "card-body");

        if (!classification.available) {
            const note = SS.el("p", null,
                classification.reason || "The classifier is not available.");
            note.style.color = "var(--ink-faint)";
            body.appendChild(note);
        } else {
            const predictions = classification.predictions || [];

            predictions.forEach((prediction) => {
                const row = SS.el("div");
                row.style.marginBottom = "12px";

                const top = SS.el("div");
                top.style.cssText = "display:flex;justify-content:space-between;font-size:13.5px";
                top.appendChild(SS.el("strong", null, prediction.label));
                top.appendChild(SS.el("span", null, prediction.confidence + "%"));
                row.appendChild(top);

                const bar = SS.el("div", "bar");
                const fill = SS.el("span");
                fill.style.width = Math.min(100, prediction.confidence) + "%";
                bar.appendChild(fill);
                row.appendChild(bar);

                body.appendChild(row);
            });

            body.appendChild(SS.dl([
                ["Scene likelihood", classification.scene_likelihood],
                ["Tags", (classification.tags || []).join(", ")],
            ]));
        }

        card.appendChild(body);
        panel.appendChild(card);

        const warnings = classification.consistency_warnings || [];
        if (warnings.length) {
            const warnCard = SS.el("div", "card");
            warnCard.style.marginTop = "18px";
            const warnHead = SS.el("div", "card-head");
            warnHead.appendChild(SS.el("h3", null, "Metadata contradictions"));
            warnCard.appendChild(warnHead);
            const warnBody = SS.el("div", "card-body tight");
            warnings.forEach((warning) => {
                warnBody.appendChild(findingNode({
                    severity: warning.severity,
                    title: warning.title,
                    explanation: warning.explanation,
                    source: "content classification"
                }));
            });
            warnCard.appendChild(warnBody);
            panel.appendChild(warnCard);
        }
    }

    function renderRules(data) {
        const panel = SS.clear(document.getElementById("tab-rules"));
        const rules = data.rules || {};
        const triggered = rules.triggered || [];

        const summary = SS.el("div", "metric-grid");
        summary.style.marginBottom = "18px";
        summary.appendChild(SS.metric(
            "Rules evaluated", rules.evaluated || 0, "from the policy set"));
        summary.appendChild(SS.metric(
            "Rules triggered", triggered.length, "matched by the evidence"));
        summary.appendChild(SS.metric(
            "Parse errors", (rules.errors || []).length, "rules that could not run"));
        panel.appendChild(summary);

        if (rules.errors && rules.errors.length) {
            const errorCard = SS.el("div", "card");
            errorCard.style.marginBottom = "18px";
            const errorHead = SS.el("div", "card-head");
            errorHead.appendChild(SS.el("h3", null, "Rules that could not be evaluated"));
            errorCard.appendChild(errorHead);
            const errorBody = SS.el("div", "card-body tight");
            rules.errors.forEach((error) => {
                const p = SS.el("p", null, error.name + ": " + error.error);
                p.style.cssText = "font-size:13px;color:var(--critical);margin:0 0 6px";
                errorBody.appendChild(p);
            });
            errorCard.appendChild(errorBody);
            panel.appendChild(errorCard);
        }

        if (!triggered.length) {
            const note = SS.el("p", null,
                "No policy rule was triggered by this file.");
            note.style.color = "var(--ink-soft)";
            panel.appendChild(note);
            return;
        }

        triggered.forEach((rule) => {
            const node = SS.el("div", "rule-trigger");

            node.appendChild(SS.badge(rule.severity, rule.severity));

            const bodyNode = SS.el("div", "rt-body");
            bodyNode.appendChild(SS.el("div", "rt-name", rule.name));
            bodyNode.appendChild(SS.el("div", "rt-action", rule.action));
            if (rule.description) {
                bodyNode.appendChild(SS.el("div", "rt-desc", rule.description));
            }
            bodyNode.appendChild(SS.el("div", "rt-cond", rule.condition));
            node.appendChild(bodyNode);

            panel.appendChild(node);
        });
    }

    function renderFingerprint(analysis, data) {
        const panel = SS.clear(document.getElementById("tab-fingerprint"));

        const card = SS.el("div", "card");
        const head = SS.el("div", "card-head");
        head.appendChild(SS.el("h3", null, "Cryptographic fingerprint"));
        card.appendChild(head);
        const body = SS.el("div", "card-body tight");

        body.appendChild(SS.dl([
            ["SHA-256", data.fingerprints.sha256, true],
            ["SHA-512", data.fingerprints.sha512, true],
            ["Size (bytes)", data.fingerprints.size_bytes + " bytes", true],
            ["Engine version", analysis.engine_version, true],
            ["Analysed at", analysis.analysed_at, true],
            ["Whole-file entropy", analysis.entropy.overall_bits_per_byte + " bits/byte"],
            ["Entropy at start", analysis.entropy.head_bits_per_byte + " bits/byte"],
            ["Entropy at end", analysis.entropy.tail_bits_per_byte + " bits/byte"],
        ]));

        card.appendChild(body);
        panel.appendChild(card);

        const note = SS.el("p", null,
            "These digests identify the file uniquely. If the same file is examined " +
            "again later, the digests must match; a mismatch means the file has " +
            "been altered.");
        note.style.cssText = "font-size:13px;color:var(--ink-soft);margin-top:14px";
        panel.appendChild(note);
    }

    function folderOf(analysis) {
        return analysis.artefact_folder || "";
    }

})();
