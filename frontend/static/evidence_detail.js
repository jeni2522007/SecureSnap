"use strict";

document.addEventListener("DOMContentLoaded", async () => {
    const app = document.getElementById("evidenceApp");
    if (!app) {
        return;
    }

    const evidenceId = Number(app.dataset.evidenceId);
    if (!Number.isInteger(evidenceId) || evidenceId <= 0) {
        SS.toast("The evidence identifier could not be read.", "error");
        return;
    }

    let item = null;

    const reportBtn = document.getElementById("reportBtn");
    reportBtn.href = "/report/" + evidenceId;

    async function load() {
        try {
            const data = await SS.request("/api/evidence/" + evidenceId);
            item = data.evidence;
            render(item);
            loadAudit();
        } catch (error) {
            SS.toast(error.message, "error");
        }
    }

    function render(item) {
        document.getElementById("itemTitle").textContent = item.title;
        document.getElementById("itemSubtitle").textContent =
            "Case " + item.case_ref + (item.exhibit_ref ? " · Exhibit " + item.exhibit_ref : "");

        document.getElementById("editCaseRef").value = item.case_ref || "";
        document.getElementById("editExhibitRef").value = item.exhibit_ref || "";
        document.getElementById("editTitle").value = item.title || "";
        document.getElementById("editDescription").value = item.description || "";
        document.getElementById("editSource").value = item.source || "";
        document.getElementById("editCollectedBy").value = item.collected_by || "";

        // Summary.
        const summary = SS.clear(document.getElementById("summaryHolder"));
        const analysis = item.analysis || {};

        const banner = SS.el("div", "verdict-banner " + SS.verdictBand(item.risk_score || 0));
        banner.style.margin = "0 0 18px";

        const dial = SS.el("div", "risk-dial");
        dial.style.setProperty("--value", item.risk_score || 0);
        dial.style.setProperty("--dial-color", SS.riskColour(item.risk_score || 0));
        dial.appendChild(SS.el("span", null, item.risk_score !== null ? item.risk_score : "-"));
        banner.appendChild(dial);

        const text = SS.el("div", "vb-text");
        text.appendChild(SS.el("h3", null, item.verdict || "No verdict recorded"));
        if (analysis.summary) {
            text.appendChild(SS.el("p", null, analysis.summary.reasoning));
        }
        banner.appendChild(text);
        summary.appendChild(banner);

        if (analysis.summary) {
            const metrics = SS.el("div", "metric-grid");
            metrics.appendChild(SS.metric("Findings", analysis.summary.finding_count, "total"));
            metrics.appendChild(SS.metric(
                "Critical", analysis.summary.critical_count, "immediate escalation"));
            metrics.appendChild(SS.metric(
                "High", analysis.summary.high_count, "verify against the original"));
            metrics.appendChild(SS.metric(
                "Risk band", analysis.summary.risk_band, "combined score"));
            summary.appendChild(metrics);
        }

        // Findings.
        const findings = SS.clear(document.getElementById("findingsHolder"));
        const list = (analysis.findings || []);

        if (!list.length) {
            const note = SS.el("p", null, "No findings were recorded for this item.");
            note.style.color = "var(--ink-faint)";
            findings.appendChild(note);
        } else {
            list.forEach((finding) => {
                const node = SS.el("div", "finding sev-" + finding.severity);
                const head = SS.el("div", "finding-head");
                head.appendChild(SS.badge(finding.severity, finding.severity));
                head.appendChild(SS.el("strong", null, finding.title));
                node.appendChild(head);
                node.appendChild(SS.el("p", null, finding.explanation));
                findings.appendChild(node);
            });
        }

        // Analysis history.
        const history = SS.clear(document.getElementById("historyHolder"));
        const runs = item.analysis_runs || [];

        if (!runs.length) {
            const note = SS.el("p", null, "No analysis runs recorded.");
            note.style.color = "var(--ink-faint)";
            history.appendChild(note);
        } else {
            history.appendChild(SS.dl(runs.map((run) => [
                run.created_at,
                `engine ${run.engine_version} · risk ${run.risk_score} · ${run.verdict}`
            ])));
        }

        // Fingerprints.
        const fingerprints = SS.clear(document.getElementById("fingerprintHolder"));
        fingerprints.appendChild(SS.dl([
            ["SHA-256", item.sha256, true],
            ["SHA-512", item.sha512, true],
            ["Size", SS.bytes(item.size_bytes)],
            ["Detected format", item.detected_format],
            ["Original filename", item.original_filename, true],
            ["Collected at", SS.dateTime(item.collected_at)],
            ["Registered at", SS.dateTime(item.created_at)],
        ]));
    }

    async function loadAudit() {
        try {
            const data = await SS.request("/api/audit?limit=40");
            const holder = SS.clear(document.getElementById("auditHolder"));

            const relevant = data.entries.filter((entry) =>
                entry.entity_id === evidenceId || entry.entity === "register");

            if (!relevant.length) {
                const note = SS.el("p", null, "No entries recorded for this item.");
                note.style.color = "var(--ink-faint)";
                holder.appendChild(note);
                return;
            }

            const list = SS.el("dl", "dl");
            relevant.forEach((entry) => {
                const row = SS.el("div", "dl-row");
                const left = SS.el("dt", null, entry.action.replace(/_/g, " "));
                const right = SS.el("dd", null, entry.detail || "");
                right.style.fontWeight = "400";
                right.style.fontSize = "12.5px";
                row.append(left, right);
                list.appendChild(row);
            });
            holder.appendChild(list);

        } catch (error) {
            SS.toast(error.message, "error");
        }
    }

    document.getElementById("verifyBtn").addEventListener("click", async () => {
        const holder = SS.clear(document.getElementById("verifyHolder"));
        holder.appendChild(SS.el("p", "status-line", "Re-verifying the stored file…"));

        try {
            const data = await SS.request("/api/evidence/" + evidenceId + "/verify", {
                method: "POST"
            });

            SS.clear(holder);
            const card = SS.el("div", "card");
            card.style.marginBottom = "18px";

            const head = SS.el("div", "card-head");
            head.appendChild(SS.el("h3", null, data.intact ? "Integrity confirmed" : "Integrity failure"));
            card.appendChild(head);

            const body = SS.el("div", "card-body tight");
            body.appendChild(SS.dl([
                ["Result", data.verdict],
                ["Verified at", SS.dateTime(data.verified_at)],
            ]));

            const table = SS.el("table");
            table.style.marginTop = "12px";
            const headRow = table.insertRow();
            ["Check", "Expected", "Actual", "Result"].forEach((label) => {
                const th = SS.el("th", null, label);
                headRow.appendChild(th);
            });
            data.checks.forEach((check) => {
                const row = table.insertRow();
                row.insertCell().textContent = check.check;
                const expected = row.insertCell();
                expected.className = "mono";
                expected.textContent = String(check.expected).slice(0, 24);
                const actual = row.insertCell();
                actual.className = "mono";
                actual.textContent = String(check.actual).slice(0, 24);
                const result = row.insertCell();
                result.appendChild(SS.badge(check.passed ? "Pass" : "Fail",
                    check.passed ? "good" : "critical"));
            });
            body.appendChild(table);
            card.appendChild(body);
            holder.appendChild(card);

            SS.toast(data.intact ? "Integrity confirmed." : "INTEGRITY FAILURE.",
                data.intact ? "success" : "error");

        } catch (error) {
            SS.clear(holder);
            SS.toast(error.message, "error");
        }
    });

    document.getElementById("saveBtn").addEventListener("click", async () => {
        try {
            await SS.request("/api/evidence/" + evidenceId, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    case_ref: document.getElementById("editCaseRef").value.trim(),
                    exhibit_ref: document.getElementById("editExhibitRef").value.trim(),
                    title: document.getElementById("editTitle").value.trim(),
                    description: document.getElementById("editDescription").value.trim(),
                    source: document.getElementById("editSource").value.trim(),
                    collected_by: document.getElementById("editCollectedBy").value.trim()
                })
            });
            SS.toast("Register entry updated.", "success");
            load();
        } catch (error) {
            SS.toast(error.message, "error");
        }
    });

    document.getElementById("deleteBtn").addEventListener("click", async () => {
        if (!confirm("Remove this entry from the register? The stored file stays on disk.")) {
            return;
        }
        try {
            await SS.request("/api/evidence/" + evidenceId, { method: "DELETE" });
            SS.toast("Register entry removed.", "success");
            setTimeout(() => window.location.href = "/evidence", 700);
        } catch (error) {
            SS.toast(error.message, "error");
        }
    });

    load();
});
