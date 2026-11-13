"use strict";

document.addEventListener("DOMContentLoaded", async () => {
    const body = document.getElementById("recent-body");
    if (!body) {
        return;
    }

    try {
        const data = await SS.request("/api/evidence/stats");

        document.getElementById("stat-total").textContent = data.stats.total_evidence;
        document.getElementById("stat-cases").textContent = data.stats.cases;
        document.getElementById("stat-flagged").textContent = data.stats.flagged;
        document.getElementById("stat-average").textContent = data.stats.average_risk;

        SS.clear(body);

        if (!data.recent.length) {
            const row = body.insertRow();
            const cell = row.insertCell();
            cell.colSpan = 6;
            cell.style.color = "var(--ink-faint)";
            cell.textContent = "No evidence has been registered yet.";
            return;
        }

        data.recent.forEach((item) => {
            const row = body.insertRow();

            row.insertCell().innerHTML =
                `<span class="mono">${SS.escape(item.case_ref)}</span>`;

            row.insertCell().textContent = item.title;

            const verdict = row.insertCell();
            const score = item.risk_score || 0;
            const badge = SS.badge(
                score >= 60 ? "High risk" : score >= 35 ? "Review" : "Low risk",
                score >= 60 ? "critical" : score >= 35 ? "medium" : "good"
            );
            verdict.appendChild(badge);

            const risk = row.insertCell();
            risk.className = "tnum";
            risk.textContent = score;

            const when = row.insertCell();
            when.className = "nowrap";
            when.textContent = SS.dateTime(item.created_at);

            const action = row.insertCell();
            const link = SS.el("a", "btn btn-ghost btn-sm", "Open");
            link.href = "/evidence/" + item.id;
            action.appendChild(link);
        });
    } catch (error) {
        SS.toast(error.message, "error");
    }
});
