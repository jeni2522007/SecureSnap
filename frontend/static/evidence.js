"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const body = document.getElementById("registerBody");
    if (!body) {
        return;
    }

    const countLabel = document.getElementById("resultCount");

    async function load() {
        const params = new URLSearchParams();
        const search = document.getElementById("search").value.trim();
        const caseRef = document.getElementById("caseFilter").value.trim();
        const verdict = document.getElementById("verdictFilter").value;

        if (search) params.set("q", search);
        if (caseRef) params.set("case_ref", caseRef);
        if (verdict) params.set("verdict", verdict);

        SS.clear(body);

        try {
            const data = await SS.request("/api/evidence?" + params.toString());
            countLabel.textContent = "Register — " + data.count + " item" + (data.count === 1 ? "" : "s");

            if (!data.items.length) {
                const row = body.insertRow();
                const cell = row.insertCell();
                cell.colSpan = 9;
                cell.style.color = "var(--ink-faint)";
                cell.textContent = "No items match the current filters.";
                return;
            }

            data.items.forEach((item) => {
                const row = body.insertRow();

                row.insertCell().innerHTML = `<span class="mono">${item.id}</span>`;

                const caseCell = row.insertCell();
                caseCell.innerHTML = `<span class="mono">${SS.escape(item.case_ref)}</span>`;
                if (item.exhibit_ref) {
                    caseCell.innerHTML += `<br><span style="font-size:11.5px;color:var(--ink-faint)">${SS.escape(item.exhibit_ref)}</span>`;
                }

                const titleCell = row.insertCell();
                titleCell.textContent = item.title;
                if (item.original_filename) {
                    const sub = SS.el("div", null, item.original_filename);
                    sub.style.cssText = "font-size:11.5px;color:var(--ink-faint)";
                    titleCell.appendChild(sub);
                }

                row.insertCell().textContent = item.detected_format || "-";

                const risk = row.insertCell();
                risk.className = "tnum nowrap";
                risk.textContent = item.risk_score !== null ? item.risk_score : "-";

                const verdict = row.insertCell();
                const score = item.risk_score || 0;
                verdict.appendChild(SS.badge(
                    score >= 60 ? "High" : score >= 35 ? "Review" : "Low",
                    score >= 60 ? "critical" : score >= 35 ? "medium" : "good"
                ));

                const hash = row.insertCell();
                const hashCode = SS.el("span", "mono", SS.shortHash(item.sha256));
                hash.appendChild(hashCode);

                const when = row.insertCell();
                when.className = "nowrap";
                when.textContent = SS.dateTime(item.created_at);

                const actions = row.insertCell();
                actions.className = "nowrap";

                const open = SS.el("a", "btn btn-ghost btn-sm", "Open");
                open.href = "/evidence/" + item.id;
                actions.appendChild(open);

                const report = SS.el("a", "btn btn-ghost btn-sm", "Report");
                report.href = "/report/" + item.id;
                report.style.marginLeft = "6px";
                actions.appendChild(report);
            });

        } catch (error) {
            const row = body.insertRow();
            const cell = row.insertCell();
            cell.colSpan = 9;
            cell.style.color = "var(--critical)";
            cell.textContent = error.message;
        }
    }

    document.getElementById("applyBtn").addEventListener("click", load);
    document.getElementById("refreshBtn").addEventListener("click", load);
    document.getElementById("clearBtn").addEventListener("click", () => {
        document.getElementById("search").value = "";
        document.getElementById("caseFilter").value = "";
        document.getElementById("verdictFilter").value = "";
        load();
    });

    document.getElementById("search").addEventListener("keydown", (event) => {
        if (event.key === "Enter") load();
    });

    document.getElementById("duplicatesBtn").addEventListener("click", async () => {
        try {
            const data = await SS.request("/api/evidence/duplicates");

            if (!data.count) {
                SS.toast("No duplicate files were found in the register.", "success");
                return;
            }

            const lines = data.groups.map((group) =>
                `${group.filename} appears ${group.copies} times (cases: ${group.case_refs.join(", ")})`
            );
            SS.toast(lines.join(" | "), "error");

        } catch (error) {
            SS.toast(error.message, "error");
        }
    });

    load();
});
