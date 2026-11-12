/* ============================================================
   SecureSnap - shared front-end helpers
   ============================================================ */

"use strict";

const SS = {};

/* ---------- HTTP ---------- */

SS.request = async function (url, options = {}) {
    const response = await fetch(url, options);
    let payload = null;

    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
        payload = await response.json();
    } else {
        payload = await response.text();
    }

    if (!response.ok) {
        const message = (payload && payload.error)
            ? payload.error
            : `Request failed (${response.status})`;
        throw new Error(message);
    }

    return payload;
};

SS.postJSON = function (url, body) {
    return SS.request(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
    });
};

SS.putJSON = function (url, body) {
    return SS.request(url, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
    });
};

SS.delete = function (url) {
    return SS.request(url, { method: "DELETE" });
};

/* ---------- Feedback ---------- */

SS.toast = function (message, kind = "") {
    const element = document.getElementById("toast");
    if (!element) return;

    element.textContent = message;
    element.className = "toast show" + (kind ? " " + kind : "");

    clearTimeout(SS._toastTimer);
    SS._toastTimer = setTimeout(() => {
        element.className = "toast" + (kind ? " " + kind : "");
    }, 3800);
};

/* ---------- Formatting ---------- */

SS.bytes = function (value) {
    if (value === null || value === undefined) return "-";
    const units = ["B", "KB", "MB", "GB"];
    let size = Number(value);
    let unit = 0;

    while (size >= 1024 && unit < units.length - 1) {
        size /= 1024;
        unit += 1;
    }
    return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
};

SS.shortHash = function (value) {
    if (!value) return "-";
    return value.length > 20 ? value.slice(0, 20) + "…" : value;
};

SS.dateTime = function (value) {
    if (!value) return "-";
    const parsed = new Date(value);
    if (isNaN(parsed.getTime())) return value;
    return parsed.toLocaleString(undefined, {
        year: "numeric", month: "short", day: "2-digit",
        hour: "2-digit", minute: "2-digit"
    });
};

SS.pct = function (value, digits = 1) {
    if (value === null || value === undefined) return "-";
    return `${(Number(value) * 100).toFixed(digits)}%`;
};

SS.severityClass = function (severity) {
    return "badge badge-" + String(severity || "info").toLowerCase();
};

SS.riskColour = function (score) {
    if (score >= 60) return "var(--critical)";
    if (score >= 35) return "var(--high)";
    if (score >= 15) return "var(--medium)";
    return "var(--good)";
};

SS.verdictBand = function (score) {
    if (score >= 60) return "critical";
    if (score >= 35) return "high";
    if (score >= 15) return "medium";
    return "low";
};

SS.escape = function (value) {
    if (value === null || value === undefined) return "";
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
};

/* ---------- DOM builders ---------- */

SS.el = function (tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
};

SS.clear = function (node) {
    while (node.firstChild) node.removeChild(node.firstChild);
    return node;
};

SS.dl = function (rows) {
    const list = SS.el("dl", "dl");

    rows.forEach(([label, value, mono]) => {
        const row = SS.el("div", "dl-row");
        row.appendChild(SS.el("dt", null, label));

        const dd = SS.el("dd", mono ? "mono" : null);
        if (value === null || value === undefined || value === "") {
            dd.textContent = "Not recorded";
            dd.style.color = "var(--ink-faint)";
            dd.style.fontWeight = "400";
        } else {
            dd.textContent = value;
        }
        row.appendChild(dd);
        list.appendChild(row);
    });

    return list;
};

SS.metric = function (label, value, note) {
    const box = SS.el("div", "metric");
    box.appendChild(SS.el("div", "m-label", label));
    box.appendChild(SS.el("div", "m-value", value));
    if (note) box.appendChild(SS.el("div", "m-note", note));
    return box;
};

SS.badge = function (text, kind) {
    return SS.el("span", SS.severityClass(kind), text);
};

/* ---------- Tabs ---------- */

SS.initTabs = function (root = document) {
    const tabs = root.querySelectorAll(".tab");
    tabs.forEach((tab) => {
        tab.addEventListener("click", () => {
            const group = tab.closest(".tabs").parentElement;

            group.querySelectorAll(".tab").forEach((other) => {
                other.classList.remove("active");
            });
            group.querySelectorAll(".tab-panel").forEach((panel) => {
                panel.classList.remove("active");
            });

            tab.classList.add("active");
            const panel = group.querySelector("#" + tab.dataset.target);
            if (panel) panel.classList.add("active");
        });
    });
};

/* ---------- Navigation highlight ---------- */

document.addEventListener("DOMContentLoaded", () => {
    const path = window.location.pathname;
    document.querySelectorAll(".nav a").forEach((link) => {
        const href = link.getAttribute("href");
        if (href === "/" && path === "/") {
            link.classList.add("active");
        } else if (href !== "/" && path.startsWith(href)) {
            link.classList.add("active");
        }
    });

    SS.initTabs();
});
