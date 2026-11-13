/* ============================================================
   SecureSnap - Policy Rules page
   ============================================================ */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const list = document.getElementById("ruleList");
    if (!list) {
        return;
    }

    const ruleId = document.getElementById("ruleId");
    const nameField = document.getElementById("ruleName");
    const actionField = document.getElementById("ruleAction");
    const severityField = document.getElementById("ruleSeverity");
    const conditionField = document.getElementById("ruleCondition");
    const descriptionField = document.getElementById("ruleDescription");
    const validation = document.getElementById("validationHolder");
    const formTitle = document.getElementById("formTitle");
    const saveBtn = document.getElementById("saveBtn");

    // Incremented whenever a validation result should no longer be shown.
    // This stops a slow "check syntax" reply from overwriting the form after
    // the user has cleared it or started editing another rule.
    let validationSequence = 0;

    function setValidation(kind, message) {
        validation.className = "status-line" + (kind ? " " + kind : "");
        validation.textContent = message;
    }

    function resetValidation() {
        validationSequence += 1;
        setValidation("", "");
    }

    async function load() {
        try {
            const data = await SS.request("/api/rules");
            SS.clear(list);

            if (!data.rules.length) {
                const empty = SS.el("p", null, "No rules are configured.");
                empty.style.color = "var(--ink-faint)";
                list.appendChild(empty);
                return;
            }

            data.rules.forEach((rule) => {
                const node = SS.el("div", "rule-item" + (rule.enabled ? "" : " disabled"));

                const badge = SS.badge(rule.severity, rule.severity);
                badge.style.marginTop = "2px";

                const body = SS.el("div");
                body.appendChild(SS.el("div", "ri-name", rule.name + (rule.builtin ? " · built-in" : "")));
                body.appendChild(SS.el("div", "ri-cond", rule.condition));
                body.appendChild(SS.el("div", "ri-action mono", rule.action));
                if (rule.description) {
                    body.appendChild(SS.el("div", "ri-desc", rule.description));
                }

                const actions = SS.el("div", "ri-actions");

                const toggle = SS.el("label", "switch");
                const toggleInput = SS.el("input");
                toggleInput.type = "checkbox";
                toggleInput.checked = !!rule.enabled;
                const slider = SS.el("span", "slider");
                toggle.append(toggleInput, slider);
                toggleInput.addEventListener("change", async () => {
                    try {
                        await SS.request("/api/rules/" + rule.id + "/toggle", { method: "POST" });
                        load();
                    } catch (error) {
                        toggleInput.checked = !!rule.enabled;
                        SS.toast(error.message, "error");
                    }
                });
                actions.appendChild(toggle);

                const edit = SS.el("button", "btn btn-ghost btn-sm", "Edit");
                edit.addEventListener("click", () => fillForm(rule));
                actions.appendChild(edit);

                if (!rule.builtin) {
                    const remove = SS.el("button", "btn btn-ghost btn-sm", "Delete");
                    remove.addEventListener("click", async () => {
                        if (!confirm("Remove the rule '" + rule.name + "'?")) return;
                        try {
                            await SS.request("/api/rules/" + rule.id, { method: "DELETE" });
                            SS.toast("Rule removed.", "success");
                            load();
                        } catch (error) {
                            SS.toast(error.message, "error");
                        }
                    });
                    actions.appendChild(remove);
                }

                node.append(badge, body, actions);
                list.appendChild(node);
            });

        } catch (error) {
            SS.toast(error.message, "error");
        }
    }

    function fillForm(rule) {
        ruleId.value = rule.id;
        nameField.value = rule.name;
        actionField.value = rule.action;
        severityField.value = rule.severity;
        conditionField.value = rule.condition;
        descriptionField.value = rule.description || "";
        formTitle.textContent = "Edit rule — " + rule.name;
        resetValidation();
        window.scrollTo({ top: 0, behavior: "smooth" });
    }

    function clearForm() {
        ruleId.value = "";
        nameField.value = "";
        actionField.value = "";
        severityField.value = "MEDIUM";
        conditionField.value = "";
        descriptionField.value = "";
        formTitle.textContent = "Rule editor";
        resetValidation();
    }

    async function checkSyntax() {
        const condition = conditionField.value.trim();
        if (!condition) {
            setValidation("error", "Enter a condition first.");
            return;
        }

        const sequence = ++validationSequence;
        setValidation("", "Checking the condition…");

        try {
            const data = await SS.postJSON("/api/rules/validate", { condition });

            if (sequence !== validationSequence) {
                return;
            }
            if (conditionField.value.trim() !== condition) {
                return;
            }

            if (data.valid) {
                setValidation("success", "Valid — parses as: " + data.parsed.condition);
            } else {
                setValidation("error", data.error || "The condition is not valid.");
            }
        } catch (error) {
            if (sequence !== validationSequence) {
                return;
            }
            setValidation("error", error.message);
        }
    }

    async function saveRule() {
        const payload = {
            name: nameField.value.trim(),
            action: actionField.value.trim(),
            severity: severityField.value,
            condition: conditionField.value.trim(),
            description: descriptionField.value.trim()
        };

        if (!payload.name || !payload.action || !payload.condition) {
            setValidation("error", "A name, an action and a condition are all required.");
            return;
        }

        validationSequence += 1;
        setValidation("", "Saving the rule…");
        saveBtn.disabled = true;

        try {
            if (ruleId.value) {
                await SS.putJSON("/api/rules/" + ruleId.value, payload);
                SS.toast("Rule updated.", "success");
            } else {
                await SS.postJSON("/api/rules", payload);
                SS.toast("Rule added to the policy set.", "success");
            }
            clearForm();
            await load();
        } catch (error) {
            setValidation("error", error.message);
        } finally {
            saveBtn.disabled = false;
        }
    }

    document.getElementById("checkBtn").addEventListener("click", checkSyntax);

    conditionField.addEventListener("blur", () => {
        // Only validate a condition the user actually entered. Clearing the
        // form must not produce a spurious "enter a condition" warning.
        if (conditionField.value.trim()) {
            checkSyntax();
        }
    });

    document.getElementById("cancelBtn").addEventListener("click", () => {
        clearForm();
        nameField.focus();
    });

    document.getElementById("newBtn").addEventListener("click", () => {
        clearForm();
        nameField.focus();
    });

    saveBtn.addEventListener("click", saveRule);

    load();
});
