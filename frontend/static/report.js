"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const printBtn = document.getElementById("printBtn");
    if (!printBtn) {
        return;
    }

    printBtn.addEventListener("click", () => {
        window.print();
    });
});
