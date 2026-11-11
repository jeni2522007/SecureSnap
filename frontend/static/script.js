async function analyzeImage() {
    const input = document.getElementById("imageInput");
    const message = document.getElementById("message");
    const button = document.getElementById("analyzeButton");
    const resultSection = document.getElementById("resultSection");
    const resultContent = document.getElementById("resultContent");

    if (input.files.length === 0) {
        message.textContent = "Please select an image first.";
        return;
    }

    const formData = new FormData();
    formData.append("image", input.files[0]);

    button.disabled = true;
    button.textContent = "Analyzing...";
    message.textContent = "Please wait. Analyzing your image...";
    resultSection.classList.add("hidden");
    resultContent.replaceChildren();

    try {
        const response = await fetch("/upload", {
            method: "POST",
            body: formData
        });

        const result = await response.json();

        if (!response.ok) {
            message.textContent = result.error || "Analysis failed.";
            return;
        }

        message.textContent = result.message;
        displayResults(result);
        resultSection.classList.remove("hidden");

    } catch (error) {
        message.textContent = "Unable to connect to the server.";
        console.error(error);

    } finally {
        button.disabled = false;
        button.textContent = "Analyze Image";
    }
}


// Create result cards
function createCard(title) {
    const card = document.createElement("div");
    card.className = "result-card";

    const heading = document.createElement("h3");
    heading.textContent = title;

    card.appendChild(heading);
    return card;
}


// Add information rows
function addRow(card, label, value, status = false) {
    const row = document.createElement("div");
    row.className = "result-row";

    const left = document.createElement("span");
    left.className = "result-label";
    left.textContent = label;

    const right = document.createElement("span");
    right.className = "result-value";
    right.textContent = value ?? "Not available";

    if (status) {
        const text = String(value).toLowerCase();

        right.classList.add(
            text.includes("allow") ||
            text.includes("successful") ||
            text.includes("success")
                ? "success"
                : "warning"
        );
    }

    row.append(left, right);
    card.appendChild(row);
}


// Display complete analysis results
function displayResults(data) {
    const container = document.getElementById("resultContent");
    container.replaceChildren();


    // 1. Image Overview
    const overview = createCard("📁 Image Overview");

    addRow(overview, "Status", data.status);
    addRow(overview, "Filename", data.filename);
    addRow(
        overview,
        "Image Size",
        `${(data.image_size_bytes / (1024 * 1024)).toFixed(2)} MB`
    );

    container.appendChild(overview);


    // 2. Security Analysis
    const security = createCard("🛡️ Security Analysis");

    addRow(security, "Compiler Rule", data.security_rule);
    addRow(security, "Compiler Result", data.compiler_result, true);
    addRow(security, "Encryption", data.encryption, true);
    addRow(security, "Encrypted File", data.encrypted_file);

    container.appendChild(security);


    // 3. SHA-256 Fingerprint
    const hashCard = createCard("🔐 SHA-256 Fingerprint");

    addRow(hashCard, "SHA-256", data.sha256);

    container.appendChild(hashCard);


    // 4. AI Image Classification
    const aiCard = createCard("🤖 AI Image Classification");

    if (Array.isArray(data.ai_predictions)) {

        data.ai_predictions.forEach(prediction => {

            const item = document.createElement("div");
            item.className = "prediction";

            const info = document.createElement("div");
            info.className = "prediction-info";

            const label = document.createElement("strong");
            label.textContent = prediction.label;

            const confidence = document.createElement("span");
            confidence.textContent = `${prediction.confidence}%`;

            info.append(label, confidence);

            const progress = document.createElement("div");
            progress.className = "progress";

            const fill = document.createElement("div");
            fill.className = "progress-fill";

            const score = Math.min(
                100,
                Math.max(0, Number(prediction.confidence) || 0)
            );

            fill.style.width = `${score}%`;

            progress.appendChild(fill);
            item.append(info, progress);

            aiCard.appendChild(item);
        });
    }

    container.appendChild(aiCard);


    // 5. Image Processing Previews
    const processing = createCard("🖼️ Image Processing");

    const previewGrid = document.createElement("div");
    previewGrid.className = "preview-grid";

    if (data.image_processing) {

        Object.entries(data.image_processing).forEach(
            ([operation, filename]) => {

                const preview = document.createElement("div");
                preview.className = "preview-item";

                const heading = document.createElement("h4");

                heading.textContent =
                    operation.charAt(0).toUpperCase() +
                    operation.slice(1);

                const image = document.createElement("img");

                image.src = `/processed/${encodeURIComponent(filename)}`;
                image.alt = `${operation} processed image`;
                image.loading = "lazy";

                image.onerror = () => {
                    image.alt = "Preview unavailable";
                    image.style.display = "none";

                    const error = document.createElement("p");
                    error.textContent = "Preview unavailable";

                    preview.appendChild(error);
                };

                const name = document.createElement("p");
                name.className = "file-name";
                name.textContent = filename;

                preview.append(heading, image, name);

                previewGrid.appendChild(preview);
            }
        );
    }

    processing.appendChild(previewGrid);
    container.appendChild(processing);
    const downloadButton = document.createElement("button");

    downloadButton.textContent = "Download Analysis Report";

    downloadButton.onclick = () => downloadReport(data);

    container.appendChild(downloadButton);
}

function downloadReport(data) {
    const report = `
========================================
          SECURESNAP REPORT
========================================

IMAGE OVERVIEW
--------------
Status: ${data.status}
Filename: ${data.filename}
Image Size: ${data.image_size_bytes} bytes

SECURITY ANALYSIS
-----------------
Security Rule: ${data.security_rule}
Compiler Result: ${data.compiler_result}
Encryption: ${data.encryption}
Encrypted File: ${data.encrypted_file}

SHA-256 FINGERPRINT
-------------------
${data.sha256}

AI IMAGE CLASSIFICATION
-----------------------
${(data.ai_predictions || []).map(
    p => `${p.label}: ${p.confidence}%`
).join("\n")}

IMAGE PROCESSING
----------------
${Object.entries(data.image_processing || {}).map(
    ([operation, filename]) => `${operation}: ${filename}`
).join("\n")}

========================================
       END OF REPORT
========================================
`;

    const blob = new Blob([report], {
        type: "text/plain"
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "SecureSnap_Analysis_Report.txt";

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
}
