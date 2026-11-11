
# SecureSnap – Smart Image Security Analyzer

## 1. Project Overview

SecureSnap is a web-based image security and analysis application developed using Python and Flask.

It allows users to upload images and performs multiple security and image-analysis operations, including image validation, SHA-256 fingerprint generation, Fernet encryption, digital image processing and AI-based image classification.

The application provides an interactive dashboard where users can view analysis results and download a text report.

## 2. Key Features

- **Image Upload Validation:** Accepts JPG, JPEG and PNG images and rejects invalid or corrupted files.
- **SHA-256 Hashing:** Generates a unique fingerprint for the uploaded image.
- **Image Encryption:** Uses Fernet authenticated encryption to protect image data.
- **Image Processing:** Performs grayscale conversion, resizing, Gaussian blurring and edge detection.
- **AI Image Classification:** Uses pretrained MobileNetV2 to identify image content.
- **Security Rule Compiler:** Evaluates custom image-size security rules.
- **Interactive Dashboard:** Displays analysis results and processed image previews.
- **Report Generation:** Allows users to download analysis results as a text file.

## 3. Technologies Used

| Component | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript |
| Backend | Python, Flask |
| Image Processing | OpenCV |
| Deep Learning | PyTorch, Torchvision |
| AI Model | MobileNetV2 |
| Encryption | Cryptography (Fernet) |
| Hashing | SHA-256 |
| Image Validation | Pillow |
| Testing | Python unittest |

## 4. Project Architecture

```text
SecureSnap/
│
├── backend/
│   ├── app.py
│   ├── routes/
│   │   └── upload_routes.py
│   └── modules/
│       ├── image_processing.py
│       ├── encryption.py
│       ├── hashing.py
│       ├── ai_classifier.py
│       └── rule_compiler.py
│
├── frontend/
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── style.css
│       └── script.js
│
├── uploads/
├── encrypted/
├── processed/
├── tests/
├── requirements.txt
└── README.md
```

## 5. Working Process

1. User uploads an image through the web interface.
2. The backend validates the image extension and content.
3. The image size is checked against a custom security rule.
4. SHA-256 hashing generates the image fingerprint.
5. Fernet encryption creates an encrypted copy.
6. OpenCV performs image-processing operations.
7. MobileNetV2 predicts the image's content categories.
8. Results are returned to the frontend.
9. The dashboard displays the analysis report and processed images.
10. Users can download the analysis report.

## 6. Academic Subject Integration

| Subject | Implementation |
|---|---|
| Cryptography | SHA-256 hashing and Fernet encryption |
| Cybersecurity | Upload validation and security checks |
| Deep Learning | MobileNetV2 image classification |
| Compiler Design | Custom security rule evaluation |
| Computer Networks | Flask HTTP client-server communication |
| Digital Image Processing | Grayscale, resizing, blur and edge detection |

## 7. Installation and Execution

### Step 1: Clone the repository

```bash
git clone https://github.com/jeni2522007/SecureSnap.git
cd SecureSnap
```

### Step 2: Create a virtual environment

```bash
python -m venv .venv
```

### Step 3: Install dependencies

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Step 4: Run the application

```powershell
.\.venv\Scripts\python.exe backend/app.py
```

### Step 5: Open in browser

```text
http://127.0.0.1:5000
```

## 8. Testing

Run all automated tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Current test coverage includes:

- Security rule compiler tests
- Image upload validation tests
- Encryption and decryption tests
- SHA-256 verification tests

**Current test result:** 12 tests passed.

## 9. Important Limitations

- MobileNetV2 identifies image content; it does not determine whether an image is AI-generated or authentic.
- The custom rule evaluator supports a limited rule syntax and is not a complete compiler.
- The security rule flags matching images but does not currently block their processing.
- Encryption keys are generated during encryption but are not currently persisted for later application-level decryption.
- The application uses Flask's development server and is intended for project demonstration, not production deployment.

## 10. Future Enhancements

- Secure encryption-key management.
- Advanced image manipulation detection.
- User authentication and analysis history.
- PDF report generation.
- Improved security rule language with lexer and parser.
- Production deployment with secure configuration.

## 11. Conclusion

SecureSnap demonstrates the integration of cybersecurity, cryptography, deep learning, compiler concepts, computer networks and digital image processing in a single web-based application.

It provides a practical approach to image validation, protection and analysis through an interactive dashboard.

## 12. Developer

Developed as an academic mini-project.
