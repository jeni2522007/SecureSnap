# SecureSnap — Media Authenticity & Forensic Workbench

**A media authenticity examination system for investigating officers.**

SecureSnap takes images and video stills that are placed in evidence, establishes
their identity, reads and cross-checks their embedded metadata, and applies
seven independent manipulation tests. The result is a risk assessment, a set of
plain-language findings, and a court-ready report that an officer can sign.

Everything runs on the local workstation. No evidence leaves the machine.

---

## 1. What problem this solves

An officer receives a photograph and is asked whether it can be relied upon.
The honest answer is usually "that depends", and working it out by hand takes
hours of specialist knowledge that a station does not always have on site.

SecureSnap turns that judgement into a repeatable, documented process:

| Question an officer actually asks | How SecureSnap answers it |
|---|---|
| *Is this really the file I think it is?* | Magic-byte identification, extension-vs-content comparison, embedded-payload search, dual SHA-256/SHA-512 fingerprinting, and a sealed copy that proves the file was not altered |
| *Was this edited?* | Error level analysis, noise-discontinuity analysis, JPEG double-compression detection, copy-move (cloning) detection, resampling detection |
| *Is anything hidden in it?* | Chi-square attack on the least-significant-bit plane, and a search for data appended past the end of the image stream |
| *Does the file tell a consistent story?* | EXIF/XMP/IPTC extraction with internal contradiction checks — capture time against modification time, camera serial against make and model, recorded dimensions against stored pixels |
| *What should I do about it?* | A policy rule set that turns findings into named actions, scored by severity |
| *Can I show my work?* | A signed, printable report, a JSON export, a CSV register export, and an append-only audit trail |

---

## 2. Feature overview

### 2.1 File identity and integrity
- **Magic-byte format detection** across 20+ container types — JPEG, PNG, WebP,
  HEIC, AVIF, MP4, MOV, PDF, ZIP, RAR, 7-Zip, PE/ELF executables and more.
- **Claim-versus-content comparison.** A PDF renamed to `.jpg`, or an executable
  renamed to `.png`, is detected and escalated as CRITICAL rather than opened.
- **Polyglot search.** Additional file structures embedded inside a file are
  located by offset.
- **Dual fingerprinting.** SHA-256 and SHA-512 plus the byte size, taken at intake.
- **Sealed evidence copy.** The original is encrypted with AES-128-CBC under an
  HMAC-SHA256 tag. Re-verification decrypts the sealed copy and compares it
  against the intake fingerprints, proving the working copy is unaltered.

### 2.2 Metadata forensics
Extracts EXIF, XMP (including the Photoshop/Lightroom editing history) and IPTC,
then checks for internal contradictions:

- capture time later than modification time
- digitisation time earlier than capture time
- timestamps in the future or before 1990
- image dimensions that disagree with the recorded EXIF dimensions
- camera make and model that disagree with the software field
- an orientation tag that contradicts the actual pixel geometry
- artist and copyright fields that name different people
- GPS coordinates, decoded into decimal degrees with an OpenStreetMap link
- a missing body serial number on a professional camera

Editing tools and generative-AI tools recorded in the metadata are flagged by name.

### 2.3 Manipulation detection

| Technique | What it detects |
|---|---|
| **Error Level Analysis** | Locally edited regions. The frame is re-compressed at a fixed quality and the residual is measured block by block on the JPEG grid. Produces a heat map and candidate regions. |
| **Copy-move detection** | Cloned regions. Every block is reduced to a perceptual DCT hash; matches are found through a banded index, filtered for texture, and clustered into regions. Produces a duplicate-region map. |
| **Noise discontinuity** | Splicing. A high-pass residual is computed per block; abrupt changes in noise level between neighbouring blocks indicate content joined from a different source. |
| **JPEG structure** | Double compression, via the quantization table fingerprint, with an estimated final quality factor. |
| **Resampling detection** | Enlargement, via the collapse of high-frequency energy in the power spectrum. |
| **Steganography** | Classic LSB embedding, via a chi-square attack on each colour channel, plus a search for data appended past the end of the image stream. |
| **Content classification** | MobileNetV2 scene classification, cross-checked against the metadata — a frame classified as a screen capture that nonetheless carries DSLR camera fields is a contradiction worth recording. |

### 2.4 Policy rule engine
The former regex "rule compiler" has been replaced by a real lexer, recursive-descent
parser and evaluator for a small rule language:

```
RULE MetadataAbsent
WHEN metadata.available == false AND format.category == "image"
THEN ESCALATE_UNVERIFIED_SOURCE
SEVERITY MEDIUM
```

Supported: `==` `!=` `>` `>=` `<` `<=`, `AND` `OR` `NOT`, `EXISTS`, `CONTAINS`,
`MATCHES`, `IN`, parentheses, numbers, strings and booleans.

Nineteen rules covering the checks an examiner would otherwise perform by hand
ship enabled. Rules can be edited, disabled, added and deleted from the interface,
and every condition is parsed and validated before it is saved — a broken rule is
reported as an error rather than silently weakening the examination.

### 2.5 Case and evidence management
- Evidence register with case reference, exhibit reference, narrative, source and
  collecting officer.
- Duplicate detection across cases — the same file logged twice is surfaced.
- Analysis history: every run is retained with its engine version and score.
- Append-only audit trail of every registration, edit, verification and export.
- CSV export of the whole register for spreadsheet or database use.

### 2.6 Comparative analysis
Two images can be placed side by side to establish whether they depict the same
scene. The pair is aligned, structural similarity (SSIM) and pixel correlation are
measured, the translation offset is estimated by phase correlation, and a
difference map plus a divergence map are produced with the coordinates of every
region where the two images part company.

### 2.7 Reporting
- A printable court report with the opinion, the particulars of the item, the
  integrity fingerprints, every finding, the metadata table, the policy rules
  triggered, the method of examination, and a qualification-and-limitations
  section with signature blocks.
- JSON export of the complete analysis.
- CSV export of the register.

---

## 3. Screens

| Screen | Purpose |
|---|---|
| **Dashboard** | Headline figures, recent examinations, and an explanation of what the pipeline checks |
| **Analyse** | Submit a file, optionally register it as evidence, and read the full result across eight tabs |
| **Compare** | Two-image comparison with difference and divergence maps |
| **Evidence Register** | Filterable register with per-item report and integrity verification |
| **Evidence item** | Full analysis, register details, analysis history, fingerprints and audit trail |
| **Policy Rules** | Rule editor with live syntax validation and the language reference |
| **Court report** | Printable, signable report |

---

## 4. Technology

| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3, vanilla JavaScript (no build step) |
| Backend | Python 3.11, Flask 3 |
| Persistence | SQLite 3 (standard library) |
| Image processing | OpenCV, Pillow, NumPy, SciPy |
| Deep learning | PyTorch, Torchvision (MobileNetV2) |
| Cryptography | `cryptography` (Fernet / AES-128-CBC + HMAC-SHA256), `hashlib` |
| Rule language | Hand-written lexer, parser and evaluator |
| Testing | pytest, 82 tests |

The classifier is optional: if PyTorch or Torchvision cannot be loaded, the rest
of the pipeline still runs and the classifier is simply reported as unavailable.

---

## 5. Project structure

```text
SecureSnap/
├── backend/
│   ├── app.py                     # application factory and error handling
│   ├── config.py                  # paths and limits
│   ├── db.py                      # schema, transactions, audit trail
│   ├── routes/
│   │   ├── analysis_routes.py     # /api/analyze, /api/compare
│   │   ├── evidence_routes.py     # register CRUD, integrity verification
│   │   ├── rules_routes.py        # policy rule management
│   │   ├── report_routes.py       # court report, JSON and CSV export
│   │   └── page_routes.py         # HTML pages
│   └── modules/
│       ├── analyzer.py            # the analysis pipeline and fact mapping
│       ├── file_identity.py       # magic bytes, polyglots, entropy
│       ├── metadata.py            # EXIF / XMP / IPTC and contradiction checks
│       ├── hashing.py             # SHA-256, SHA-512, sealed manifests
│       ├── encryption.py          # evidence sealing
│       ├── compare.py             # two-image comparison
│       ├── ai_classifier.py       # MobileNetV2 content classification
│       ├── rule_service.py        # rule loading and execution
│       ├── forensics/
│       │   ├── ela.py             # error level analysis
│       │   ├── copy_move.py       # cloning detection
│       │   ├── noise.py           # noise, splicing, JPEG and resampling
│       │   ├── steganography.py   # LSB chi-square and appended payloads
│       │   └── scoring.py         # findings, risk score, verdict
│       └── rule_engine/
│           ├── lexer.py           # tokeniser
│           ├── parser.py          # recursive-descent parser
│           ├── evaluator.py       # evaluation against the facts
│           └── defaults.py        # the built-in policy rule set
│
├── frontend/
│   ├── templates/                 # dashboard, analyse, compare, evidence,
│   │                              # evidence detail, rules, report
│   └── static/                    # style.css, app.js, analyze.js
│
├── tests/                         # 82 tests
│   ├── fixtures.py
│   ├── test_rule_engine.py
│   ├── test_file_identity.py
│   ├── test_forensics.py
│   └── test_api.py
│
├── data/                          # created on first run (git-ignored)
│   ├── securesnap.db              # evidence register, rules, audit trail
│   ├── evidence/                  # working copies
│   ├── sealed/                    # encrypted evidence copies
│   └── analysis/                  # generated heat maps and diagnostic images
│
├── requirements.txt
└── README.md
```

---

## 6. Installation and running

### Prerequisites
- Python 3.11 or newer
- ~1 GB of disk for the PyTorch dependency (optional — the forensic pipeline
  runs without it)

### Step 1 — clone and set up

```bash
git clone https://github.com/jeni2522007/SecureSnap.git
cd SecureSnap
python -m venv .venv
```

### Step 2 — install dependencies

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

macOS / Linux:

```bash
./.venv/bin/python -m pip install -r requirements.txt
```

### Step 3 — run

```powershell
.\.venv\Scripts\python.exe backend/app.py
```

### Step 4 — open

```text
http://127.0.0.1:5000
```

The database and the working folders are created automatically on first run.

---

## 7. Testing

```powershell
.\.venv\Scripts\python.exe -m pytest tests -v
```

**Current result: 97 tests passed.**

The suite covers the rule language (lexing, parsing, precedence, evaluation,
validation), file identification (magic bytes, renamed files, executables,
polyglots, entropy), hashing and sealing (stability, tamper detection,
authentication failure), the forensic techniques (error level analysis on an
edited frame, clone detection, LSB embedding, appended payloads, metadata
contradictions, scoring), the full API (pages, analysis, registration,
integrity verification, duplicates, rule management, reporting and comparison),
and a dedicated security suite that guards against the weaknesses listed below.

---

## 8. Security

The application handles evidence, so it is hardened accordingly. Every item
below has a regression test in `tests/test_security.py`.

### Controls in place

| Control | Detail |
|---|---|
| **Path traversal** | The filename in a multipart header is chosen entirely by the client, so it is never used to build a path. Every upload name is passed through `werkzeug.utils.secure_filename` before it touches the disk. |
| **CSRF** | Every state-changing request must carry a session token issued when the page was served. Requests without it are refused with `403`. |
| **Origin and Host checks** | A request whose `Origin` or `Host` names another machine is refused, so a web page on another site cannot drive the application. |
| **Security headers** | `Content-Security-Policy` (no inline script, `frame-ancestors 'none'`), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Permissions-Policy`. |
| **Session cookie** | `HttpOnly` and `SameSite=Strict`. |
| **Debug mode off** | The Werkzeug interactive debugger allows arbitrary code execution, so it is off unless `SECURESNAP_DEBUG=1` is set explicitly. |
| **Secrets** | The session key is generated randomly on first run and stored with owner-only permissions, or supplied through `SECURESNAP_SECRET_KEY`. No key is hard-coded. |
| **Error handling** | Internal exceptions are logged on the server and reported to the browser as a generic message, so paths and tracebacks are never disclosed. |
| **Resource limits** | Uploads are capped at 25 MB. Image headers declaring more than 50 million pixels are refused before the file is decoded, which closes the decompression-bomb route. |
| **Dependency hygiene** | Pillow and cryptography are pinned to versions with no published advisories. |
| **Port guard** | The application refuses to start if the port is already in use, so a stale copy cannot keep serving old code on the same address. |

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SECURESNAP_SECRET_KEY` | random, stored in `data/secret.key` | Session signing key |
| `SECURESNAP_DEBUG` | off | Enables the Werkzeug debugger. Leave off. |
| `SECURESNAP_HOST` | `127.0.0.1` | Address to bind |
| `SECURESNAP_PORT` | `5000` | Port to bind |
| `SECURESNAP_ALLOWED_HOSTS` | `127.0.0.1,localhost` | Hosts permitted to make requests |
| `SECURESNAP_DATA_DIR` | `./data` | Where evidence, keys and the database are kept |

### Known limitations

- **The evidence key is stored in plaintext** at `data/evidence.key`. This is
  appropriate for a single-workstation tool, but the key must be moved to
  removable media or a hardware token if the workstation itself may be seized.
- **There is no user authentication.** The application is designed to run on a
  workstation that the officer controls. Adding accounts and roles would be the
  next step for any shared or networked deployment.
- **The application is a development server.** It should be put behind a
  production WSGI server with TLS before it is exposed to a network.
- **The classifier downloads its model weights on first use.** For a sealed or
  offline workstation, pre-seed the Torch model cache or run without the
  classifier, which the pipeline handles gracefully.

---

## 9. A worked example

1. Open **Analyse**, drop in a photograph.
2. Leave *Register as evidence* ticked and enter the case reference.
3. Press **Run examination**.
4. Read the verdict banner and the **Findings** tab.
5. Open the **ELA heat map** and **duplicate region map** to see where the
   pipeline is pointing.
6. Check the **Policy rules** tab for the action each finding triggers.
7. Press **Open report**, print or save as PDF, and sign it.

If the same file is examined again later, the fingerprints in the report will
match only if the file has not changed. The **Verify integrity** action proves
this against the sealed copy.

---

## 10. Limitations and responsible use

These limits are stated in the report itself, because they matter:

- **A finding is a lead, not a proof.** Every technique has false positives and
  false negatives. Repetitive scene structure produces copy-move matches;
  ordinary compression produces ELA response.
- **The absence of a finding proves nothing.** A clean result means nothing
  tested was contradicted — not that the file is genuine.
- **Re-encoded media loses evidence.** An image that has been through a
  messaging application or a social platform has already lost the original
  camera metadata and the original pixel noise. Always obtain the original file
  from the device.
- **The classifier describes content; it does not judge authenticity.** It is
  used only to cross-check the picture against its own metadata.
- **The rule set is a policy, not a legal test.** It expresses the examining
  policy of the station. A court may require different thresholds.
- **Not a substitute for a laboratory.** Where a finding is critical, or where
  the item is central to a prosecution, it should be referred to a digital
  forensics laboratory and a second expert opinion obtained.

---

## 11. Subject integration

| Subject | Implementation |
|---|---|
| Cybersecurity | Input validation, format verification, polyglot detection, sealed evidence, integrity re-verification, append-only audit trail |
| Cryptography | SHA-256 and SHA-512 fingerprinting, Fernet (AES-128-CBC + HMAC-SHA256) sealing, key management |
| Digital Image Processing | Error level analysis, resampling and colour conversion, DCT perceptual hashing, SSIM, phase correlation, FFT power-spectrum analysis |
| Deep Learning | MobileNetV2 scene classification and metadata cross-validation |
| Compiler Design | A complete lexer, recursive-descent parser and evaluator for a purpose-built rule language, with abstract syntax tree evaluation |
| Computer Networks | Flask HTTP client-server architecture, REST-style JSON API, multipart file transfer, client-side rendering |
| Database Systems | A normalised SQLite schema, indexed queries, transactional writes, referential integrity between evidence and analysis runs |

---

## 12. Developer

Developed as an academic mini-project, restructured into a working forensic
tool for police evidence handling.
