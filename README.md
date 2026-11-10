# SSRF Sentinel

**SSRF Sentinel** is a Dynamic Application Security Testing (DAST) framework designed to detect, analyze, and verify Server-Side Request Forgery (SSRF) vulnerabilities across multiple behavior categories.

---

## Architecture & Project Structure

The project consists of two core components:

```
SSRF-Sentinel/
├── SSRF-Target/        # C++ multi-service vulnerable testbed (Ports 8080, 8081, 8090)
│   ├── CMakeLists.txt  # CMake build definition
│   ├── include/        # Header files (httplib, server managers, callback store)
│   └── src/            # Implementation source files
│
└── DAST-Scanner/       # Python-based multi-engine SSRF scanner
    ├── config.py       # Centralized target URLs, thresholds, and markers
    ├── main.py         # Scanner entrypoint
    ├── core/           # HTTP client and workflow coordinator
    ├── engine/         # 5 specialized SSRF detection engines
    ├── reporting/      # JSON report generator
    ├── reports/        # Output reports directory (ssrf_report.json)
    └── tests/          # Automated test suite and mock test harness
```

---

## Supported SSRF Techniques

1. **In-Band / Content-Based SSRF:** Identifies internal resource content, credentials, and verification markers.
2. **Limited-Response SSRF:** Detects status-only (HTTP 204), header-only, truncated bodies, and content suppression.
3. **Blind / Out-of-Band (OOB) SSRF:** Uses cryptographic tokens and a dedicated local callback listener (Port 8090).
4. **Time-Based SSRF:** Evaluates latency differentials using multi-sample median calculations.
5. **Boolean-Based SSRF:** Differentiates conditional TRUE and FALSE server states via status codes and content lengths.

---

## Quick Start Guide

### 1. Requirements

- **C++ Target:** CMake (>= 3.16), MSVC x64 / GCC / Clang (C++17)
- **Python Scanner:** Python 3.10+, `requests` library

---

### 2. Running the Target Application

#### Option A: Native C++ Build (MSVC x64)
```cmd
cd SSRF-Target
cmake -S . -B build -G "NMake Makefiles"
cmake --build build
cd build
ssrf_target.exe
```

#### Option B: Python Test Harness (Useful if native execution is restricted by OS policy)
```powershell
cd DAST-Scanner
.\venv\Scripts\python.exe tests\mock_target_server.py
```

*This spins up:*
- Public Web Server on `http://127.0.0.1:8080`
- Internal Service on `http://127.0.0.1:8081`
- Dedicated OOB Callback Receiver on `http://127.0.0.1:8090`

---

### 3. Running the DAST Scanner

In a separate terminal:

```powershell
cd DAST-Scanner

# Install dependencies if not already installed
pip install -r requirements.txt

# Run the scanner
python main.py
```

Results are displayed in the terminal and saved to `DAST-Scanner/reports/ssrf_report.json`.

---

### 4. Running Automated Tests

```powershell
cd DAST-Scanner
python -m unittest discover -s tests
```

