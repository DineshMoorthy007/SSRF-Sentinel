# SSRF Sentinel

SSRF Sentinel is a local Dynamic Application Security Testing (DAST) lab for
demonstrating and validating Server-Side Request Forgery (SSRF) detection.
It combines:

- a deliberately vulnerable C++ target application;
- a Python test harness for environments where the native target cannot be
  built or run; and
- a multi-engine Python scanner that records evidence in JSON.

> **Use only against this local lab or systems you are explicitly authorized to
> test.** The target is intentionally vulnerable. The services bind to
> `127.0.0.1`, but loopback binding does not isolate them from other processes
> on the same machine.

## What it detects

The scanner runs five complementary detection engines:

| Engine | What it verifies |
| --- | --- |
| In-band | Internal response content reflected through the public application |
| Limited-response | SSRF when only a status code, header, truncated body, generic response, or suppression marker is observable |
| Blind/OOB | A server-side request confirmed by a callback received by the local evidence store |
| Time-based | A measurable response-time difference between fast and delayed internal resources |
| Boolean-based | A difference between true and false downstream conditions using status, headers, and response content |

Detection is evidence-based. Timing anomalies are not marked as laboratory
confirmed on timing alone; the report includes confidence and execution details
for every probe.

## Repository layout

```text
SSRF-Sentinel/
├── DAST-Scanner/
│   ├── main.py                 # Scanner entry point
│   ├── config.py               # Local URLs, markers, and thresholds
│   ├── core/                   # HTTP client and scan workflow
│   ├── engine/                 # Discovery, analysis, and SSRF engines
│   ├── reporting/              # JSON report generation
│   ├── reports/                # Generated ssrf_report.json
│   └── tests/                  # Unit tests and Python target harness
└── SSRF-Target/
    ├── CMakeLists.txt          # CMake build definition
    ├── include/                # C++ headers and embedded HTTP library
    └── src/                    # Public, internal, and callback servers
```

## Requirements

- Python 3.10 or newer
- `requests` (pinned in `DAST-Scanner/requirements.txt`)
- CMake 3.16 or newer and a C++17 compiler for the native target
  - Visual Studio/MSVC on Windows
  - GCC or Clang on Linux/macOS

## Quick start with the Python harness

The Python harness is the quickest way to run the complete lab.

### 1. Install scanner dependencies

From the repository root:

```powershell
cd DAST-Scanner
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

On Linux/macOS, use `.venv/bin/python` instead of
`.venv\Scripts\python.exe`.

### 2. Start the target services

Open a second terminal and run:

```powershell
cd DAST-Scanner
.\.venv\Scripts\python.exe tests\mock_target_server.py
```

The harness starts:

| Service | URL | Purpose |
| --- | --- | --- |
| Public application | `http://127.0.0.1:8080` | Crawled and scanned entry point |
| Internal service | `http://127.0.0.1:8081` | Simulated internal resources |
| OOB callback receiver | `http://127.0.0.1:8090` | Callback evidence and token store |

Keep this terminal running while scanning. Stop it with `Ctrl+C`.

### 3. Run the scanner

In the first terminal:

```powershell
cd DAST-Scanner
.\.venv\Scripts\python.exe main.py
```

The scanner checks the public `/health` endpoint, discovers endpoints and
parameters, runs all enabled SSRF engines, executes negative controls, and
writes the report to:

```text
DAST-Scanner/reports/ssrf_report.json
```

The scanner is deliberately scoped to `127.0.0.1:8080` by
`DAST-Scanner/config.py`; it rejects targets outside the configured local test
scope.

## Build and run the native C++ target

The native target starts the same three loopback services. From the repository
root:

```powershell
cd SSRF-Target
cmake -S . -B build
cmake --build build --config Release
.\build\Release\ssrf_target.exe
```

For single-configuration generators, the executable may instead be at
`build\ssrf_target.exe`. The target prints its active routes and waits for
`Enter` or `Ctrl+C` before shutting down.

Important lab routes include:

- `GET /fetch?url=...` on port `8080`: vulnerable forwarding endpoint
- `/internal/secret` and `/internal/admin/config` on port `8081`: in-band resources
- `/internal/limited/...` on port `8081`: limited-response cases
- `/internal/fast` and `/internal/delayed?ms=2000` on port `8081`: timing cases
- `/internal/check?condition=true|false` on port `8081`: boolean cases
- `/token/generate`, `/callback`, and `/evidence` on port `8090`: OOB support

## Run the tests

The tests start and stop their own Python target cluster. With the virtual
environment activated or from `DAST-Scanner`:

```powershell
cd DAST-Scanner
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The suite covers individual engines, report compatibility, the complete scan
pipeline, and repeatability across back-to-back scans.

## Report contents

`ssrf_report.json` contains:

- `scan_metadata`: scanner version, target, timestamp, and duration;
- `scan_summary`: endpoint, parameter, test, and outcome counts;
- `detection_summary`: counts by engine and confidence;
- `individual_findings`: positive findings with evidence and remediation;
- `discovered_endpoints` and `analyzed_parameters`; and
- `test_execution_details`: positive, negative, inconclusive, and failed probes.

The checked-in report is an example output. Running a scan overwrites
`DAST-Scanner/reports/ssrf_report.json`.

## Configuration

Edit `DAST-Scanner/config.py` to change lab-only URLs, request timeouts,
discovery paths, test markers, polling behavior, and detection thresholds.
Keep the public target aligned with the scanner's local allowlist:
`ALLOWED_HOST = "127.0.0.1"` and `ALLOWED_PORT = 8080`.

## Limitations

- This is a deterministic training and testing lab, not a general-purpose
  internet scanner.
- The scanner currently sends GET requests through the configured target.
- OOB verification requires the callback receiver to be reachable by the
  target service.
- Timing results can vary with host load and should be interpreted with the
  recorded confidence and evidence.

## License

No license file is currently included in this repository. Add a license before
redistributing the project.
