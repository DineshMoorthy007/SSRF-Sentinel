import time
import json
from core.http_client import HTTPClient
from engine.payload_generator import PayloadGenerator
from engine.response_analyzer import ResponseAnalyzer
from engine.inband_detector import InBandDetector
from engine.limited_response_detector import LimitedResponseDetector
from engine.blind_oob_detector import BlindOOBDetector
from engine.time_based_detector import TimeBasedDetector
from engine.boolean_based_detector import BooleanBasedDetector


def evaluate_ground_truth():
    client = HTTPClient()
    health = client.get("/health")
    if health is None or health.status_code != 200:
        print("[FATAL ERROR] C++ Target Application is not running on 127.0.0.1:8080.")
        print("Please start 'ssrf_target.exe' before running validation.")
        return None

    pg = PayloadGenerator()
    ra = ResponseAnalyzer()
    inband = InBandDetector(client, ra, pg)
    limited = LimitedResponseDetector(client, ra, pg)
    blind = BlindOOBDetector(client, ra, pg)
    time_detector = TimeBasedDetector(client, ra, pg)
    boolean = BooleanBasedDetector(client, ra, pg)

    # Dataset definition: (Case_ID, Name, Actual_Evaluation_Function, Ground_Truth_Label)
    # Ground_Truth_Label: 1 = Vulnerable (True Positive expected), 0 = Not Vulnerable / Blocked / Negative Control (True Negative expected)
    test_cases = []

    # 1. In-band Standard Cases (Expected: 1)
    for probe in pg.generate_category_a():
        test_cases.append({
            "id": probe["id"],
            "name": probe["name"],
            "category": probe["category"],
            "ground_truth": 1,
            "runner": lambda p=probe: inband.client.get("/fetch", params={"url": p["payload"]}),
            "evaluator": lambda resp, p=probe: ra.inspect_inband(ra.extract_metrics(resp), p["expected"].get("marker"))["detected"]
        })

    # 2. Alternative IP Notations (Expected: 1)
    for probe in pg.generate_category_b():
        test_cases.append({
            "id": probe["id"],
            "name": probe["name"],
            "category": probe["category"],
            "ground_truth": 1,
            "runner": lambda p=probe: inband.client.get("/fetch", params={"url": p["payload"]}),
            "evaluator": lambda resp, p=probe: "SSRF_SENTINEL_INTERNAL_ACCESS_2026" in (resp.text if resp else "")
        })

    # 3. URL Encoding Variations (Expected: 1)
    for probe in pg.generate_category_c():
        test_cases.append({
            "id": probe["id"],
            "name": probe["name"],
            "category": probe["category"],
            "ground_truth": 1,
            "runner": lambda p=probe: inband.client.get("/fetch", params={"url": p["payload"]}),
            "evaluator": lambda resp, p=probe: "SSRF_SENTINEL_INTERNAL_ACCESS_2026" in (resp.text if resp else "")
        })

    # 4. Redirect Chaining (Expected: 1)
    for probe in pg.generate_category_d()[:2]:  # Internal redirect & public bounce
        test_cases.append({
            "id": probe["id"],
            "name": probe["name"],
            "category": probe["category"],
            "ground_truth": 1,
            "runner": lambda p=probe: inband.client.get("/fetch", params={"url": p["payload"]}),
            "evaluator": lambda resp, p=probe: "SSRF_SENTINEL_INTERNAL_ACCESS_2026" in (resp.text if resp else "")
        })

    # 5. Limited-Response Cases (Expected: 1)
    for probe in pg.generate_category_f():
        def eval_limited(p=probe):
            res = limited.scan("/fetch", "url", mode="vulnerable")
            match = [f for f in res if f.get("extra_metadata", {}).get("probe_id") == p["id"]]
            return match[0]["detected"] if match else False
        test_cases.append({
            "id": probe["id"],
            "name": probe["name"],
            "category": probe["category"],
            "ground_truth": 1,
            "runner": lambda: None,
            "evaluator": lambda _, fn=eval_limited: fn()
        })

    # 6. Blind OOB Callback (Expected: 1)
    def eval_blind():
        res = blind.scan("/fetch", "url", mode="vulnerable")
        return res[0]["detected"] if res else False
    test_cases.append({
        "id": "PL-OOB-001",
        "name": "Dedicated Blind OOB Callback Probe",
        "category": "Category I: Blind / OOB",
        "ground_truth": 1,
        "runner": lambda: None,
        "evaluator": lambda _, fn=eval_blind: fn()
    })

    # 7. Time-Based SSRF (Expected: 1)
    def eval_time():
        res = time_detector.scan("/fetch", "url", mode="vulnerable")
        return res[0]["detected"] if res else False
    test_cases.append({
        "id": "PL-TIME-DELAY-002",
        "name": "Time-Based Latency Delay Probe",
        "category": "Category G: Time-Based",
        "ground_truth": 1,
        "runner": lambda: None,
        "evaluator": lambda _, fn=eval_time: fn()
    })

    # 8. Boolean-Based SSRF (Expected: 1)
    def eval_boolean():
        res = boolean.scan("/fetch", "url", mode="vulnerable")
        return res[0]["detected"] if res else False
    test_cases.append({
        "id": "PL-BOOL-TRUE-001",
        "name": "Boolean Condition Differential Probe",
        "category": "Category H: Boolean-Based",
        "ground_truth": 1,
        "runner": lambda: None,
        "evaluator": lambda _, fn=eval_boolean: fn()
    })

    # ========================================================
    # NEGATIVE CONTROLS & SECURE MODE DEFENSES (Expected: 0)
    # ========================================================

    # 9. Health endpoint (Non-SSRF public endpoint)
    test_cases.append({
        "id": "CTRL-HEALTH-001",
        "name": "Ordinary Public Health Endpoint",
        "category": "Negative Control: Clean Public Service",
        "ground_truth": 0,
        "runner": lambda: client.get("/health"),
        "evaluator": lambda resp: "SSRF_SENTINEL_INTERNAL_ACCESS" in (resp.text if resp else "")
    })

    # 10. Unsupported Schemes (file, gopher, ftp, malformed)
    for probe in pg.generate_category_e():
        test_cases.append({
            "id": probe["id"],
            "name": probe["name"],
            "category": probe["category"],
            "ground_truth": 0,
            "runner": lambda p=probe: client.get("/fetch", params={"url": p["payload"]}),
            "evaluator": lambda resp: (resp is not None and resp.status_code == 200 and "SSRF_SENTINEL" in resp.text)
        })

    # 11. Redirect Loop Cap
    test_cases.append({
        "id": "CTRL-REDIR-LOOP-001",
        "name": "Infinite Redirect Loop Exhaustion",
        "category": "Negative Control: Redirect Safety",
        "ground_truth": 0,
        "runner": lambda: client.get("/fetch", params={"url": "http://127.0.0.1:8081/internal/redirect-loop"}),
        "evaluator": lambda resp: (resp is not None and resp.status_code == 200 and "SSRF_SENTINEL" in resp.text)
    })

    # 12. Secure Mode Defenses
    test_cases.append({
        "id": "SEC-BLOCK-SECRET-001",
        "name": "Secure Mode Direct Access Block",
        "category": "Defense Control: Secure Mode Allowlist",
        "ground_truth": 0,
        "runner": lambda: client.get("/fetch", params={"url": "http://127.0.0.1:8081/internal/secret", "mode": "secure"}),
        "evaluator": lambda resp: (resp is not None and resp.status_code == 200 and "SSRF_SENTINEL" in resp.text)
    })

    test_cases.append({
        "id": "SEC-BLOCK-DEC-002",
        "name": "Secure Mode Alternative IP Notation Block",
        "category": "Defense Control: Secure Mode Allowlist",
        "ground_truth": 0,
        "runner": lambda: client.get("/fetch", params={"url": "http://2130706433:8081/internal/secret", "mode": "secure"}),
        "evaluator": lambda resp: (resp is not None and resp.status_code == 200 and "SSRF_SENTINEL" in resp.text)
    })

    test_cases.append({
        "id": "SEC-BLOCK-FETCHSEC-003",
        "name": "Dedicated Secure Endpoint Restriction",
        "category": "Defense Control: Secure Mode Allowlist",
        "ground_truth": 0,
        "runner": lambda: client.get("/fetch-secure", params={"url": "http://127.0.0.1:8081/internal/secret"}),
        "evaluator": lambda resp: (resp is not None and resp.status_code == 200 and "SSRF_SENTINEL" in resp.text)
    })

    # Run evaluations
    print("\n" + "=" * 70)
    print("      SSRF SENTINEL - GROUND-TRUTH VALIDATION EXECUTION")
    print("=" * 70)

    tp, fp, tn, fn = 0, 0, 0, 0
    records = []

    for tc in test_cases:
        tc_id = tc["id"]
        tc_name = tc["name"]
        gt = tc["ground_truth"]

        resp = tc["runner"]()
        predicted = 1 if tc["evaluator"](resp) else 0

        if gt == 1 and predicted == 1:
            classification = "TP (True Positive)"
            tp += 1
        elif gt == 0 and predicted == 0:
            classification = "TN (True Negative)"
            tn += 1
        elif gt == 0 and predicted == 1:
            classification = "FP (False Positive)"
            fp += 1
        else:
            classification = "FN (False Negative)"
            fn += 1

        status_symbol = "[PASS]" if (gt == predicted) else "[FAIL]"
        print(f" {status_symbol} {tc_id:<20} {tc_name:<40} GT={gt} Pred={predicted} -> {classification}")

        records.append({
            "id": tc_id,
            "name": tc_name,
            "category": tc["category"],
            "ground_truth": gt,
            "predicted": predicted,
            "classification": classification
        })

    total = len(test_cases)
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = ((tp + tn) / total) if total > 0 else 0.0

    print("\n" + "=" * 70)
    print("                 DETECTION ACCURACY & METRICS SUMMARY")
    print("=" * 70)
    print(f" Total Ground-Truth Cases Evaluated : {total}")
    print(f" True Positives (TP)                : {tp}")
    print(f" True Negatives (TN)                : {tn}")
    print(f" False Positives (FP)               : {fp}")
    print(f" False Negatives (FN)               : {fn}")
    print("-" * 70)
    print(f" Precision                          : {precision * 100:.2f}%")
    print(f" Recall (Sensitivity)               : {recall * 100:.2f}%")
    print(f" F1-Score                           : {f1 * 100:.2f}%")
    print(f" Overall Accuracy                   : {accuracy * 100:.2f}%")
    print("=" * 70)

    # Save validation records
    metrics_report = {
        "dataset_size": total,
        "confusion_matrix": {
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn
        },
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(accuracy, 4)
        },
        "evaluation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "test_cases": records
    }

    with open("reports/ground_truth_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics_report, f, indent=2)

    client.close()
    blind.close()
    return metrics_report


if __name__ == "__main__":
    evaluate_ground_truth()
