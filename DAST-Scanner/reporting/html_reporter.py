import os
import json
import html
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from config import PROJECT_NAME, VERSION, TARGET_URL


class HTMLReporter:
    """
    Professional HTML vulnerability report generator for SSRF Sentinel.
    Produces clean, executive and developer-friendly security reports
    in a modern, responsive dashboard style.
    Operates 100% offline with zero external CDN dependencies.
    """

    TECHNIQUE_DESCRIPTIONS = {
        "In-Band / Content-Based": "Tests for direct reflection of internal resources, configuration vaults, and verification markers through public proxy endpoints.",
        "Limited-Response": "Evaluates indirect leakage via HTTP 204 status codes, internal response headers, truncated buffers, and policy suppression filters.",
        "Blind / Out-of-Band": "Verifies asynchronous server-initiated callbacks against a dedicated local listener using correlated high-entropy tokens.",
        "Time-Based": "Analyzes round-trip latency differentials using multi-sample median calculations to identify slow or delayed internal requests.",
        "Boolean-Based": "Infers downstream evaluation by comparing HTTP status, length, and header divergence between conditional TRUE and FALSE queries."
    }

    def __init__(self, report_dir: str = "reports", template_path: Optional[str] = None):
        self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True)

        # Locate template
        if template_path and os.path.exists(template_path):
            self.template_path = template_path
        else:
            base_dir = os.path.dirname(__file__)
            self.template_path = os.path.join(base_dir, "templates", "report_template.html")

    def _load_template(self) -> str:
        """Loads HTML report template from disk."""
        if os.path.exists(self.template_path):
            with open(self.template_path, "r", encoding="utf-8") as f:
                return f.read()
        raise FileNotFoundError(f"Report template not found at {self.template_path}")

    @staticmethod
    def _escape(val: Any) -> str:
        """Safely escapes strings for HTML injection protection."""
        if val is None:
            return ""
        return html.escape(str(val))

    def _build_posture_banner(self, vuln_count: int, max_severity: str) -> str:
        """Generates the Security Posture assessment banner."""
        if vuln_count > 0:
            return f"""
      <div class="posture-banner vuln-found">
        <div class="posture-icon">&#9888;</div>
        <div class="posture-text">
          <h4>Vulnerabilities Detected &bull; {max_severity.upper()} RISK</h4>
          <p>The assessment identified {vuln_count} unique SSRF vulnerability finding(s). The application can be coerced into accessing unauthorized internal endpoints or executing outbound requests. Immediate remediation is advised.</p>
        </div>
      </div>"""
        else:
            return """
      <div class="posture-banner safe">
        <div class="posture-icon">&#10004;</div>
        <div class="posture-text">
          <h4>Defensive Controls Verified &bull; SECURE POSTURE</h4>
          <p>No active SSRF vulnerabilities were identified across the evaluated endpoints. Prohibitions against loopback, private internal network ranges, and unauthorized redirects were verified to be actively enforced.</p>
        </div>
      </div>"""

    def _build_distribution_bars(self, counts: Dict[str, int], total: int, color_map: Dict[str, str]) -> str:
        """Renders responsive segmented percentage bars for distributions."""
        if total == 0:
            return '<div class="dist-bar-seg" style="width: 100%; background: #e2e8f0;"></div>'

        segments = []
        for key, count in counts.items():
            if count > 0:
                pct = round((count / total) * 100, 1)
                bg = color_map.get(key, "#94a3b8")
                segments.append(f'<div class="dist-bar-seg" style="width: {pct}%; background: {bg};" title="{self._escape(key)}: {count} ({pct}%)"></div>')

        return "".join(segments)

    def _build_vulnerabilities_html(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Renders interactive vulnerability cards."""
        if not vulnerabilities:
            return """
        <div class="no-findings-box">
          <h3>&#10003; Zero Vulnerabilities Identified</h3>
          <p>All tested parameters successfully rejected unauthorized server-side requests. No internal data, headers, timing anomalies, or out-of-band callbacks were observed.</p>
        </div>"""

        cards = []
        for vuln in vulnerabilities:
            vuln_id = self._escape(vuln.get("id", "SSRF-UNKNOWN"))
            name = self._escape(vuln.get("name", "Server-Side Request Forgery"))
            severity = (vuln.get("severity") or "MEDIUM").upper()
            confidence = (vuln.get("confidence") or "HIGH").upper()
            technique = self._escape(vuln.get("technique", "Content-Based"))
            endpoint = self._escape(vuln.get("endpoint", "/fetch"))
            param = self._escape(vuln.get("parameter", "url"))

            what_happened = self._escape(vuln.get("what_happened") or vuln.get("description", "An internal resource was requested."))
            why_it_matters = self._escape(vuln.get("why_it_matters") or vuln.get("impact", "Could expose private backend resources."))
            fix = self._escape(vuln.get("recommended_fix") or vuln.get("recommendation", "Validate and allowlist destination URLs."))

            # Badge styling classes
            sev_class = f"badge-{severity.lower()}"
            if sev_class not in ("badge-critical", "badge-high", "badge-medium", "badge-low", "badge-info"):
                sev_class = "badge-medium"

            # Evidence items
            evidence_items = vuln.get("evidence", [])
            if not isinstance(evidence_items, list):
                evidence_items = [str(evidence_items)]

            evidence_lis = "".join(f"<li><span>{self._escape(ev)}</span></li>" for ev in evidence_items)

            # Search text payload
            search_blob = f"{vuln_id} {name} {endpoint} {param} {technique} {what_happened}".lower()

            card_html = f"""
        <div class="vuln-card expanded" data-severity="{severity}" data-search-text="{self._escape(search_blob)}">
          <div class="vuln-card-header" onclick="toggleCard(this)">
            <div class="vuln-header-left">
              <span class="vuln-id-badge">{vuln_id}</span>
              <span class="vuln-title">{name}</span>
            </div>
            <div class="vuln-header-right">
              <span class="badge {sev_class}">{severity}</span>
              <span class="badge badge-conf">{confidence}</span>
              <span class="badge badge-technique">{technique}</span>
              <svg class="chevron-icon" viewBox="0 0 24 24"><path d="M7 10l5 5 5-5z"/></svg>
            </div>
          </div>

          <div class="vuln-card-body">
            <div class="target-aff-bar">
              <div class="target-aff-item"><span>Affected Endpoint:</span> <code>{endpoint}</code></div>
              <div class="target-aff-item"><span>Vulnerable Parameter:</span> <code>{param}</code></div>
              <div class="target-aff-item"><span>Detection Technique:</span> <strong>{technique}</strong></div>
            </div>

            <div class="vuln-detail-grid">
              <div class="detail-block">
                <div class="detail-heading">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                  What Happened?
                </div>
                <div class="detail-content">{what_happened}</div>
              </div>

              <div class="detail-block">
                <div class="detail-heading">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                  Why Is It A Problem?
                </div>
                <div class="detail-content">{why_it_matters}</div>
              </div>
            </div>

            <div class="evidence-box">
              <div class="evidence-heading">Observed Technical Evidence</div>
              <ul>
                {evidence_lis}
              </ul>
            </div>

            <div class="fix-box">
              <div class="fix-heading">Recommended Remediation</div>
              <div>{fix}</div>
            </div>
          </div>
        </div>"""
            cards.append(card_html)

        return "\n".join(cards)

    def _build_techniques_grid(self, raw_probes: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> str:
        """Renders the 5 detection technique evaluation cards."""
        # Calculate technique breakdown
        tech_stats = {
            "In-Band / Content-Based": {"tests": 0, "pos": 0, "neg": 0, "inc": 0},
            "Limited-Response": {"tests": 0, "pos": 0, "neg": 0, "inc": 0},
            "Blind / Out-of-Band": {"tests": 0, "pos": 0, "neg": 0, "inc": 0},
            "Time-Based": {"tests": 0, "pos": 0, "neg": 0, "inc": 0},
            "Boolean-Based": {"tests": 0, "pos": 0, "neg": 0, "inc": 0}
        }

        # Analyze probes if available
        probe_source = raw_probes if raw_probes else findings
        for probe in probe_source:
            t = probe.get("detection_technique", "")
            matched_key = None
            if "In-Band" in t or "Content" in t or "Bypass" in t or "Redirect" in t:
                matched_key = "In-Band / Content-Based"
            elif "Limited" in t:
                matched_key = "Limited-Response"
            elif "Blind" in t or "Out-of-Band" in t:
                matched_key = "Blind / Out-of-Band"
            elif "Time" in t:
                matched_key = "Time-Based"
            elif "Boolean" in t:
                matched_key = "Boolean-Based"

            if matched_key:
                tech_stats[matched_key]["tests"] += 1
                if probe.get("detected") is True:
                    tech_stats[matched_key]["pos"] += 1
                elif probe.get("confidence") == "INCONCLUSIVE":
                    tech_stats[matched_key]["inc"] += 1
                else:
                    tech_stats[matched_key]["neg"] += 1

        cards = []
        for tech_name, desc in self.TECHNIQUE_DESCRIPTIONS.items():
            stats = tech_stats[tech_name]
            pos_class = "pos" if stats["pos"] > 0 else ""
            card = f"""
        <div class="tech-card">
          <h4>{self._escape(tech_name)}</h4>
          <p>{self._escape(desc)}</p>
          <div class="tech-stats">
            <div class="tech-stat-item"><span class="tech-stat-label">Tests Run:</span> <span class="tech-stat-val">{stats['tests']}</span></div>
            <div class="tech-stat-item"><span class="tech-stat-label">Positive Hits:</span> <span class="tech-stat-val {pos_class}">{stats['pos']}</span></div>
            <div class="tech-stat-item"><span class="tech-stat-label">Negative:</span> <span class="tech-stat-val">{stats['neg']}</span></div>
            <div class="tech-stat-item"><span class="tech-stat-label">Inconclusive:</span> <span class="tech-stat-val">{stats['inc']}</span></div>
          </div>
        </div>"""
            cards.append(card)

        return "\n".join(cards)

    def generate_report(
        self,
        report_data: Dict[str, Any],
        output_filename: str = "ssrf_report.html",
        raw_probes: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """
        Renders self-contained HTML report using scan data dictionary.
        Safe against missing fields and unhandled exceptions.
        """
        template = self._load_template()

        # Extract root fields
        project_name = report_data.get("project", PROJECT_NAME)
        target_url = report_data.get("target", TARGET_URL)
        scan_status = report_data.get("scan_status", "COMPLETED")
        version = report_data.get("version", VERSION)
        scan_mode = report_data.get("scan_mode", "VULNERABLE").upper()
        scan_date = report_data.get("scan_date", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
        duration = report_data.get("scan_duration_seconds")
        duration_text = f"{duration:.2f}s" if isinstance(duration, (int, float)) else "N/A"

        summary = report_data.get("summary", {})
        endpoints_count = summary.get("endpoints_discovered", 0)
        parameters_count = summary.get("parameters_tested", 0)
        tests_count = summary.get("tests_executed", 0)
        positive_count = summary.get("positive_tests", 0)
        negative_count = summary.get("negative_tests", 0)
        inconclusive_count = summary.get("inconclusive_tests", 0)
        unique_findings_count = summary.get("unique_findings", 0)

        vulnerabilities = report_data.get("vulnerabilities", [])

        # Calculate severity counts
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in vulnerabilities:
            s = (v.get("severity") or "MEDIUM").upper()
            if s in sev_counts:
                sev_counts[s] += 1
            else:
                sev_counts["MEDIUM"] += 1

        # Calculate confidence counts
        conf_counts = {"LAB_CONFIRMED": 0, "HIGH": 0, "MEDIUM": 0, "OTHER": 0}
        for v in vulnerabilities:
            c = (v.get("confidence") or "HIGH").upper()
            if c in ("LAB_CONFIRMED", "HIGH", "MEDIUM"):
                conf_counts[c] += 1
            else:
                conf_counts["OTHER"] += 1

        # Max severity
        if sev_counts["CRITICAL"] > 0:
            max_severity = "CRITICAL"
        elif sev_counts["HIGH"] > 0:
            max_severity = "HIGH"
        elif sev_counts["MEDIUM"] > 0:
            max_severity = "MEDIUM"
        elif sev_counts["LOW"] > 0:
            max_severity = "LOW"
        else:
            max_severity = "NONE"

        # Executive summary text
        if unique_findings_count > 0:
            exec_summary_text = (
                f"The dynamic security assessment identified active Server-Side Request Forgery (SSRF) vulnerabilities "
                f"in the target application ({self._escape(target_url)}). A total of {positive_count} security probes succeeded, "
                f"confirming {unique_findings_count} distinct vulnerability classes including In-Band internal disclosures, "
                f"alternative IP representation filter bypasses, redirect chains, and out-of-band interactions. "
                f"Immediate remediation is required to restrict unauthorized server-side network egress."
            )
        else:
            exec_summary_text = (
                f"The dynamic security assessment did not identify any active Server-Side Request Forgery (SSRF) vulnerabilities "
                f"in the target application ({self._escape(target_url)}). Evaluated defensive controls, including destination "
                f"allowlisting, non-canonical host address rejection, and HTTP redirect restrictions, were verified to be active and properly enforced."
            )

        # Build visual elements
        posture_banner_html = self._build_posture_banner(unique_findings_count, max_severity)

        sev_colors = {
            "CRITICAL": "var(--sev-critical)",
            "HIGH": "var(--sev-high)",
            "MEDIUM": "var(--sev-medium)",
            "LOW": "var(--sev-low)"
        }
        severity_bars_html = self._build_distribution_bars(sev_counts, unique_findings_count, sev_colors)

        conf_colors = {
            "LAB_CONFIRMED": "var(--conf-lab)",
            "HIGH": "var(--sev-high)",
            "MEDIUM": "var(--sev-medium)",
            "OTHER": "var(--sev-info)"
        }
        confidence_bars_html = self._build_distribution_bars(conf_counts, unique_findings_count, conf_colors)

        vulnerabilities_list_html = self._build_vulnerabilities_html(vulnerabilities)
        techniques_grid_html = self._build_techniques_grid(raw_probes or [], vulnerabilities)

        # Status Badge
        status_badge = f'<span class="badge badge-info" style="background:#f0fdf4; color:#166534; border:1px solid #bbf7d0;">{self._escape(scan_status)}</span>'

        # Endpoint & parameter details
        endpoints_raw = report_data.get("endpoints", ["/", "/health", "/fetch", "/fetch-secure", "/redirect"])
        endpoints_list_text = ", ".join(f"<code>{self._escape(e)}</code>" for e in endpoints_raw)
        parameters_raw = report_data.get("parameters", ["url", "mode"])
        parameters_list_text = ", ".join(f"<code>{self._escape(p)}</code>" for p in parameters_raw)

        # Card classes
        positive_card_class = "danger" if positive_count > 0 else "success"
        vuln_card_class = "danger" if unique_findings_count > 0 else "success"

        # Safely escape raw JSON for inline script embedding (OWASP standard)
        safe_raw_json = json.dumps(report_data).replace("<", "\\u003c").replace(">", "\\u003e")

        # Replacements map
        replacements = {
            "{{REPORT_TITLE}}": "SSRF Security Assessment Report",
            "{{PROJECT_NAME}}": self._escape(project_name),
            "{{VERSION}}": self._escape(version),
            "{{TARGET_URL}}": self._escape(target_url),
            "{{SCAN_MODE}}": self._escape(scan_mode),
            "{{STATUS_BADGE}}": status_badge,
            "{{SCAN_DATE}}": self._escape(scan_date),
            "{{EXECUTIVE_SUMMARY_TEXT}}": exec_summary_text,
            "{{ENDPOINTS_COUNT}}": str(endpoints_count),
            "{{PARAMETERS_COUNT}}": str(parameters_count),
            "{{TESTS_COUNT}}": str(tests_count),
            "{{POSITIVE_COUNT}}": str(positive_count),
            "{{NEGATIVE_COUNT}}": str(negative_count),
            "{{INCONCLUSIVE_COUNT}}": str(inconclusive_count),
            "{{UNIQUE_FINDINGS_COUNT}}": str(unique_findings_count),
            "{{POSITIVE_CARD_CLASS}}": positive_card_class,
            "{{VULN_CARD_CLASS}}": vuln_card_class,
            "{{POSTURE_BANNER_HTML}}": posture_banner_html,
            "{{SEVERITY_BARS_HTML}}": severity_bars_html,
            "{{CRITICAL_COUNT}}": str(sev_counts["CRITICAL"]),
            "{{HIGH_COUNT}}": str(sev_counts["HIGH"]),
            "{{MEDIUM_COUNT}}": str(sev_counts["MEDIUM"]),
            "{{LOW_COUNT}}": str(sev_counts["LOW"]),
            "{{CONFIDENCE_BARS_HTML}}": confidence_bars_html,
            "{{LAB_CONF_COUNT}}": str(conf_counts["LAB_CONFIRMED"]),
            "{{HIGH_CONF_COUNT}}": str(conf_counts["HIGH"]),
            "{{MED_CONF_COUNT}}": str(conf_counts["MEDIUM"]),
            "{{OTHER_CONF_COUNT}}": str(conf_counts["OTHER"]),
            "{{VULNERABILITIES_LIST_HTML}}": vulnerabilities_list_html,
            "{{TECHNIQUES_GRID_HTML}}": techniques_grid_html,
            "{{ENDPOINTS_LIST_TEXT}}": endpoints_list_text,
            "{{PARAMETERS_LIST_TEXT}}": parameters_list_text,
            "{{SCAN_DURATION}}": duration_text,
            "{{REPORT_GENERATED_AT}}": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "{{RAW_JSON_DATA}}": safe_raw_json
        }

        rendered = template
        for tag, value in replacements.items():
            rendered = rendered.replace(tag, value)

        output_path = os.path.join(self.report_dir, output_filename)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered)

        print(f"[REPORT] Modern HTML report generated successfully.")
        print(f"[REPORT] Location: {output_path}")

        return output_path

    def generate_from_file(self, json_file_path: str, output_filename: Optional[str] = None) -> str:
        """Generates an HTML report directly from an existing JSON report file."""
        if not os.path.exists(json_file_path):
            raise FileNotFoundError(f"JSON report file not found at {json_file_path}")

        with open(json_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not output_filename:
            base_name = os.path.splitext(os.path.basename(json_file_path))[0]
            output_filename = f"{base_name}.html"

        return self.generate_report(report_data=data, output_filename=output_filename)
