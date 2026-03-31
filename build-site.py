#!/usr/bin/env python3
"""Build a static site from CL-SEC advisory YAML files.

Generates:
  _site/index.html       - Searchable advisory table
  _site/advisories.json  - Machine-readable advisory data
  _site/advisories.tar.gz - Tarball for cl-sec-audit
  _site/version.json     - Metadata
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ADVISORY_DIR = Path("advisories")
SITE_DIR = Path("_site")


def parse_yaml_value(s):
    s = s.strip()
    if s in ("null", "~", ""):
        return None
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


def parse_advisory(path):
    """Minimal YAML parser for CL-SEC advisory files."""
    adv = {}
    with open(path) as f:
        for line in f:
            line = line.rstrip()
            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            if indent == 0 and ":" in stripped:
                key, _, val = stripped.partition(":")
                val = val.split("#")[0].strip()
                if key in ("id", "title", "severity", "cvss-score", "cwe",
                           "reported", "published"):
                    adv[key] = parse_yaml_value(val)
            elif indent == 2 and ":" in stripped:
                key, _, val = stripped.partition(":")
                val = val.split("#")[0].strip()
                if key == "name" and "project-name" not in adv:
                    adv["project-name"] = parse_yaml_value(val)
                elif key == "homepage":
                    adv["homepage"] = parse_yaml_value(val)
    return adv


def severity_class(sev):
    return {
        "critical": "severity-critical",
        "high": "severity-high",
        "medium": "severity-medium",
        "low": "severity-low",
    }.get(sev, "")


def severity_order(sev):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(sev, 4)


def build_html(advisories):
    rows = []
    for a in sorted(advisories, key=lambda x: (severity_order(x.get("severity", "")),
                                                 -(float(x.get("cvss-score") or 0)))):
        sev = a.get("severity", "")
        score = a.get("cvss-score", "")
        cwe = a.get("cwe", "")
        cwe_url = ""
        if cwe and cwe.startswith("CWE-"):
            num = cwe.split("-")[1].split(" ")[0]
            cwe_url = f"https://cwe.mitre.org/data/definitions/{num}.html"

        homepage = a.get("homepage", "")
        project = a.get("project-name", "")
        project_link = f'<a href="{homepage}">{project}</a>' if homepage else project

        rows.append(f"""        <tr>
          <td><strong>{a.get("id", "")}</strong></td>
          <td>{project_link}</td>
          <td class="{severity_class(sev)}">{sev.upper()}</td>
          <td>{score}</td>
          <td>{a.get("title", "")}</td>
          <td>{"<a href='" + cwe_url + "'>" + cwe + "</a>" if cwe_url else cwe}</td>
          <td>{a.get("published", "") or ""}</td>
        </tr>""")

    table_rows = "\n".join(rows)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CL-SEC Advisory Database</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/simple-datatables@9/dist/style.min.css">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
           margin: 0; padding: 20px; background: #f8f9fa; }}
    .container {{ max-width: 1400px; margin: 0 auto; }}
    h1 {{ color: #1a1a2e; margin-bottom: 5px; }}
    .subtitle {{ color: #666; margin-bottom: 20px; }}
    .stats {{ display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; }}
    .stat {{ background: white; padding: 12px 20px; border-radius: 8px;
             box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    .stat .number {{ font-size: 24px; font-weight: bold; }}
    .stat .label {{ font-size: 12px; color: #666; text-transform: uppercase; }}
    .stat.critical .number {{ color: #d32f2f; }}
    .stat.high .number {{ color: #f57c00; }}
    .stat.medium .number {{ color: #fbc02d; }}
    .stat.low .number {{ color: #388e3c; }}
    table {{ background: white; border-radius: 8px; overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    td, th {{ padding: 8px 12px; font-size: 14px; }}
    .severity-critical {{ color: #d32f2f; font-weight: bold; }}
    .severity-high {{ color: #f57c00; font-weight: bold; }}
    .severity-medium {{ color: #f9a825; }}
    .severity-low {{ color: #388e3c; }}
    a {{ color: #1565c0; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .footer {{ margin-top: 30px; color: #999; font-size: 12px; text-align: center; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>CL-SEC Advisory Database</h1>
    <p class="subtitle">Security vulnerabilities in the Common Lisp ecosystem</p>

    <div class="stats">
      <div class="stat critical">
        <div class="number">{sum(1 for a in advisories if a.get("severity") == "critical")}</div>
        <div class="label">Critical</div>
      </div>
      <div class="stat high">
        <div class="number">{sum(1 for a in advisories if a.get("severity") == "high")}</div>
        <div class="label">High</div>
      </div>
      <div class="stat medium">
        <div class="number">{sum(1 for a in advisories if a.get("severity") == "medium")}</div>
        <div class="label">Medium</div>
      </div>
      <div class="stat low">
        <div class="number">{sum(1 for a in advisories if a.get("severity") == "low")}</div>
        <div class="label">Low</div>
      </div>
      <div class="stat">
        <div class="number">{len(advisories)}</div>
        <div class="label">Total</div>
      </div>
    </div>

    <table id="advisories">
      <thead>
        <tr>
          <th>ID</th>
          <th>Project</th>
          <th>Severity</th>
          <th>CVSS</th>
          <th>Title</th>
          <th>CWE</th>
          <th>Published</th>
        </tr>
      </thead>
      <tbody>
{table_rows}
      </tbody>
    </table>

    <p class="footer">
      <a href="https://github.com/CL-SEC/cl-sec-advisories">GitHub</a> &middot;
      <a href="advisories.tar.gz">Download database</a> &middot;
      <a href="advisories.json">JSON API</a> &middot;
      Generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
    </p>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/simple-datatables@9" type="text/javascript"></script>
  <script>
    new simpleDatatables.DataTable("#advisories", {{
      searchable: true,
      perPage: 50,
      perPageSelect: [25, 50, 100],
      columns: [
        {{ select: 3, sort: "desc", type: "number" }},
      ]
    }});
  </script>
</body>
</html>"""


def main():
    SITE_DIR.mkdir(exist_ok=True)

    # Parse all advisories
    advisories = []
    for f in sorted(ADVISORY_DIR.glob("*.yaml")):
        adv = parse_advisory(f)
        if adv.get("id"):
            advisories.append(adv)

    print(f"Parsed {len(advisories)} advisories")

    # Build HTML
    html = build_html(advisories)
    (SITE_DIR / "index.html").write_text(html)
    print("Built index.html")

    # Build JSON
    (SITE_DIR / "advisories.json").write_text(
        json.dumps(advisories, indent=2))
    print("Built advisories.json")

    # Build tarball
    subprocess.run(["tar", "czf", str(SITE_DIR / "advisories.tar.gz"),
                    "-C", "advisories", "."], check=True)
    print("Built advisories.tar.gz")

    # Build version.json
    commit = subprocess.run(["git", "rev-parse", "HEAD"],
                           capture_output=True, text=True).stdout.strip()
    version = {
        "commit": commit,
        "count": len(advisories),
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (SITE_DIR / "version.json").write_text(json.dumps(version, indent=2))
    print("Built version.json")


if __name__ == "__main__":
    main()
