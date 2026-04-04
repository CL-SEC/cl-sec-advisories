#!/usr/bin/env python3
"""Build a static site from CL-SEC advisory YAML files.

Generates:
  _site/index.html       - Searchable advisory table with detail modals
  _site/advisories.json  - Machine-readable advisory data
  _site/advisories.tar.gz - Tarball for cl-sec-audit
  _site/version.json     - Metadata
"""

import html as html_module
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import markdown

ADVISORY_DIR = Path("advisories")
SITE_DIR = Path("_site")


def parse_advisory_full(path):
    """Parse a CL-SEC advisory YAML file, extracting all fields."""
    adv = {}
    current_block = None  # for multiline |
    block_buf = []

    with open(path) as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        # Multiline block collection (preserve relative indent)
        if current_block is not None:
            if stripped == "" or indent > 1:
                # Strip exactly 2 chars of YAML indent, preserve the rest
                dedented = line[2:] if len(line) > 2 and line[:2] == "  " else line.lstrip()
                block_buf.append(dedented)
                i += 1
                continue
            else:
                adv[current_block] = "\n".join(block_buf).strip()
                current_block = None
                block_buf = []

        # Skip blanks and comments
        if stripped == "" or stripped.startswith("#"):
            i += 1
            continue

        # Strip inline comments (respecting quotes)
        clean = stripped
        if "#" in clean and not clean.startswith("#"):
            in_q = False
            for ci, ch in enumerate(clean):
                if ch == '"':
                    in_q = not in_q
                elif ch == '#' and not in_q and ci > 0 and clean[ci-1] == ' ':
                    clean = clean[:ci].rstrip()
                    break

        def yval(s):
            s = s.strip()
            if s in ("null", "~", "", "[]", "{}"):
                return None
            if s.startswith('"') and s.endswith('"'):
                return s[1:-1]
            return s

        # Indent 0: top-level
        if indent == 0 and ":" in clean:
            key, _, val = clean.partition(":")
            val = val.strip()
            if key in ("id", "title", "severity", "cvss", "cvss-score",
                       "cwe", "reported", "published"):
                adv[key] = yval(val)
            elif key == "description" and val == "|":
                current_block = "description"
                block_buf = []
                i += 1
                continue
            elif key == "recommendation" and val == "|":
                current_block = "recommendation"
                block_buf = []
                i += 1
                continue

        # Indent 2: sub-keys
        elif indent == 2 and ":" in clean:
            key, _, val = clean.partition(":")
            val = val.strip()
            if key == "name" and "project-name" not in adv:
                adv["project-name"] = yval(val)
            elif key == "homepage":
                adv["homepage"] = yval(val)
            elif key == "status":
                adv["status"] = yval(val)
            elif key == "verdict":
                adv["audit-verdict"] = yval(val)
            elif key == "description" and val == "|":
                current_block = "description"
                block_buf = []
            elif key == "recommendation" and val == "|":
                current_block = "recommendation"
                block_buf = []
            elif key == "notes" and val == "|":
                current_block = "audit-notes"
                block_buf = []

        # Indent 4: affected-systems, unaffected-systems, fixed-in/introduced-in sub-fields
        elif indent == 4 and ":" in clean:
            key, _, val = clean.partition(":")
            val = val.strip()
            if key == "commit":
                # Could be introduced-in or fixed-in commit
                # Determine context from previous lines
                for j in range(i-1, max(i-5, 0), -1):
                    pl = lines[j].strip()
                    if "introduced-in" in pl:
                        adv["introduced-commit"] = yval(val)
                        break
                    elif "fixed-in" in pl:
                        adv["fixed-commit"] = yval(val)
                        break
            elif key == "version":
                for j in range(i-1, max(i-5, 0), -1):
                    pl = lines[j].strip()
                    if "fixed-in" in pl or "commit" in pl:
                        adv["fixed-version"] = yval(val)
                        break
            elif key == "url":
                for j in range(i-1, max(i-6, 0), -1):
                    pl = lines[j].strip()
                    if "introduced-in" in pl:
                        adv["introduced-url"] = yval(val)
                        break
                    elif "fixed-in" in pl:
                        adv["fixed-url"] = yval(val)
                        break
            elif clean.startswith("- "):
                item = yval(clean[2:])
                # Check context
                for j in range(i-1, max(i-5, 0), -1):
                    pl = lines[j].strip()
                    if "affected-systems" in pl:
                        adv.setdefault("affected-systems", []).append(item)
                        break
                    elif "unaffected-systems" in pl:
                        adv.setdefault("unaffected-systems", []).append(item)
                        break

        i += 1

    # Finish any pending block
    if current_block:
        adv[current_block] = "\n".join(block_buf).strip()

    return adv


def esc(s):
    return html_module.escape(s or "", quote=True)


def severity_class(sev):
    return {"critical": "severity-critical", "high": "severity-high",
            "medium": "severity-medium", "low": "severity-low",
            "informational": "severity-info"}.get(sev, "")


def severity_order(sev):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3,
            "informational": 4}.get(sev, 5)


def get_status_info(a):
    """Determine display status from advisory fields.

    Returns (label, css_class) tuple.
    """
    verdict = a.get("audit-verdict", "")
    status = a.get("status", "")
    has_fix = bool(a.get("fixed-commit") or a.get("fixed-version"))

    if verdict == "withdrawn" or status == "withdrawn":
        return ("Withdrawn", "status-withdrawn")
    if verdict == "disputed" or status == "disputed":
        if has_fix:
            return ("Fixed", "status-fixed")
        return ("Disputed", "status-disputed")
    if has_fix:
        return ("Fixed", "status-fixed")
    return ("Open", "status-open")


_md = markdown.Markdown(extensions=["fenced_code", "tables"])

def desc_to_html(desc):
    """Convert advisory description/recommendation markdown to HTML."""
    if not desc:
        return ""
    # Escape '#' at start of lines that aren't intended as markdown headings —
    # e.g. Lisp's #. reader macro.  Lines inside fenced code blocks are
    # handled by the fenced_code extension and won't reach here as bare text.
    escaped = re.sub(r"^(#{1,6})(?=\S)", r"\\\1", desc, flags=re.MULTILINE)
    _md.reset()
    return _md.convert(escaped)


def build_modal(a):
    """Build modal HTML for one advisory."""
    aid = esc(a.get("id", ""))
    sev = a.get("severity", "")
    status_label, status_css = get_status_info(a)

    cwe = a.get("cwe", "")
    cwe_html = ""
    if cwe and cwe.startswith("CWE-"):
        num = cwe.split("-")[1].split(" ")[0]
        cwe_html = f'<a href="https://cwe.mitre.org/data/definitions/{num}.html" target="_blank">{esc(cwe)}</a>'
    else:
        cwe_html = esc(cwe)

    homepage = a.get("homepage", "")
    project = esc(a.get("project-name", ""))

    # Affected/unaffected systems
    affected = a.get("affected-systems", [])
    unaffected = a.get("unaffected-systems", [])
    systems_html = ""
    if affected:
        systems_html += "<strong>Affected:</strong> " + ", ".join(f"<code>{esc(s)}</code>" for s in affected)
    if unaffected:
        systems_html += " &nbsp; <strong>Unaffected:</strong> " + ", ".join(f"<code>{esc(s)}</code>" for s in unaffected)

    # Introduced/Fixed
    intro_html = ""
    if a.get("introduced-url"):
        intro_html = f'<a href="{esc(a["introduced-url"])}" target="_blank">{esc(a.get("introduced-commit", ""))}</a>'
    elif a.get("introduced-commit"):
        intro_html = f'<code>{esc(a["introduced-commit"])}</code>'

    fix_html = ""
    if a.get("fixed-url"):
        fix_html = f'<a href="{esc(a["fixed-url"])}" target="_blank">{esc(a.get("fixed-commit", ""))}</a>'
        if a.get("fixed-version"):
            fix_html += f' (v{esc(a["fixed-version"])})'
    elif a.get("fixed-commit"):
        fix_html = f'<code>{esc(a["fixed-commit"])}</code>'
    elif a.get("fixed-version"):
        fix_html = f'v{esc(a["fixed-version"])}'

    # Audit notes
    audit_html = ""
    audit_notes = a.get("audit-notes", "")
    verdict = a.get("audit-verdict", "")
    if verdict or audit_notes:
        audit_html = '<div class="section audit-section">'
        audit_html += '<h3>Audit</h3>'
        if verdict:
            audit_html += f'<p><strong>Verdict:</strong> <span class="badge {status_css}">{esc(verdict)}</span></p>'
        if audit_notes:
            audit_html += desc_to_html(audit_notes)
        audit_html += '</div>'

    return f"""<div id="modal-{aid}" class="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal-content">
    <div class="modal-header">
      <div>
        <span class="modal-id">{aid}</span>
        <span class="badge {severity_class(sev)}">{sev.upper()}</span>
        <span class="badge cvss">CVSS {esc(str(a.get("cvss-score", "")))}</span>
        <span class="badge {status_css}">{status_label}</span>
      </div>
      <button class="close-btn" onclick="closeModal()">&times;</button>
    </div>
    <h2>{esc(a.get("title", ""))}</h2>
    <div class="meta">
      <div><strong>Project:</strong> <a href="{esc(homepage)}" target="_blank">{project}</a></div>
      <div>{systems_html}</div>
      <div><strong>CWE:</strong> {cwe_html}</div>
      <div><strong>Reported:</strong> {esc(a.get("reported", ""))} &nbsp; <strong>Published:</strong> {esc(a.get("published", ""))}</div>
      {f'<div><strong>Introduced:</strong> {intro_html}</div>' if intro_html else ''}
      {f'<div><strong>Fixed:</strong> {fix_html}</div>' if fix_html else ''}
    </div>
    <div class="section">
      <h3>Description</h3>
      {desc_to_html(a.get("description", ""))}
    </div>
    {audit_html}
  </div>
</div>"""


def build_html(advisories):
    rows = []
    modals = []

    # Count statuses for stats
    status_counts = {"Fixed": 0, "Open": 0, "Withdrawn": 0, "Disputed": 0}

    for a in sorted(advisories, key=lambda x: (severity_order(x.get("severity", "")),
                                                 -(float(x.get("cvss-score") or 0)))):
        sev = a.get("severity", "")
        score = a.get("cvss-score", "")
        cwe = a.get("cwe", "")
        homepage = a.get("homepage", "")
        project = a.get("project-name", "")
        aid = a.get("id", "")
        status_label, status_css = get_status_info(a)

        status_counts[status_label] = status_counts.get(status_label, 0) + 1

        rows.append(f"""        <tr onclick="openModal('{aid}')" style="cursor:pointer">
          <td><strong>{esc(aid)}</strong></td>
          <td>{esc(project)}</td>
          <td class="{severity_class(sev)}">{sev.upper()}</td>
          <td>{esc(str(score))}</td>
          <td>{esc(a.get("title", ""))}</td>
          <td><span class="status-pill {status_css}">{status_label}</span></td>
          <td>{esc(a.get("published", "") or "")}</td>
        </tr>""")

        modals.append(build_modal(a))

    table_rows = "\n".join(rows)
    modal_html = "\n".join(modals)

    n_fixed = status_counts.get("Fixed", 0)
    n_open = status_counts.get("Open", 0)
    n_withdrawn = status_counts.get("Withdrawn", 0)
    n_disputed = status_counts.get("Disputed", 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CL-SEC Advisory Database</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/simple-datatables@9/dist/style.min.css">
  <style>
    :root {{ --bg: #f8f9fa; --card: white; --text: #1a1a2e; --muted: #666; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
           margin: 0; padding: 20px; background: var(--bg); color: var(--text); }}
    .container {{ max-width: 1400px; margin: 0 auto; }}
    h1 {{ margin-bottom: 5px; }}
    .subtitle {{ color: var(--muted); margin-bottom: 20px; }}
    .stats {{ display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; }}
    .stat {{ background: var(--card); padding: 12px 20px; border-radius: 8px;
             box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    .stat .number {{ font-size: 24px; font-weight: bold; }}
    .stat .label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; }}
    .stat.critical .number {{ color: #d32f2f; }}
    .stat.high .number {{ color: #f57c00; }}
    .stat.medium .number {{ color: #fbc02d; }}
    .stat.low .number {{ color: #388e3c; }}
    .stat.fixed .number {{ color: #1565c0; }}
    .stat.open .number {{ color: #d32f2f; }}
    table {{ background: var(--card); border-radius: 8px; overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    td, th {{ padding: 8px 12px; font-size: 14px; }}
    tbody tr:hover {{ background: #e3f2fd; }}
    .severity-critical {{ color: #d32f2f; font-weight: bold; }}
    .severity-high {{ color: #f57c00; font-weight: bold; }}
    .severity-medium {{ color: #f9a825; }}
    .severity-low {{ color: #388e3c; }}
    .severity-info {{ color: #9e9e9e; }}
    a {{ color: #1565c0; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .footer {{ margin-top: 30px; color: #999; font-size: 12px; text-align: center; }}

    /* Status pills */
    .status-pill {{ display: inline-block; padding: 2px 10px; border-radius: 12px;
                    font-size: 12px; font-weight: 600; white-space: nowrap; }}
    .status-fixed {{ background: #e3f2fd; color: #1565c0; }}
    .status-open {{ background: #fce4ec; color: #c62828; }}
    .status-withdrawn {{ background: #f5f5f5; color: #9e9e9e; text-decoration: line-through; }}
    .status-disputed {{ background: #fff3e0; color: #e65100; }}

    /* Modal */
    .modal {{ display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
              background: rgba(0,0,0,0.5); z-index: 1000; overflow-y: auto;
              backdrop-filter: blur(2px); }}
    .modal.active {{ display: flex; justify-content: center; padding: 40px 20px; }}
    .modal-content {{ background: var(--card); border-radius: 12px; max-width: 800px; width: 100%;
                      padding: 30px; box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                      max-height: calc(100vh - 80px); overflow-y: auto; align-self: flex-start; }}
    .modal-header {{ display: flex; justify-content: space-between; align-items: center;
                     margin-bottom: 10px; }}
    .modal-id {{ font-family: monospace; font-size: 14px; color: var(--muted); }}
    .close-btn {{ background: none; border: none; font-size: 28px; cursor: pointer;
                  color: var(--muted); padding: 0 5px; }}
    .close-btn:hover {{ color: var(--text); }}
    .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px;
              font-size: 12px; font-weight: bold; margin-left: 8px; }}
    .badge.severity-critical {{ background: #ffcdd2; color: #b71c1c; }}
    .badge.severity-high {{ background: #ffe0b2; color: #e65100; }}
    .badge.severity-medium {{ background: #fff9c4; color: #f57f17; }}
    .badge.severity-low {{ background: #c8e6c9; color: #1b5e20; }}
    .badge.severity-info {{ background: #f5f5f5; color: #9e9e9e; }}
    .badge.cvss {{ background: #e8eaf6; color: #283593; }}
    .badge.status-fixed {{ background: #e3f2fd; color: #1565c0; }}
    .badge.status-open {{ background: #fce4ec; color: #c62828; }}
    .badge.status-withdrawn {{ background: #f5f5f5; color: #9e9e9e; }}
    .badge.status-disputed {{ background: #fff3e0; color: #e65100; }}
    .modal-content h2 {{ margin: 10px 0 15px; font-size: 20px; }}
    .meta {{ background: #f5f5f5; padding: 12px 16px; border-radius: 8px;
             margin-bottom: 20px; font-size: 14px; line-height: 1.8; }}
    .meta code {{ background: #e0e0e0; padding: 1px 6px; border-radius: 3px; font-size: 13px; }}
    .section {{ margin-bottom: 20px; }}
    .section h3 {{ font-size: 16px; margin-bottom: 8px; color: #333; border-bottom: 1px solid #eee;
                   padding-bottom: 5px; }}
    .section p {{ font-size: 14px; line-height: 1.6; margin: 8px 0; }}
    .section pre {{ background: #263238; color: #eeffff; padding: 12px 16px; border-radius: 6px;
                    overflow-x: auto; font-size: 13px; }}
    .section code {{ font-size: 13px; }}
    .audit-section {{ background: #fffde7; padding: 16px; border-radius: 8px;
                      border-left: 4px solid #fbc02d; }}
    .audit-section h3 {{ border-bottom-color: #fbc02d; }}
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
      <div class="stat fixed">
        <div class="number">{n_fixed}</div>
        <div class="label">Fixed</div>
      </div>
      <div class="stat open">
        <div class="number">{n_open}</div>
        <div class="label">Open</div>
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
          <th>Status</th>
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

  <!-- Modals -->
{modal_html}

  <script src="https://cdn.jsdelivr.net/npm/simple-datatables@9" type="text/javascript"></script>
  <script>
    new simpleDatatables.DataTable("#advisories", {{
      searchable: true,
      perPage: 50,
      perPageSelect: [25, 50, 100],
    }});

    function openModal(id) {{
      document.getElementById('modal-' + id).classList.add('active');
      document.body.style.overflow = 'hidden';
      history.pushState(null, '', '#' + id);
    }}

    function closeModal() {{
      document.querySelectorAll('.modal.active').forEach(m => m.classList.remove('active'));
      document.body.style.overflow = '';
      history.pushState(null, '', location.pathname);
    }}

    document.addEventListener('keydown', e => {{ if (e.key === 'Escape') closeModal(); }});

    // Open modal from URL hash on load
    if (location.hash) {{
      const id = location.hash.substring(1);
      const modal = document.getElementById('modal-' + id);
      if (modal) openModal(id);
    }}
  </script>
  <script>
    window.HAPPENING_SITE_ID='CTuYcrXl1uCI';
  </script>
  <script src="https://happening.labdroid.net/js/tracker.js" defer></script>
</body>
</html>"""


def main():
    SITE_DIR.mkdir(exist_ok=True)

    advisories = []
    for f in sorted(ADVISORY_DIR.glob("*.yaml")):
        adv = parse_advisory_full(f)
        if adv.get("id"):
            advisories.append(adv)

    print(f"Parsed {len(advisories)} advisories")

    html = build_html(advisories)
    (SITE_DIR / "index.html").write_text(html)
    print("Built index.html")

    (SITE_DIR / "advisories.json").write_text(json.dumps(advisories, indent=2))
    print("Built advisories.json")

    subprocess.run(["tar", "czf", str(SITE_DIR / "advisories.tar.gz"),
                    "-C", "advisories", "."], check=True)
    print("Built advisories.tar.gz")

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
