#!/usr/bin/env python3
"""Index MITRE ATT&CK STIX bundles into knowledge/knowledge.db web_articles table.

Usage:
    python3 tools/index_mitre_attck.py [--skip-existing]
"""

import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "knowledge" / "knowledge.db"

STIX_FILES = [
    ("/tmp/attck_enterprise.json", "enterprise"),
    ("/tmp/attck_mobile.json", "mobile"),
    ("/tmp/attck_ics.json", "ics"),
]

FETCH_DATE = datetime.now().strftime("%Y-%m-%d")


def ensure_table(conn: sqlite3.Connection):
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS web_articles USING fts5(
            title, content, category, tags,
            source_url UNINDEXED, domain UNINDEXED, fetch_date UNINDEXED,
            tokenize = 'porter ascii'
        )
    """)
    conn.commit()


def existing_urls(conn: sqlite3.Connection) -> set:
    rows = conn.execute("SELECT source_url FROM web_articles WHERE domain = 'attack.mitre.org'").fetchall()
    return {r[0] for r in rows}


def mitre_id(obj: dict) -> str:
    """Extract T-number from external_references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def technique_url(tid: str) -> str:
    """Build canonical ATT&CK URL. Handles subtechniques T1059.001 → /T1059/001/"""
    if "." in tid:
        parent, sub = tid.split(".", 1)
        return f"https://attack.mitre.org/techniques/{parent}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tid}/"


def build_tags(obj: dict, domain_hint: str) -> str:
    tags = set()
    tags.add(f"attck-{domain_hint}")

    for phase in obj.get("kill_chain_phases", []):
        phase_name = phase.get("phase_name", "").replace("-", " ")
        if phase_name:
            tags.add(phase_name)

    for plat in obj.get("x_mitre_platforms", []):
        tags.add(plat.lower().replace(" ", "-"))

    # Tag from tactic
    tid = mitre_id(obj)
    if tid.startswith("T"):
        tags.add("technique")
    if "." in tid:
        tags.add("subtechnique")

    # Vulnerability-type hints from description
    desc_lower = (obj.get("description", "") + " " + obj.get("x_mitre_detection", "")).lower()
    keyword_map = {
        "injection": "injection",
        "buffer overflow": "bof",
        "use-after-free": "uaf",
        "privilege escalation": "privesc",
        "credential": "credential",
        "phishing": "phishing",
        "malware": "malware",
        "backdoor": "backdoor",
        "persistence": "persistence",
        "lateral movement": "lateral-movement",
        "exfiltration": "exfiltration",
        "command and control": "c2",
        "ransomware": "ransomware",
        "rootkit": "rootkit",
        "keylog": "keylogger",
        "bypass": "bypass",
        "obfuscat": "obfuscation",
        "encrypt": "encryption",
        "powershell": "powershell",
        "python": "python",
        "javascript": "javascript",
        "bash": "bash",
        "linux": "linux",
        "windows": "windows",
        "macos": "macos",
        "cloud": "cloud",
        "container": "container",
        "kubernetes": "kubernetes",
        "aws": "aws",
        "azure": "azure",
        "active directory": "active-directory",
        "kerberos": "kerberos",
        "mimikatz": "mimikatz",
        "cobalt strike": "cobalt-strike",
    }
    for kw, tag in keyword_map.items():
        if kw in desc_lower:
            tags.add(tag)

    return ", ".join(sorted(tags))


def build_content(obj: dict, tid: str, domain_hint: str) -> str:
    name = obj.get("name", "")
    description = obj.get("description", "").strip()
    detection = obj.get("x_mitre_detection", "").strip()
    platforms = ", ".join(obj.get("x_mitre_platforms", []))
    data_sources = ", ".join(obj.get("x_mitre_data_sources", []))
    defenses_bypassed = ", ".join(obj.get("x_mitre_defense_bypassed", []))
    permissions = ", ".join(obj.get("x_mitre_permissions_required", []))
    remote_support = obj.get("x_mitre_remote_support", False)
    system_requirements = obj.get("x_mitre_system_requirements", [])
    contributors = ", ".join(obj.get("x_mitre_contributors", []))

    # Kill chain phases
    phases = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]
    phases_str = ", ".join(phases)

    # External references (CVEs, URLs)
    refs = []
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            continue
        url = ref.get("url", "")
        desc_ref = ref.get("description", "")
        src = ref.get("source_name", "")
        entry = f"[{src}] {desc_ref} {url}".strip()
        if entry and entry != f"[{src}]":
            refs.append(entry)

    parts = [
        f"# MITRE ATT&CK {tid} - {name}",
        f"",
        f"**Domain**: {domain_hint.upper()}",
        f"**Tactic(s)**: {phases_str}",
        f"**Platforms**: {platforms}",
    ]

    if permissions:
        parts.append(f"**Permissions Required**: {permissions}")
    if defenses_bypassed:
        parts.append(f"**Defenses Bypassed**: {defenses_bypassed}")
    if data_sources:
        parts.append(f"**Data Sources**: {data_sources}")
    if remote_support:
        parts.append(f"**Remote Support**: Yes")
    if system_requirements:
        parts.append(f"**System Requirements**: {'; '.join(system_requirements)}")

    parts.append("")
    parts.append("## Description")
    parts.append(description or "(no description)")

    if detection:
        parts.append("")
        parts.append("## Detection")
        parts.append(detection)

    if refs:
        parts.append("")
        parts.append("## References")
        for r in refs[:20]:  # cap at 20 refs
            parts.append(f"- {r}")

    if contributors:
        parts.append("")
        parts.append(f"*Contributors: {contributors}*")

    return "\n".join(parts)


def index_bundle(conn: sqlite3.Connection, stix_path: str, domain_hint: str,
                 skip_existing: bool, already_indexed: set) -> tuple[int, int, int]:
    """Returns (inserted, skipped, errors)."""
    print(f"\n--- Loading {stix_path} ({domain_hint}) ---")
    with open(stix_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])
    techniques = [o for o in objects if o.get("type") == "attack-pattern"
                  and not o.get("x_mitre_deprecated", False)
                  and not o.get("revoked", False)]

    print(f"  Found {len(techniques)} active attack-patterns (out of {len(objects)} total objects)")

    inserted = skipped = errors = 0

    for obj in techniques:
        tid = mitre_id(obj)
        if not tid:
            errors += 1
            continue

        url = technique_url(tid)

        if skip_existing and url in already_indexed:
            skipped += 1
            continue

        name = obj.get("name", "Unknown")
        title = f"MITRE ATT&CK {tid} - {name}"
        content = build_content(obj, tid, domain_hint)
        tags = build_tags(obj, domain_hint)

        try:
            # Remove old entry if updating
            if url in already_indexed:
                conn.execute("DELETE FROM web_articles WHERE source_url = ?", (url,))

            conn.execute(
                "INSERT INTO web_articles (title, content, category, tags, source_url, domain, fetch_date) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (title, content, "mitre-attck", tags, url, "attack.mitre.org", FETCH_DATE)
            )
            already_indexed.add(url)
            inserted += 1

            if inserted % 100 == 0:
                conn.commit()
                print(f"  ... {inserted} inserted so far")

        except sqlite3.Error as e:
            print(f"  DB ERROR for {tid}: {e}")
            errors += 1

    conn.commit()
    return inserted, skipped, errors


def main():
    skip_existing = "--skip-existing" in sys.argv

    print(f"MITRE ATT&CK Indexer")
    print(f"DB: {DB_PATH}")
    print(f"Skip existing: {skip_existing}")
    print(f"Date: {FETCH_DATE}")

    conn = sqlite3.connect(str(DB_PATH))
    try:
        ensure_table(conn)
        already_indexed = existing_urls(conn)
        print(f"\nAlready indexed ATT&CK URLs: {len(already_indexed)}")

        total_inserted = total_skipped = total_errors = 0

        for stix_path, domain_hint in STIX_FILES:
            if not Path(stix_path).exists():
                print(f"MISSING: {stix_path} — skipping")
                continue
            ins, skip, err = index_bundle(conn, stix_path, domain_hint, skip_existing, already_indexed)
            total_inserted += ins
            total_skipped += skip
            total_errors += err
            print(f"  Domain '{domain_hint}': inserted={ins}, skipped={skip}, errors={err}")

        print(f"\n{'='*60}")
        print(f"TOTAL: inserted={total_inserted}, skipped={total_skipped}, errors={total_errors}")

        # Final stats
        count = conn.execute("SELECT COUNT(*) FROM web_articles WHERE domain = 'attack.mitre.org'").fetchone()[0]
        cats = conn.execute(
            "SELECT tags, COUNT(*) FROM web_articles WHERE domain='attack.mitre.org' "
            "AND tags LIKE 'attck-%' GROUP BY 1 ORDER BY 2 DESC LIMIT 5"
        ).fetchall()
        print(f"Total ATT&CK entries in DB: {count}")

        total_wa = conn.execute("SELECT COUNT(*) FROM web_articles").fetchone()[0]
        print(f"Total web_articles entries: {total_wa}")

    finally:
        conn.close()


if __name__ == "__main__":
    main()
