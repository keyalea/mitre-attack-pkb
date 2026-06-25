#!/usr/bin/env python3
"""
extract_attack.py — Extract ATT&CK v19 technique data from local STIX bundle
and output JavaScript ready to paste into mitre-attack-pkb.html DATA array.

Usage:
  # Extract specific techniques (parent + all its subs):
  python3 extract_attack.py T1059
  python3 extract_attack.py T1059 T1003

  # Extract a single sub-technique:
  python3 extract_attack.py T1059.001

  # Extract all techniques in a tactic:
  python3 extract_attack.py --tactic "Credential Access"

  # List all available tactics:
  python3 extract_attack.py --list-tactics

  # List all technique IDs in a tactic:
  python3 extract_attack.py --list-tactic "Credential Access"
"""

import json
import sys
import re
import os
import textwrap

# Set this to the directory where you downloaded the MITRE ATT&CK STIX bundles.
# Download from: https://github.com/mitre-attack/attack-stix-data
STIX_BASE = "/change-your-path/attack-stix-data"
STIX_FILE = os.path.join(STIX_BASE, "enterprise-attack", "enterprise-attack-19.1.json")

TACTIC_DISPLAY = {
    "initial-access":        "Initial Access",
    "execution":             "Execution",
    "persistence":           "Persistence",
    "privilege-escalation":  "Privilege Escalation",
    "stealth":               "Stealth",
    "defense-impairment":    "Defense Impairment",
    "credential-access":     "Credential Access",
    "discovery":             "Discovery",
    "lateral-movement":      "Lateral Movement",
    "collection":            "Collection",
    "command-and-control":   "Command and Control",
    "exfiltration":          "Exfiltration",
    "impact":                "Impact",
    "resource-development":  "Resource Development",
    "reconnaissance":        "Reconnaissance",
}


def load_stix():
    with open(STIX_FILE) as f:
        return json.load(f)["objects"]


def build_index(objects):
    """Build lookup tables from the STIX object list."""
    by_id = {o["id"]: o for o in objects}

    # technique external_id → object
    techniques = {}
    for o in objects:
        if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("deprecated"):
            for ref in o.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    techniques[ref["external_id"]] = o
                    break

    # data-component id → name
    data_components = {}
    for o in objects:
        if o["type"] == "x-mitre-data-component":
            data_components[o["id"]] = o["name"]

    # analytic id → object
    analytics = {o["id"]: o for o in objects if o["type"] == "x-mitre-analytic"}

    # detection-strategy id → object
    det_strategies = {o["id"]: o for o in objects if o["type"] == "x-mitre-detection-strategy"}

    # technique stix-id → list of detection-strategy ids
    tech_to_det = {}
    for o in objects:
        if o["type"] == "relationship" and o.get("relationship_type") == "detects":
            src, tgt = o["source_ref"], o["target_ref"]
            if src in det_strategies:
                tech_to_det.setdefault(tgt, []).append(src)

    # parent technique external_id → list of sub-technique external_ids
    subtechnique_map = {}
    for o in objects:
        if o["type"] == "relationship" and o.get("relationship_type") == "subtechnique-of":
            child_obj = by_id.get(o["source_ref"])
            parent_obj = by_id.get(o["target_ref"])
            if child_obj and parent_obj:
                child_id = next(
                    (r["external_id"] for r in child_obj.get("external_references", [])
                     if r.get("source_name") == "mitre-attack"), None)
                parent_id = next(
                    (r["external_id"] for r in parent_obj.get("external_references", [])
                     if r.get("source_name") == "mitre-attack"), None)
                if child_id and parent_id:
                    subtechnique_map.setdefault(parent_id, []).append(child_id)

    # Sort sub-technique lists
    for k in subtechnique_map:
        subtechnique_map[k].sort()

    return {
        "techniques": techniques,
        "data_components": data_components,
        "analytics": analytics,
        "det_strategies": det_strategies,
        "tech_to_det": tech_to_det,
        "subtechnique_map": subtechnique_map,
    }


def get_tactics(tech_obj):
    """Return list of display tactic names for a technique."""
    return [
        TACTIC_DISPLAY.get(phase["phase_name"], phase["phase_name"])
        for phase in tech_obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
    ]


def get_data_sources(stix_id, idx):
    """
    Extract unique 'Component Name' strings for a technique
    by walking: technique → detection-strategies → analytics → data-components.
    """
    components = set()
    for ds_id in idx["tech_to_det"].get(stix_id, []):
        ds_obj = idx["det_strategies"].get(ds_id, {})
        for a_ref in ds_obj.get("x_mitre_analytic_refs", []):
            analytic = idx["analytics"].get(a_ref)
            if not analytic:
                continue
            for log_ref in analytic.get("x_mitre_log_source_references", []):
                dc_ref = log_ref.get("x_mitre_data_component_ref")
                if dc_ref:
                    name = idx["data_components"].get(dc_ref)
                    if name:
                        components.add(name)
    return sorted(components)


def get_detection_text(stix_id, idx):
    """
    Concatenate analytic descriptions for a technique into a single detection paragraph.
    Each analytic contributes one sentence (its description).
    """
    sentences = []
    seen = set()
    for ds_id in idx["tech_to_det"].get(stix_id, []):
        ds_obj = idx["det_strategies"].get(ds_id, {})
        for a_ref in ds_obj.get("x_mitre_analytic_refs", []):
            analytic = idx["analytics"].get(a_ref)
            if not analytic:
                continue
            desc = (analytic.get("description") or "").strip()
            if desc and desc not in seen:
                seen.add(desc)
                sentences.append(desc)
    return " ".join(sentences)


def clean_stix_text(text):
    """Remove STIX-specific markup that doesn't belong in HTML display."""
    # Strip citation references: (Citation: Some Title 2020)
    text = re.sub(r'\(Citation:[^)]+\)', '', text)
    # Strip markdown links: [display text](url) → display text
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    # Strip bare URLs left over
    text = re.sub(r'https?://\S+', '', text)
    # Collapse runs of spaces created by removal
    text = re.sub(r'  +', ' ', text)
    return text.strip()


def js_string(text):
    """Escape a string for use inside a JS double-quoted string."""
    text = clean_stix_text(text)
    text = text.replace("\\", "\\\\")
    text = text.replace('"', '\\"')
    # Collapse multiple blank lines into one space
    text = re.sub(r'\n{2,}', ' ', text)
    text = text.replace('\n', ' ')
    # Collapse multiple spaces
    text = re.sub(r'  +', ' ', text).strip()
    return text


def js_array(items):
    """Format a Python list as a JS array literal."""
    if not items:
        return "[]"
    inner = ", ".join(f'"{x}"' for x in items)
    return f"[{inner}]"


def format_technique(ext_id, obj, idx, indent=6, include_subs=True):
    """Return a JS object literal string for a technique."""
    stix_id = obj["id"]
    name = obj.get("name", "")
    description = js_string(obj.get("description", ""))
    detection = js_string(get_detection_text(stix_id, idx))
    data_sources = get_data_sources(stix_id, idx)
    tactics = get_tactics(obj)

    pad = " " * indent
    pad2 = " " * (indent + 2)

    lines = [f"{pad}{{"]
    lines.append(f'{pad2}id: "{ext_id}", name: "{js_string(name)}",')
    if tactics:
        lines.append(f'{pad2}// Tactic(s): {", ".join(tactics)}')
    lines.append(f'{pad2}description: "{description}",')
    lines.append(f'{pad2}detection: "{detection or "No detection notes available."}",')
    lines.append(f'{pad2}dataSources: {js_array(data_sources)},')

    if include_subs and not obj.get("x_mitre_is_subtechnique"):
        sub_ids = idx["subtechnique_map"].get(ext_id, [])
        if sub_ids:
            lines.append(f"{pad2}subTechniques: [")
            for sub_id in sub_ids:
                sub_obj = idx["techniques"].get(sub_id)
                if sub_obj:
                    lines.append(format_technique(sub_id, sub_obj, idx, indent=indent+4, include_subs=False) + ",")
                else:
                    lines.append(f'{pad2}  // {sub_id} — not found in STIX data')
            lines.append(f"{pad2}]")
        else:
            lines.append(f"{pad2}subTechniques: []")

    lines.append(f"{pad}}}")
    return "\n".join(lines)


def list_tactics(idx):
    tactic_counts = {}
    for ext_id, obj in idx["techniques"].items():
        if "." not in ext_id:  # parent techniques only
            for tactic in get_tactics(obj):
                tactic_counts.setdefault(tactic, 0)
                tactic_counts[tactic] += 1
    print("Available tactics in enterprise-attack-19.1:")
    for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {tactic:<32}  {count} parent techniques")


def list_tactic(tactic_name, idx):
    print(f"Techniques in '{tactic_name}':")
    for ext_id, obj in sorted(idx["techniques"].items()):
        if "." in ext_id:
            continue
        if tactic_name.lower() in [t.lower() for t in get_tactics(obj)]:
            sub_ids = idx["subtechnique_map"].get(ext_id, [])
            print(f"  {ext_id:<12}  {obj['name']}  ({len(sub_ids)} sub-techniques)")


def main():
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return

    print(f"Loading {STIX_FILE} ...", file=sys.stderr)
    objects = load_stix()
    idx = build_index(objects)
    print(f"Indexed {len(idx['techniques'])} techniques.", file=sys.stderr)

    if args[0] == "--list-tactics":
        list_tactics(idx)
        return

    if args[0] == "--list-tactic":
        if len(args) < 2:
            print("Error: --list-tactic requires a tactic name argument.", file=sys.stderr)
            sys.exit(1)
        list_tactic(" ".join(args[1:]), idx)
        return

    if args[0] == "--tactic":
        if len(args) < 2:
            print("Error: --tactic requires a tactic name argument.", file=sys.stderr)
            sys.exit(1)
        tactic_name = " ".join(args[1:])
        requested = [
            ext_id for ext_id, obj in sorted(idx["techniques"].items())
            if "." not in ext_id
            and tactic_name.lower() in [t.lower() for t in get_tactics(obj)]
        ]
        print(f"// {tactic_name} — {len(requested)} parent techniques from ATT&CK v19.1")
    else:
        requested = args

    print()
    results = []
    for tech_id in requested:
        obj = idx["techniques"].get(tech_id)
        if not obj:
            print(f"// WARNING: {tech_id} not found in STIX data", file=sys.stderr)
            continue
        is_sub = obj.get("x_mitre_is_subtechnique", False)
        results.append(format_technique(tech_id, obj, idx, indent=6, include_subs=not is_sub))

    print(",\n".join(results))
    print(file=sys.stderr)
    print(f"Done — extracted {len(results)} technique(s).", file=sys.stderr)


if __name__ == "__main__":
    main()
