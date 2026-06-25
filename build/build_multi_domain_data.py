#!/usr/bin/env python3
"""
build_multi_domain_data.py
Generates mobile-data.js and ics-data.js for the MITRE ATT&CK PKB.

For techniques whose name exactly matches an Enterprise technique, a
`canonicalId` field is added pointing to the Enterprise ID. This allows
the HTML app to look up detection notes (keyed by Enterprise ID) for
conceptually shared techniques even when viewed in the Mobile or ICS domain.

Usage:
    python3 build_multi_domain_data.py

Outputs (same directory as this script):
    mobile-data.js   — const MOBILE_DATA = [...]
    ics-data.js      — const ICS_DATA    = [...]
"""

import json, re, sys, os

STIX_BASE = "/change-your-path/attack-stix-data"

STIX_FILES = {
    "enterprise": os.path.join(STIX_BASE, "enterprise-attack", "enterprise-attack-19.1.json"),
    "mobile":     os.path.join(STIX_BASE, "mobile-attack",     "mobile-attack-19.1.json"),
    "ics":        os.path.join(STIX_BASE, "ics-attack",        "ics-attack-19.1.json"),
}

# Kill chain name used in each bundle's kill_chain_phases
KILL_CHAIN = {
    "enterprise": "mitre-attack",
    "mobile":     "mitre-mobile-attack",
    "ics":        "mitre-ics-attack",
}

# kebab-case phase_name → display name
PHASE_DISPLAY = {
    "reconnaissance":           "Reconnaissance",
    "resource-development":     "Resource Development",
    "initial-access":           "Initial Access",
    "execution":                "Execution",
    "persistence":              "Persistence",
    "privilege-escalation":     "Privilege Escalation",
    "defense-evasion":          "Defense Evasion",
    "credential-access":        "Credential Access",
    "discovery":                "Discovery",
    "lateral-movement":         "Lateral Movement",
    "collection":               "Collection",
    "command-and-control":      "Command and Control",
    "exfiltration":             "Exfiltration",
    "impact":                   "Impact",
    # ICS-specific
    "evasion":                  "Evasion",
    "inhibit-response-function":"Inhibit Response Function",
    "impair-process-control":   "Impair Process Control",
    # Mobile legacy
    "network-effects":          "Network Effects",
    "remote-service-effects":   "Remote Service Effects",
}

OUT_DIR = os.path.dirname(os.path.abspath(__file__))


# ── STIX helpers ──────────────────────────────────────────────────────────────

def load_stix(domain):
    path = STIX_FILES[domain]
    print(f"Loading {path} ...", file=sys.stderr)
    with open(path) as f:
        return json.load(f)["objects"]


def build_index(objects, domain):
    """Build lookup tables from a STIX object list."""
    kc = KILL_CHAIN[domain]

    # technique external_id → STIX object
    techniques = {}
    for o in objects:
        if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("deprecated"):
            for ref in o.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    techniques[ref["external_id"]] = o
                    break

    data_components = {o["id"]: o["name"]
                       for o in objects if o["type"] == "x-mitre-data-component"}

    analytics     = {o["id"]: o for o in objects if o["type"] == "x-mitre-analytic"}
    det_strategies= {o["id"]: o for o in objects if o["type"] == "x-mitre-detection-strategy"}
    mitigations   = {o["id"]: o for o in objects if o["type"] == "course-of-action"}

    # technique STIX id → list of detection-strategy STIX ids
    tech_to_det = {}
    # technique STIX id → list of mitigation STIX ids
    tech_to_mit = {}
    # parent external_id → list of child external_ids
    subtechnique_map = {}

    stix_id_to_ext = {}  # STIX id → external_id
    for ext_id, obj in techniques.items():
        stix_id_to_ext[obj["id"]] = ext_id

    for o in objects:
        if o["type"] != "relationship":
            continue
        rtype = o.get("relationship_type", "")
        src, tgt = o.get("source_ref", ""), o.get("target_ref", "")

        if rtype == "detects" and src in det_strategies:
            tech_to_det.setdefault(tgt, []).append(src)

        if rtype == "mitigates" and src in mitigations:
            tech_to_mit.setdefault(tgt, []).append(src)

        if rtype == "subtechnique-of":
            child_ext = stix_id_to_ext.get(src)
            parent_ext = stix_id_to_ext.get(tgt)
            if child_ext and parent_ext:
                subtechnique_map.setdefault(parent_ext, []).append(child_ext)

    for k in subtechnique_map:
        subtechnique_map[k].sort()

    # ICS uses x-mitre-asset objects (linked via "targets" relationships) instead of
    # x_mitre_platforms on technique objects. Build technique STIX-id → asset names.
    asset_by_id = {o["id"]: o["name"] for o in objects if o["type"] == "x-mitre-asset"}
    tech_to_assets = {}
    for o in objects:
        if o["type"] == "relationship" and o.get("relationship_type") == "targets":
            src, tgt = o.get("source_ref", ""), o.get("target_ref", "")
            if tgt in asset_by_id:
                tech_to_assets.setdefault(src, []).append(asset_by_id[tgt])

    # tactic display name order from x-mitre-matrix (main matrix first)
    tactic_by_id = {o["id"]: o["name"]
                    for o in objects if o["type"] == "x-mitre-tactic"}
    ordered_tactics = []
    matrices = [o for o in objects if o["type"] == "x-mitre-matrix"]
    # put the main (non-legacy) matrix first
    matrices.sort(key=lambda m: len(m.get("tactic_refs", [])), reverse=True)
    seen_tactics = set()
    for mat in matrices:
        for tid in mat.get("tactic_refs", []):
            name = tactic_by_id.get(tid)
            if name and name not in seen_tactics:
                ordered_tactics.append(name)
                seen_tactics.add(name)

    return {
        "techniques":       techniques,
        "data_components":  data_components,
        "analytics":        analytics,
        "det_strategies":   det_strategies,
        "mitigations":      mitigations,
        "tech_to_det":      tech_to_det,
        "tech_to_mit":      tech_to_mit,
        "subtechnique_map": subtechnique_map,
        "tech_to_assets":   tech_to_assets,
        "ordered_tactics":  ordered_tactics,
        "kc":               kc,
    }


def get_tactics(tech_obj, kc):
    return [
        PHASE_DISPLAY.get(p["phase_name"], p["phase_name"])
        for p in tech_obj.get("kill_chain_phases", [])
        if p.get("kill_chain_name") == kc
    ]


def get_detection(stix_id, idx):
    sentences, seen = [], set()
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


def get_data_sources(stix_id, idx):
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


def get_mitigations(stix_id, idx):
    mits = []
    for mit_id in idx["tech_to_mit"].get(stix_id, []):
        obj = idx["mitigations"].get(mit_id)
        if not obj:
            continue
        ext_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id", "")
                break
        mits.append({
            "id":          ext_id,
            "name":        obj.get("name", ""),
            "description": clean(obj.get("description", "")),
        })
    mits.sort(key=lambda m: m["id"])
    return mits


# ── Text cleaning ─────────────────────────────────────────────────────────────

def clean(text):
    """Strip STIX citation markers, markdown links, and bare URLs."""
    text = re.sub(r'\(Citation:[^)]+\)', '', text)
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    text = re.sub(r'https?://\S+', '', text)
    text = re.sub(r'  +', ' ', text)
    return text.strip()


def js_str(text):
    """Escape text for embedding inside a JS double-quoted string."""
    text = clean(text)
    text = text.replace("\\", "\\\\")
    text = text.replace('"', '\\"')
    text = re.sub(r'\n+', ' ', text)
    text = re.sub(r'  +', ' ', text)
    return text.strip()


def js_arr(items):
    if not items:
        return "[]"
    return "[" + ", ".join(f'"{x}"' for x in items) + "]"


# ── Technique serialisation ───────────────────────────────────────────────────

def serialise_technique(ext_id, obj, idx, ent_name_to_id,
                         include_subs=True, indent=6):
    stix_id    = obj["id"]
    name       = obj.get("name", "")
    desc       = js_str(obj.get("description", ""))
    detection  = js_str(get_detection(stix_id, idx))
    data_srcs  = get_data_sources(stix_id, idx)
    # ICS stores platform equivalents as x-mitre-asset objects linked via "targets" rels.
    # Use those when present; fall back to x_mitre_platforms for Enterprise/Mobile.
    asset_names = idx.get("tech_to_assets", {}).get(stix_id, [])
    if asset_names:
        platforms = sorted(set(asset_names))
    else:
        platforms = sorted(p for p in obj.get("x_mitre_platforms", []) if p != "None")
    mits       = get_mitigations(stix_id, idx)

    # Cross-domain canonical ID (Enterprise ID for same-named technique)
    canonical_id = ent_name_to_id.get(name) if ent_name_to_id else None

    pad  = " " * indent
    pad2 = " " * (indent + 2)

    lines = [f"{pad}{{"]
    lines.append(f'{pad2}id: "{ext_id}", name: "{js_str(name)}",')
    if canonical_id and canonical_id != ext_id:
        lines.append(f'{pad2}canonicalId: "{canonical_id}",')
    lines.append(f'{pad2}description: "{desc}",')
    lines.append(f'{pad2}detection: "{detection or "No detection notes available."}",')
    lines.append(f'{pad2}platforms: {js_arr(platforms)},')

    if data_srcs:
        lines.append(f'{pad2}dataSources: {js_arr(data_srcs)},')
    else:
        lines.append(f'{pad2}dataSources: [],')

    if mits:
        lines.append(f'{pad2}mitigations: [')
        for m in mits:
            mid  = js_str(m["id"])
            mnam = js_str(m["name"])
            mdes = js_str(m["description"])
            lines.append(f'{pad2}  {{ id: "{mid}", name: "{mnam}", description: "{mdes}" }},')
        lines.append(f'{pad2}],')
    else:
        lines.append(f'{pad2}mitigations: [],')

    if include_subs and not obj.get("x_mitre_is_subtechnique"):
        sub_ids = idx["subtechnique_map"].get(ext_id, [])
        if sub_ids:
            lines.append(f"{pad2}subTechniques: [")
            for sub_id in sub_ids:
                sub_obj = idx["techniques"].get(sub_id)
                if sub_obj:
                    lines.append(
                        serialise_technique(sub_id, sub_obj, idx, ent_name_to_id,
                                            include_subs=False,
                                            indent=indent + 4) + ","
                    )
            lines.append(f"{pad2}],")
        else:
            lines.append(f"{pad2}subTechniques: [],")

    lines.append(f"{pad}}}")
    return "\n".join(lines)


# ── Domain builder ────────────────────────────────────────────────────────────

def build_domain_data(domain, ent_name_to_id):
    objects = load_stix(domain)
    idx     = build_index(objects, domain)
    kc      = idx["kc"]

    # Map tactic display name → list of (ext_id, obj) pairs
    tactic_to_techs = {}
    for ext_id, obj in idx["techniques"].items():
        if obj.get("x_mitre_is_subtechnique"):
            continue
        for tac in get_tactics(obj, kc):
            tactic_to_techs.setdefault(tac, []).append((ext_id, obj))

    # Sort techniques within each tactic by ID
    for tac in tactic_to_techs:
        tactic_to_techs[tac].sort(key=lambda x: x[0])

    lines = []
    for tac in idx["ordered_tactics"]:
        techs = tactic_to_techs.get(tac, [])
        if not techs:
            continue
        lines.append(f'  {{')
        lines.append(f'    tactic: "{tac}",')
        lines.append(f'    techniques: [')
        for ext_id, obj in techs:
            lines.append(
                serialise_technique(ext_id, obj, idx, ent_name_to_id, indent=6) + ","
            )
        lines.append(f'    ]')
        lines.append(f'  }},')

    print(f"  {domain}: {sum(len(v) for v in tactic_to_techs.values())} parent techniques "
          f"across {len([t for t in idx['ordered_tactics'] if tactic_to_techs.get(t)])} tactics",
          file=sys.stderr)
    return lines


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # Build Enterprise name → external_id index for cross-referencing
    ent_objects = load_stix("enterprise")
    ent_name_to_id = {}
    for o in ent_objects:
        if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("deprecated"):
            for ref in o.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ent_name_to_id[o["name"]] = ref["external_id"]
                    break
    print(f"Enterprise name index: {len(ent_name_to_id)} entries", file=sys.stderr)

    for domain, var_name, out_file in [
        ("mobile", "MOBILE_DATA", "mobile-data.js"),
        ("ics",    "ICS_DATA",    "ics-data.js"),
    ]:
        print(f"\nBuilding {domain} ...", file=sys.stderr)
        lines = build_domain_data(domain, ent_name_to_id)

        out_path = os.path.join(OUT_DIR, out_file)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"// Auto-generated from MITRE ATT&CK STIX {domain}-attack-19.1.json\n")
            f.write(f"// DO NOT EDIT — regenerate with build_multi_domain_data.py\n")
            f.write(f"const {var_name} = [\n")
            f.writelines(line + "\n" for line in lines)
            f.write("];\n")

        print(f"  Written: {out_path}", file=sys.stderr)

    print("\nDone.", file=sys.stderr)


if __name__ == "__main__":
    main()
