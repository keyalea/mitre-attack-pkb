# MITRE ATT&CK Personal Knowledge Base

A simple, local, browser-based tool for adding your own detection notes across the MITRE ATT&CK Enterprise, Mobile, and ICS matrices. No server required — open the HTML file locally and start writing. The notes are preserved on your local device.

---

## What it does

- Browse all three ATT&CK matrices (Enterprise, Mobile, ICS) with a domain switcher
- Filter techniques by platform (Windows, Linux, macOS, Android, iOS, OT assets) and data source
- Read MITRE's official technique descriptions, detection strategies, and mitigations alongside your own notes
- View cross-domain ID badges when a technique appears in multiple matrices
- Resume exactly where you left off — the active domain and last-selected technique are remembered across reloads

A look at the interface

![Demo](demo/Demo-MITRE-Notes.gif)

## Adding notes

Notes live in `notes.js`. Each entry is an HTML string keyed by technique ID. Example of note inserted into the T1059.001 subtechnique:

```javascript
"T1059.001": "<p>PowerShell: watch for encoded commands (-enc) and suspicious parent processes.</p>",
```

Leave the value as `""` to mark a technique as a placeholder with no notes yet.
Two example notes are included at the top of the file — `T1589` and `T1589.001` — to demonstrate plain text and paragraph-tag formatting. The ICS entry `T0813` shows a reference link. 

The file is organised into four sections:

1. **Enterprise** — grouped by tactic, techniques in ID order
2. **Mobile-only** — unique Mobile techniques (no Enterprise equivalent)
3. **ICS-only** — unique ICS techniques (no Enterprise equivalent)
4. **Legacy** — revoked or deprecated IDs retained from earlier builds

### Cross-domain notes

Enterprise notes take precedence across all three domains. If a Mobile or ICS technique shares the same name as an Enterprise technique (e.g. Phishing: Mobile `T1660` ↔ Enterprise `T1566`), the Enterprise note is displayed automatically — no separate Mobile or ICS entry is needed. Only add entries in the Mobile-only or ICS-only sections for techniques that have no Enterprise equivalent.

---

## File overview

| File | Purpose |
|---|---|
| `mitre-attack-pkb.html` | The PKB tool — open this file in a browser |
| `notes.js` | Your personal detection notes, organised by tactic. Edit this. |
| `attack-data.js` | Enterprise technique data (generated, do not edit manually) |
| `mobile-data.js` | Mobile technique data (generated, do not edit manually) |
| `ics-data.js` | ICS technique data (generated, do not edit manually) |

### `build/` — Optional data generation scripts

| Script | Purpose |
|---|---|
| `extract_attack.py` | Generates `attack-data.js` from the Enterprise STIX bundle |
| `build_multi_domain_data.py` | Generates `mobile-data.js` and `ics-data.js` from Mobile and ICS STIX bundles |

---

## Requirements

- A modern browser (Chrome, Firefox, or Edge recommended)

### Optionally, to build your own version
Needed only if regenerating data files from a new STIX release
- Python 3
- The MITRE ATT&CK STIX bundles downloaded locally 

---



## Regenerating the data files

The technique data files are generated from the [MITRE ATT&CK STIX bundles](https://github.com/mitre-attack/attack-stix-data). The STIX data is expected locally in a directory above. Modify to your local setup:

```
/change-your-path/attack-stix-data/
  enterprise-attack/enterprise-attack-19.1.json
  mobile-attack/mobile-attack-19.1.json
  ics-attack/ics-attack-19.1.json
```

To regenerate after downloading a new STIX release:

```bash
# Enterprise
python3 build/extract_attack.py

# Mobile and ICS
python3 build/build_multi_domain_data.py
```

---


