// notes.js
// Personal notes for MITRE ATT&CK techniques.
//
// FORMAT
//   "TECHNIQUE_ID": "<p>HTML content</p>",
//   Leave the value as "" to mark a technique as a placeholder with no notes yet.
//
// HOW DOMAIN NOTES WORK
//   Enterprise notes take precedence across all domains.
//   Mobile and ICS techniques that share a name with an Enterprise technique
//   (e.g. Phishing: Mobile T1660 ↔ Enterprise T1566) automatically display
//   the Enterprise note — no separate entry is needed for those.
//   Only techniques with NO Enterprise equivalent need entries in the
//   Mobile-only or ICS-only sections below.
//
// SECTIONS
//   1. Enterprise  — grouped by tactic, sorted by technique ID
//   2. Mobile-only — unique Mobile techniques (no Enterprise name match)
//   3. ICS-only    — unique ICS techniques   (no Enterprise name match)
//   4. Legacy      — revoked/deprecated Enterprise IDs retained from earlier builds

const DETECTION_NOTES = {

// ══════════════════════════════════════════════════════════════════════════════
// ENTERPRISE — ATT&CK v19
// Notes here also appear automatically for any Mobile or ICS technique that
// shares the same name (resolved via canonicalId lookup).
// ══════════════════════════════════════════════════════════════════════════════

// ── Reconnaissance ───────────────────────────────────────────────────────────
  // T1589 · Gather Victim Identity Information
  "T1589": "<p>Example. Add your notes here.</p>",
    // T1589.001 · Credentials
  "T1589.001": "The paragraph tags above are not needed, but can be used to better format notes.",
    // T1589.002 · Email Addresses
  "T1589.002": "",
    // T1589.003 · Employee Names
  "T1589.003": "",
  // T1590 · Gather Victim Network Information
  "T1590": "",
    // T1590.001 · Domain Properties
  "T1590.001": "",
    // T1590.002 · DNS
  "T1590.002": "",
    // T1590.003 · Network Trust Dependencies
  "T1590.003": "",
    // T1590.004 · Network Topology
  "T1590.004": "",
    // T1590.005 · IP Addresses
  "T1590.005": "",
    // T1590.006 · Network Security Appliances
  "T1590.006": "",
  // T1591 · Gather Victim Org Information
  "T1591": "",
    // T1591.001 · Determine Physical Locations
  "T1591.001": "",
    // T1591.002 · Business Relationships
  "T1591.002": "",
    // T1591.003 · Identify Business Tempo
  "T1591.003": "",
    // T1591.004 · Identify Roles
  "T1591.004": "",
  // T1592 · Gather Victim Host Information
  "T1592": "",
    // T1592.001 · Hardware
  "T1592.001": "",
    // T1592.002 · Software
  "T1592.002": "",
    // T1592.003 · Firmware
  "T1592.003": "",
    // T1592.004 · Client Configurations
  "T1592.004": "",
  // T1593 · Search Open Websites/Domains
  "T1593": "",
    // T1593.001 · Social Media
  "T1593.001": "",
    // T1593.002 · Search Engines
  "T1593.002": "",
    // T1593.003 · Code Repositories
  "T1593.003": "",
  // T1594 · Search Victim-Owned Websites
  "T1594": "",
  // T1595 · Active Scanning
  "T1595": "",
    // T1595.001 · Scanning IP Blocks
  "T1595.001": "",
    // T1595.002 · Vulnerability Scanning
  "T1595.002": "",
    // T1595.003 · Wordlist Scanning
  "T1595.003": "",
  // T1596 · Search Open Technical Databases
  "T1596": "",
    // T1596.001 · DNS/Passive DNS
  "T1596.001": "",
    // T1596.002 · WHOIS
  "T1596.002": "",
    // T1596.003 · Digital Certificates
  "T1596.003": "",
    // T1596.004 · CDNs
  "T1596.004": "",
    // T1596.005 · Scan Databases
  "T1596.005": "",
  // T1597 · Search Closed Sources
  "T1597": "",
    // T1597.001 · Threat Intel Vendors
  "T1597.001": "",
    // T1597.002 · Purchase Technical Data
  "T1597.002": "",
  // T1598 · Phishing for Information
  "T1598": "",
    // T1598.001 · Spearphishing Service
  "T1598.001": "",
    // T1598.002 · Spearphishing Attachment
  "T1598.002": "",
    // T1598.003 · Spearphishing Link
  "T1598.003": "",
    // T1598.004 · Spearphishing Voice
  "T1598.004": "",
  // T1681 · Search Threat Vendor Data
  "T1681": "",
  // T1682 · Query Public AI Services
  "T1682": "",

// ── Resource Development ─────────────────────────────────────────────────────
  // T1583 · Acquire Infrastructure
  "T1583": "",
    // T1583.001 · Domains
  "T1583.001": "",
    // T1583.002 · DNS Server
  "T1583.002": "",
    // T1583.003 · Virtual Private Server
  "T1583.003": "",
    // T1583.004 · Server
  "T1583.004": "",
    // T1583.005 · Botnet
  "T1583.005": "",
    // T1583.006 · Web Services
  "T1583.006": "",
    // T1583.007 · Serverless
  "T1583.007": "",
    // T1583.008 · Malvertising
  "T1583.008": "",
  // T1584 · Compromise Infrastructure
  "T1584": "",
    // T1584.001 · Domains
  "T1584.001": "",
    // T1584.002 · DNS Server
  "T1584.002": "",
    // T1584.003 · Virtual Private Server
  "T1584.003": "",
    // T1584.004 · Server
  "T1584.004": "",
    // T1584.005 · Botnet
  "T1584.005": "",
    // T1584.006 · Web Services
  "T1584.006": "",
    // T1584.007 · Serverless
  "T1584.007": "",
    // T1584.008 · Network Devices
  "T1584.008": "",
  // T1585 · Establish Accounts
  "T1585": "",
    // T1585.001 · Social Media Accounts
  "T1585.001": "",
    // T1585.002 · Email Accounts
  "T1585.002": "",
    // T1585.003 · Cloud Accounts
  "T1585.003": "",
  // T1586 · Compromise Accounts
  "T1586": "",
    // T1586.001 · Social Media Accounts
  "T1586.001": "",
    // T1586.002 · Email Accounts
  "T1586.002": "",
    // T1586.003 · Cloud Accounts
  "T1586.003": "",
  // T1587 · Develop Capabilities
  "T1587": "",
    // T1587.001 · Malware
  "T1587.001": "",
    // T1587.002 · Code Signing Certificates
  "T1587.002": "",
    // T1587.003 · Digital Certificates
  "T1587.003": "",
    // T1587.004 · Exploits
  "T1587.004": "",
  // T1588 · Obtain Capabilities
  "T1588": "",
    // T1588.001 · Malware
  "T1588.001": "",
    // T1588.002 · Tool
  "T1588.002": "",
    // T1588.003 · Code Signing Certificates
  "T1588.003": "",
    // T1588.004 · Digital Certificates
  "T1588.004": "",
    // T1588.005 · Exploits
  "T1588.005": "",
    // T1588.006 · Vulnerabilities
  "T1588.006": "",
    // T1588.007 · Artificial Intelligence
  "T1588.007": "",
  // T1608 · Stage Capabilities
  "T1608": "",
    // T1608.001 · Upload Malware
  "T1608.001": "",
    // T1608.002 · Upload Tool
  "T1608.002": "",
    // T1608.003 · Install Digital Certificate
  "T1608.003": "",
    // T1608.004 · Drive-by Target
  "T1608.004": "",
    // T1608.005 · Link Target
  "T1608.005": "",
    // T1608.006 · SEO Poisoning
  "T1608.006": "",
  // T1650 · Acquire Access
  "T1650": "",
  // T1683 · Generate Content
  "T1683": "",
    // T1683.001 · Written Content
  "T1683.001": "",
    // T1683.002 · Audio-Visual Content
  "T1683.002": "",

// ── Initial Access ───────────────────────────────────────────────────────────
  // T1078 · Valid Accounts  [also: Persistence, Privilege Escalation, Initial Access]
  "T1078": "",
    // T1078.001 · Default Accounts  [also: Persistence, Privilege Escalation, Initial Access]
  "T1078.001": "",
    // T1078.002 · Domain Accounts  [also: Persistence, Privilege Escalation, Initial Access]
  "T1078.002": "",
    // T1078.003 · Local Accounts  [also: Persistence, Privilege Escalation, Initial Access]
  "T1078.003": "",
    // T1078.004 · Cloud Accounts  [also: Persistence, Privilege Escalation, Initial Access]
  "T1078.004": "",
  // T1091 · Replication Through Removable Media  [also: Initial Access]
  "T1091": "",
  // T1133 · External Remote Services  [also: Initial Access]
  "T1133": "",
  // T1189 · Drive-by Compromise
  "T1189": "",
  // T1190 · Exploit Public-Facing Application
  "T1190": "",
  // T1195 · Supply Chain Compromise
  "T1195": "",
    // T1195.001 · Compromise Software Dependencies and Development Tools
  "T1195.001": "",
    // T1195.002 · Compromise Software Supply Chain
  "T1195.002": "",
    // T1195.003 · Compromise Hardware Supply Chain
  "T1195.003": "",
  // T1199 · Trusted Relationship
  "T1199": "",
  // T1200 · Hardware Additions
  "T1200": "",
  // T1566 · Phishing
  "T1566": "",
    // T1566.001 · Spearphishing Attachment
  "T1566.001": "",
    // T1566.002 · Spearphishing Link
  "T1566.002": "",
    // T1566.003 · Spearphishing via Service
  "T1566.003": "",
    // T1566.004 · Spearphishing Voice
  "T1566.004": "",
  // T1659 · Content Injection  [also: Command and Control]
  "T1659": "",
  // T1669 · Wi-Fi Networks
  "T1669": "",

// ── Execution ────────────────────────────────────────────────────────────────
  // T1047 · Windows Management Instrumentation
  "T1047": "",
  // T1053 · Scheduled Task/Job  [also: Persistence, Privilege Escalation]
  "T1053": "",
    // T1053.002 · At  [also: Persistence, Privilege Escalation]
  "T1053.002": "",
    // T1053.003 · Cron  [also: Persistence, Privilege Escalation]
  "T1053.003": "",
    // T1053.004 · Launchd  [also: Persistence, Privilege Escalation]
  "T1053.004": "",
    // T1053.005 · Scheduled Task  [also: Persistence, Privilege Escalation]
  "T1053.005": "",
    // T1053.006 · Systemd Timers  [also: Persistence, Privilege Escalation]
  "T1053.006": "",
    // T1053.007 · Container Orchestration Job  [also: Persistence, Privilege Escalation]
  "T1053.007": "",
  // T1059 · Command and Scripting Interpreter
  "T1059": "",
    // T1059.001 · PowerShell
  "T1059.001": "",
    // T1059.002 · AppleScript
  "T1059.002": "",
    // T1059.003 · Windows Command Shell
  "T1059.003": "",
    // T1059.004 · Unix Shell
  "T1059.004": "",
    // T1059.005 · Visual Basic
  "T1059.005": "",
    // T1059.006 · Python
  "T1059.006": "",
    // T1059.007 · JavaScript
  "T1059.007": "",
    // T1059.008 · Network Device CLI
  "T1059.008": "",
    // T1059.009 · Cloud API
  "T1059.009": "",
    // T1059.010 · AutoHotKey & AutoIT
  "T1059.010": "",
    // T1059.011 · Lua
  "T1059.011": "",
    // T1059.012 · Hypervisor CLI
  "T1059.012": "",
    // T1059.013 · Container CLI/API
  "T1059.013": "",
  // T1061 · Graphical User Interface
  "T1061": "",
  // T1064 · Scripting  [also: Execution]
  "T1064": "",
  // T1072 · Software Deployment Tools  [also: Lateral Movement]
  "T1072": "",
  // T1106 · Native API
  "T1106": "",
  // T1127 · Trusted Developer Utilities Proxy Execution  [also: Execution]
  "T1127": "",
    // T1127.001 · MSBuild  [also: Execution]
  "T1127.001": "",
    // T1127.002 · ClickOnce  [also: Execution]
  "T1127.002": "",
    // T1127.003 · JamPlus  [also: Execution]
  "T1127.003": "",
  // T1129 · Shared Modules
  "T1129": "",
  // T1153 · Source
  "T1153": "",
  // T1175 · Component Object Model and Distributed COM  [also: Execution]
  "T1175": "",
  // T1197 · BITS Jobs  [also: Persistence, Execution]
  "T1197": "",
  // T1203 · Exploitation for Client Execution
  "T1203": "",
  // T1204 · User Execution
  "T1204": "",
    // T1204.001 · Malicious Link
  "T1204.001": "",
    // T1204.002 · Malicious File
  "T1204.002": "",
    // T1204.003 · Malicious Image
  "T1204.003": "",
    // T1204.004 · Malicious Copy and Paste
  "T1204.004": "",
    // T1204.005 · Malicious Library
  "T1204.005": "",
  // T1559 · Inter-Process Communication
  "T1559": "",
    // T1559.001 · Component Object Model
  "T1559.001": "",
    // T1559.002 · Dynamic Data Exchange
  "T1559.002": "",
    // T1559.003 · XPC Services
  "T1559.003": "",
  // T1569 · System Services
  "T1569": "",
    // T1569.001 · Launchctl
  "T1569.001": "",
    // T1569.002 · Service Execution
  "T1569.002": "",
    // T1569.003 · Systemctl
  "T1569.003": "",
  // T1574 · Hijack Execution Flow  [also: Execution]
  "T1574": "",
    // T1574.001 · DLL  [also: Execution]
  "T1574.001": "",
    // T1574.004 · Dylib Hijacking  [also: Execution]
  "T1574.004": "",
    // T1574.005 · Executable Installer File Permissions Weakness  [also: Execution]
  "T1574.005": "",
    // T1574.006 · Dynamic Linker Hijacking  [also: Execution]
  "T1574.006": "",
    // T1574.007 · Path Interception by PATH Environment Variable  [also: Execution]
  "T1574.007": "",
    // T1574.008 · Path Interception by Search Order Hijacking  [also: Execution]
  "T1574.008": "",
    // T1574.009 · Path Interception by Unquoted Path  [also: Execution]
  "T1574.009": "",
    // T1574.010 · Services File Permissions Weakness  [also: Execution]
  "T1574.010": "",
    // T1574.011 · Services Registry Permissions Weakness  [also: Execution]
  "T1574.011": "",
    // T1574.012 · COR_PROFILER  [also: Execution]
  "T1574.012": "",
    // T1574.013 · KernelCallbackTable  [also: Execution]
  "T1574.013": "",
    // T1574.014 · AppDomainManager  [also: Execution]
  "T1574.014": "",
  // T1609 · Container Administration Command
  "T1609": "",
  // T1610 · Deploy Container
  "T1610": "",
  // T1648 · Serverless Execution
  "T1648": "",
  // T1651 · Cloud Administration Command
  "T1651": "",
  // T1674 · Input Injection
  "T1674": "",
  // T1675 · ESXi Administration Command
  "T1675": "",
  // T1677 · Poisoned Pipeline Execution
  "T1677": "",

// ── Persistence ──────────────────────────────────────────────────────────────
  // T1034 · Path Interception  [also: Privilege Escalation]
  "T1034": "",
  // T1037 · Boot or Logon Initialization Scripts  [also: Privilege Escalation]
  "T1037": "",
    // T1037.001 · Logon Script (Windows)  [also: Privilege Escalation]
  "T1037.001": "",
    // T1037.002 · Login Hook  [also: Privilege Escalation]
  "T1037.002": "",
    // T1037.003 · Network Logon Script  [also: Privilege Escalation]
  "T1037.003": "",
    // T1037.004 · RC Scripts  [also: Privilege Escalation]
  "T1037.004": "",
    // T1037.005 · Startup Items  [also: Privilege Escalation]
  "T1037.005": "",
  // T1062 · Hypervisor
  "T1062": "",
  // T1098 · Account Manipulation  [also: Privilege Escalation]
  "T1098": "",
    // T1098.001 · Additional Cloud Credentials  [also: Privilege Escalation]
  "T1098.001": "",
    // T1098.002 · Additional Email Delegate Permissions  [also: Privilege Escalation]
  "T1098.002": "",
    // T1098.003 · Additional Cloud Roles  [also: Privilege Escalation]
  "T1098.003": "",
    // T1098.004 · SSH Authorized Keys  [also: Privilege Escalation]
  "T1098.004": "",
    // T1098.005 · Device Registration  [also: Privilege Escalation]
  "T1098.005": "",
    // T1098.006 · Additional Container Cluster Roles  [also: Privilege Escalation]
  "T1098.006": "",
    // T1098.007 · Additional Local or Domain Groups  [also: Privilege Escalation]
  "T1098.007": "",
  // T1108 · Redundant Access  [also: Persistence]
  "T1108": "",
  // T1112 · Modify Registry  [also: Persistence]
  "T1112": "",
  // T1136 · Create Account
  "T1136": "",
    // T1136.001 · Local Account
  "T1136.001": "",
    // T1136.002 · Domain Account
  "T1136.002": "",
    // T1136.003 · Cloud Account
  "T1136.003": "",
  // T1137 · Office Application Startup
  "T1137": "",
    // T1137.001 · Office Template Macros
  "T1137.001": "",
    // T1137.002 · Office Test
  "T1137.002": "",
    // T1137.003 · Outlook Forms
  "T1137.003": "",
    // T1137.004 · Outlook Home Page
  "T1137.004": "",
    // T1137.005 · Outlook Rules
  "T1137.005": "",
    // T1137.006 · Add-ins
  "T1137.006": "",
  // T1176 · Software Extensions
  "T1176": "",
    // T1176.001 · Browser Extensions
  "T1176.001": "",
    // T1176.002 · IDE Extensions
  "T1176.002": "",
  // T1205 · Traffic Signaling  [also: Persistence, Command and Control]
  "T1205": "",
    // T1205.001 · Port Knocking  [also: Persistence, Command and Control]
  "T1205.001": "",
    // T1205.002 · Socket Filters  [also: Persistence, Command and Control]
  "T1205.002": "",
  // T1505 · Server Software Component
  "T1505": "",
    // T1505.001 · SQL Stored Procedures
  "T1505.001": "",
    // T1505.002 · Transport Agent
  "T1505.002": "",
    // T1505.003 · Web Shell
  "T1505.003": "",
    // T1505.004 · IIS Components
  "T1505.004": "",
    // T1505.005 · Terminal Services DLL
  "T1505.005": "",
    // T1505.006 · vSphere Installation Bundles
  "T1505.006": "",
  // T1525 · Implant Internal Image
  "T1525": "",
  // T1542 · Pre-OS Boot  [also: Persistence]
  "T1542": "",
    // T1542.001 · System Firmware  [also: Persistence]
  "T1542.001": "",
    // T1542.002 · Component Firmware  [also: Persistence]
  "T1542.002": "",
    // T1542.003 · Bootkit  [also: Persistence]
  "T1542.003": "",
    // T1542.004 · ROMMONkit  [also: Persistence]
  "T1542.004": "",
    // T1542.005 · TFTP Boot  [also: Persistence]
  "T1542.005": "",
  // T1543 · Create or Modify System Process  [also: Privilege Escalation]
  "T1543": "",
    // T1543.001 · Launch Agent  [also: Privilege Escalation]
  "T1543.001": "",
    // T1543.002 · Systemd Service  [also: Privilege Escalation]
  "T1543.002": "",
    // T1543.003 · Windows Service  [also: Privilege Escalation]
  "T1543.003": "",
    // T1543.004 · Launch Daemon  [also: Privilege Escalation]
  "T1543.004": "",
    // T1543.005 · Container Service  [also: Privilege Escalation]
  "T1543.005": "",
  // T1546 · Event Triggered Execution  [also: Persistence]
  "T1546": "",
    // T1546.001 · Change Default File Association  [also: Persistence]
  "T1546.001": "",
    // T1546.002 · Screensaver  [also: Persistence]
  "T1546.002": "",
    // T1546.003 · Windows Management Instrumentation Event Subscription  [also: Persistence]
  "T1546.003": "",
    // T1546.004 · Unix Shell Configuration Modification  [also: Persistence]
  "T1546.004": "",
    // T1546.005 · Trap  [also: Persistence]
  "T1546.005": "",
    // T1546.006 · LC_LOAD_DYLIB Addition  [also: Persistence]
  "T1546.006": "",
    // T1546.007 · Netsh Helper DLL  [also: Persistence]
  "T1546.007": "",
    // T1546.008 · Accessibility Features  [also: Persistence]
  "T1546.008": "",
    // T1546.009 · AppCert DLLs  [also: Persistence]
  "T1546.009": "",
    // T1546.010 · AppInit DLLs  [also: Persistence]
  "T1546.010": "",
    // T1546.011 · Application Shimming  [also: Persistence]
  "T1546.011": "",
    // T1546.012 · Image File Execution Options Injection  [also: Persistence]
  "T1546.012": "",
    // T1546.013 · PowerShell Profile  [also: Persistence]
  "T1546.013": "",
    // T1546.014 · Emond  [also: Persistence]
  "T1546.014": "",
    // T1546.015 · Component Object Model Hijacking  [also: Persistence]
  "T1546.015": "",
    // T1546.016 · Installer Packages  [also: Persistence]
  "T1546.016": "",
    // T1546.017 · Udev Rules  [also: Privilege Escalation]
  "T1546.017": "",
    // T1546.018 · Python Startup Hooks  [also: Privilege Escalation]
  "T1546.018": "",
  // T1547 · Boot or Logon Autostart Execution  [also: Privilege Escalation]
  "T1547": "",
    // T1547.001 · Registry Run Keys / Startup Folder  [also: Privilege Escalation]
  "T1547.001": "",
    // T1547.002 · Authentication Package  [also: Privilege Escalation]
  "T1547.002": "",
    // T1547.003 · Time Providers  [also: Privilege Escalation]
  "T1547.003": "",
    // T1547.004 · Winlogon Helper DLL  [also: Privilege Escalation]
  "T1547.004": "",
    // T1547.005 · Security Support Provider  [also: Privilege Escalation]
  "T1547.005": "",
    // T1547.006 · Kernel Modules and Extensions  [also: Privilege Escalation]
  "T1547.006": "",
    // T1547.007 · Re-opened Applications  [also: Privilege Escalation]
  "T1547.007": "",
    // T1547.008 · LSASS Driver  [also: Privilege Escalation]
  "T1547.008": "",
    // T1547.009 · Shortcut Modification  [also: Privilege Escalation]
  "T1547.009": "",
    // T1547.010 · Port Monitors  [also: Privilege Escalation]
  "T1547.010": "",
    // T1547.012 · Print Processors  [also: Privilege Escalation]
  "T1547.012": "",
    // T1547.013 · XDG Autostart Entries  [also: Privilege Escalation]
  "T1547.013": "",
    // T1547.014 · Active Setup  [also: Privilege Escalation]
  "T1547.014": "",
    // T1547.015 · Login Items  [also: Privilege Escalation]
  "T1547.015": "",
  // T1554 · Compromise Host Software Binary
  "T1554": "",
  // T1556 · Modify Authentication Process  [also: Persistence, Credential Access]
  "T1556": "",
    // T1556.001 · Domain Controller Authentication  [also: Persistence, Credential Access]
  "T1556.001": "",
    // T1556.002 · Password Filter DLL  [also: Persistence, Credential Access]
  "T1556.002": "",
    // T1556.003 · Pluggable Authentication Modules  [also: Persistence, Credential Access]
  "T1556.003": "",
    // T1556.004 · Network Device Authentication  [also: Persistence, Credential Access]
  "T1556.004": "",
    // T1556.005 · Reversible Encryption  [also: Persistence, Credential Access]
  "T1556.005": "",
    // T1556.006 · Multi-Factor Authentication  [also: Persistence, Credential Access]
  "T1556.006": "",
    // T1556.007 · Hybrid Identity  [also: Persistence, Credential Access]
  "T1556.007": "",
    // T1556.008 · Network Provider DLL  [also: Persistence, Credential Access]
  "T1556.008": "",
    // T1556.009 · Conditional Access Policies  [also: Persistence, Credential Access]
  "T1556.009": "",
  // T1653 · Power Settings
  "T1653": "",
  // T1668 · Exclusive Control
  "T1668": "",
  // T1671 · Cloud Application Integration
  "T1671": "",

// ── Privilege Escalation ─────────────────────────────────────────────────────
  // T1055 · Process Injection  [also: Privilege Escalation]
  "T1055": "",
    // T1055.001 · Dynamic-link Library Injection  [also: Privilege Escalation]
  "T1055.001": "",
    // T1055.002 · Portable Executable Injection  [also: Privilege Escalation]
  "T1055.002": "",
    // T1055.003 · Thread Execution Hijacking  [also: Privilege Escalation]
  "T1055.003": "",
    // T1055.004 · Asynchronous Procedure Call  [also: Privilege Escalation]
  "T1055.004": "",
    // T1055.005 · Thread Local Storage  [also: Privilege Escalation]
  "T1055.005": "",
    // T1055.008 · Ptrace System Calls  [also: Privilege Escalation]
  "T1055.008": "",
    // T1055.009 · Proc Memory  [also: Privilege Escalation]
  "T1055.009": "",
    // T1055.011 · Extra Window Memory Injection  [also: Privilege Escalation]
  "T1055.011": "",
    // T1055.012 · Process Hollowing  [also: Privilege Escalation]
  "T1055.012": "",
    // T1055.013 · Process Doppelgänging  [also: Privilege Escalation]
  "T1055.013": "",
    // T1055.014 · VDSO Hijacking  [also: Privilege Escalation]
  "T1055.014": "",
    // T1055.015 · ListPlanting  [also: Privilege Escalation]
  "T1055.015": "",
  // T1068 · Exploitation for Privilege Escalation
  "T1068": "",
  // T1134 · Access Token Manipulation  [also: Privilege Escalation]
  "T1134": "",
    // T1134.001 · Token Impersonation/Theft  [also: Privilege Escalation]
  "T1134.001": "",
    // T1134.002 · Create Process with Token  [also: Privilege Escalation]
  "T1134.002": "",
    // T1134.003 · Make and Impersonate Token  [also: Privilege Escalation]
  "T1134.003": "",
    // T1134.004 · Parent PID Spoofing  [also: Privilege Escalation]
  "T1134.004": "",
    // T1134.005 · SID-History Injection  [also: Privilege Escalation]
  "T1134.005": "",
  // T1484 · Domain or Tenant Policy Modification  [also: Privilege Escalation]
  "T1484": "",
    // T1484.001 · Group Policy Modification  [also: Privilege Escalation]
  "T1484.001": "",
    // T1484.002 · Trust Modification  [also: Privilege Escalation]
  "T1484.002": "",
  // T1548 · Abuse Elevation Control Mechanism
  "T1548": "",
    // T1548.001 · Setuid and Setgid
  "T1548.001": "",
    // T1548.002 · Bypass User Account Control
  "T1548.002": "",
    // T1548.003 · Sudo and Sudo Caching
  "T1548.003": "",
    // T1548.004 · Elevated Execution with Prompt
  "T1548.004": "",
    // T1548.005 · Temporary Elevated Cloud Access
  "T1548.005": "",
    // T1548.006 · TCC Manipulation
  "T1548.006": "",
  // T1611 · Escape to Host
  "T1611": "",

// ── Stealth ──────────────────────────────────────────────────────────────────
  // T1006 · Direct Volume Access
  "T1006": "",
  // T1014 · Rootkit
  "T1014": "",
  // T1027 · Obfuscated Files or Information
  "T1027": "",
    // T1027.001 · Binary Padding
  "T1027.001": "",
    // T1027.002 · Software Packing
  "T1027.002": "",
    // T1027.003 · Steganography
  "T1027.003": "",
    // T1027.004 · Compile After Delivery
  "T1027.004": "",
    // T1027.005 · Indicator Removal from Tools
  "T1027.005": "",
    // T1027.006 · HTML Smuggling
  "T1027.006": "",
    // T1027.007 · Dynamic API Resolution
  "T1027.007": "",
    // T1027.008 · Stripped Payloads
  "T1027.008": "",
    // T1027.009 · Embedded Payloads
  "T1027.009": "",
    // T1027.010 · Command Obfuscation
  "T1027.010": "",
    // T1027.011 · Fileless Storage
  "T1027.011": "",
    // T1027.012 · LNK Icon Smuggling
  "T1027.012": "",
    // T1027.013 · Encrypted/Encoded File
  "T1027.013": "",
    // T1027.014 · Polymorphic Code
  "T1027.014": "",
    // T1027.015 · Compression
  "T1027.015": "",
    // T1027.016 · Junk Code Insertion
  "T1027.016": "",
    // T1027.017 · SVG Smuggling
  "T1027.017": "",
    // T1027.018 · Invisible Unicode
  "T1027.018": "",
  // T1036 · Masquerading
  "T1036": "",
    // T1036.001 · Invalid Code Signature
  "T1036.001": "",
    // T1036.002 · Right-to-Left Override
  "T1036.002": "",
    // T1036.003 · Rename Legitimate Utilities
  "T1036.003": "",
    // T1036.004 · Masquerade Task or Service
  "T1036.004": "",
    // T1036.005 · Match Legitimate Resource Name or Location
  "T1036.005": "",
    // T1036.006 · Space after Filename
  "T1036.006": "",
    // T1036.007 · Double File Extension
  "T1036.007": "",
    // T1036.008 · Masquerade File Type
  "T1036.008": "",
    // T1036.009 · Break Process Trees
  "T1036.009": "",
    // T1036.010 · Masquerade Account Name
  "T1036.010": "",
    // T1036.011 · Overwrite Process Arguments
  "T1036.011": "",
    // T1036.012 · Browser Fingerprint
  "T1036.012": "",
  // T1070 · Indicator Removal
  "T1070": "",
    // T1070.003 · Clear Command History
  "T1070.003": "",
    // T1070.004 · File Deletion
  "T1070.004": "",
    // T1070.005 · Network Share Connection Removal
  "T1070.005": "",
    // T1070.006 · Timestomp
  "T1070.006": "",
    // T1070.007 · Clear Network Connection History and Configurations
  "T1070.007": "",
    // T1070.008 · Clear Mailbox Data
  "T1070.008": "",
    // T1070.009 · Clear Persistence
  "T1070.009": "",
    // T1070.010 · Relocate Malware
  "T1070.010": "",
  // T1140 · Deobfuscate/Decode Files or Information
  "T1140": "",
  // T1149 · LC_MAIN Hijacking
  "T1149": "",
  // T1202 · Indirect Command Execution
  "T1202": "",
  // T1211 · Exploitation for Stealth
  "T1211": "",
  // T1216 · System Script Proxy Execution
  "T1216": "",
    // T1216.001 · PubPrn
  "T1216.001": "",
    // T1216.002 · SyncAppvPublishingServer
  "T1216.002": "",
  // T1218 · System Binary Proxy Execution
  "T1218": "",
    // T1218.001 · Compiled HTML File
  "T1218.001": "",
    // T1218.002 · Control Panel
  "T1218.002": "",
    // T1218.003 · CMSTP
  "T1218.003": "",
    // T1218.004 · InstallUtil
  "T1218.004": "",
    // T1218.005 · Mshta
  "T1218.005": "",
    // T1218.007 · Msiexec
  "T1218.007": "",
    // T1218.008 · Odbcconf
  "T1218.008": "",
    // T1218.009 · Regsvcs/Regasm
  "T1218.009": "",
    // T1218.010 · Regsvr32
  "T1218.010": "",
    // T1218.011 · Rundll32
  "T1218.011": "",
    // T1218.012 · Verclsid
  "T1218.012": "",
    // T1218.013 · Mavinject
  "T1218.013": "",
    // T1218.014 · MMC
  "T1218.014": "",
    // T1218.015 · Electron Applications
  "T1218.015": "",
  // T1220 · XSL Script Processing
  "T1220": "",
  // T1221 · Template Injection
  "T1221": "",
  // T1480 · Execution Guardrails
  "T1480": "",
    // T1480.001 · Environmental Keying
  "T1480.001": "",
    // T1480.002 · Mutual Exclusion
  "T1480.002": "",
  // T1497 · Virtualization/Sandbox Evasion  [also: Discovery]
  "T1497": "",
    // T1497.001 · System Checks  [also: Discovery]
  "T1497.001": "",
    // T1497.002 · User Activity Based Checks  [also: Discovery]
  "T1497.002": "",
    // T1497.003 · Time Based Checks  [also: Discovery]
  "T1497.003": "",
  // T1535 · Unused/Unsupported Cloud Regions
  "T1535": "",
  // T1564 · Hide Artifacts
  "T1564": "",
    // T1564.001 · Hidden Files and Directories
  "T1564.001": "",
    // T1564.002 · Hidden Users
  "T1564.002": "",
    // T1564.003 · Hidden Window
  "T1564.003": "",
    // T1564.004 · NTFS File Attributes
  "T1564.004": "",
    // T1564.005 · Hidden File System
  "T1564.005": "",
    // T1564.006 · Run Virtual Instance
  "T1564.006": "",
    // T1564.007 · VBA Stomping
  "T1564.007": "",
    // T1564.008 · Email Hiding Rules
  "T1564.008": "",
    // T1564.009 · Resource Forking
  "T1564.009": "",
    // T1564.010 · Process Argument Spoofing
  "T1564.010": "",
    // T1564.011 · Ignore Process Interrupts
  "T1564.011": "",
    // T1564.012 · File/Path Exclusions
  "T1564.012": "",
    // T1564.013 · Bind Mounts
  "T1564.013": "",
    // T1564.014 · Extended Attributes
  "T1564.014": "",
  // T1612 · Build Image on Host
  "T1612": "",
  // T1620 · Reflective Code Loading
  "T1620": "",
  // T1622 · Debugger Evasion  [also: Discovery]
  "T1622": "",
  // T1678 · Delay Execution
  "T1678": "",
  // T1679 · Selective Exclusion
  "T1679": "",
  // T1684 · Social Engineering
  "T1684": "",
    // T1684.001 · Impersonation
  "T1684.001": "",
    // T1684.002 · Email Spoofing
  "T1684.002": "",

// ── Defense Impairment ───────────────────────────────────────────────────────
  // T1207 · Rogue Domain Controller
  "T1207": "",
  // T1222 · File and Directory Permissions Modification
  "T1222": "",
    // T1222.001 · Windows Permissions
  "T1222.001": "",
    // T1222.002 · Linux and Mac Permissions
  "T1222.002": "",
  // T1553 · Subvert Trust Controls
  "T1553": "",
    // T1553.001 · Gatekeeper Bypass
  "T1553.001": "",
    // T1553.002 · Code Signing
  "T1553.002": "",
    // T1553.003 · SIP and Trust Provider Hijacking
  "T1553.003": "",
    // T1553.004 · Install Root Certificate
  "T1553.004": "",
    // T1553.005 · Mark-of-the-Web Bypass
  "T1553.005": "",
    // T1553.006 · Code Signing Policy Modification
  "T1553.006": "",
  // T1578 · Modify Cloud Compute Infrastructure
  "T1578": "",
    // T1578.001 · Create Snapshot
  "T1578.001": "",
    // T1578.002 · Create Cloud Instance
  "T1578.002": "",
    // T1578.003 · Delete Cloud Instance
  "T1578.003": "",
    // T1578.004 · Revert Cloud Instance
  "T1578.004": "",
    // T1578.005 · Modify Cloud Compute Configurations
  "T1578.005": "",
  // T1599 · Network Boundary Bridging
  "T1599": "",
    // T1599.001 · Network Address Translation Traversal
  "T1599.001": "",
  // T1600 · Weaken Encryption
  "T1600": "",
    // T1600.001 · Reduce Key Space
  "T1600.001": "",
    // T1600.002 · Disable Crypto Hardware
  "T1600.002": "",
  // T1601 · Modify System Image
  "T1601": "",
    // T1601.001 · Patch System Image
  "T1601.001": "",
    // T1601.002 · Downgrade System Image
  "T1601.002": "",
  // T1647 · Plist File Modification
  "T1647": "",
  // T1666 · Modify Cloud Resource Hierarchy
  "T1666": "",
  // T1685 · Disable or Modify Tools
  "T1685": "",
    // T1685.001 · Disable or Modify Windows Event Log
  "T1685.001": "",
    // T1685.002 · Disable or Modify Cloud Log
  "T1685.002": "",
    // T1685.003 · Modify or Spoof Tool UI
  "T1685.003": "",
    // T1685.004 · Disable or Modify Linux Audit System Log
  "T1685.004": "",
    // T1685.005 · Clear Windows Event Logs
  "T1685.005": "",
    // T1685.006 · Clear Linux or Mac System Logs
  "T1685.006": "",
  // T1686 · Disable or Modify System Firewall
  "T1686": "",
    // T1686.001 · Cloud Firewall
  "T1686.001": "",
    // T1686.002 · Network Device Firewall
  "T1686.002": "",
    // T1686.003 · Windows Host Firewall
  "T1686.003": "",
  // T1687 · Exploitation for Defense Impairment
  "T1687": "",
  // T1688 · Safe Mode Boot
  "T1688": "",
  // T1689 · Downgrade Attack
  "T1689": "",
  // T1690 · Prevent Command History Logging
  "T1690": "",

// ── Credential Access ────────────────────────────────────────────────────────
  // T1003 · OS Credential Dumping
  "T1003": "",
    // T1003.001 · LSASS Memory
  "T1003.001": "",
    // T1003.002 · Security Account Manager
  "T1003.002": "",
    // T1003.003 · NTDS
  "T1003.003": "",
    // T1003.004 · LSA Secrets
  "T1003.004": "",
    // T1003.005 · Cached Domain Credentials
  "T1003.005": "",
    // T1003.006 · DCSync
  "T1003.006": "",
    // T1003.007 · Proc Filesystem
  "T1003.007": "",
    // T1003.008 · /etc/passwd and /etc/shadow
  "T1003.008": "",
  // T1040 · Network Sniffing  [also: Discovery]
  "T1040": "",
  // T1056 · Input Capture  [also: Credential Access]
  "T1056": "",
    // T1056.001 · Keylogging  [also: Credential Access]
  "T1056.001": "",
    // T1056.002 · GUI Input Capture  [also: Credential Access]
  "T1056.002": "",
    // T1056.003 · Web Portal Capture  [also: Credential Access]
  "T1056.003": "",
    // T1056.004 · Credential API Hooking  [also: Credential Access]
  "T1056.004": "",
  // T1110 · Brute Force
  "T1110": "",
    // T1110.001 · Password Guessing
  "T1110.001": "",
    // T1110.002 · Password Cracking
  "T1110.002": "",
    // T1110.003 · Password Spraying
  "T1110.003": "",
    // T1110.004 · Credential Stuffing
  "T1110.004": "",
  // T1111 · Multi-Factor Authentication Interception
  "T1111": "",
  // T1187 · Forced Authentication
  "T1187": "",
  // T1212 · Exploitation for Credential Access
  "T1212": "",
  // T1528 · Steal Application Access Token
  "T1528": "",
  // T1539 · Steal Web Session Cookie
  "T1539": "",
  // T1552 · Unsecured Credentials
  "T1552": "",
    // T1552.001 · Credentials In Files
  "T1552.001": "",
    // T1552.002 · Credentials in Registry
  "T1552.002": "",
    // T1552.003 · Shell History
  "T1552.003": "",
    // T1552.004 · Private Keys
  "T1552.004": "",
    // T1552.005 · Cloud Instance Metadata API
  "T1552.005": "",
    // T1552.006 · Group Policy Preferences
  "T1552.006": "",
    // T1552.007 · Container API
  "T1552.007": "",
    // T1552.008 · Chat Messages
  "T1552.008": "",
  // T1555 · Credentials from Password Stores
  "T1555": "",
    // T1555.001 · Keychain
  "T1555.001": "",
    // T1555.002 · Securityd Memory
  "T1555.002": "",
    // T1555.003 · Credentials from Web Browsers
  "T1555.003": "",
    // T1555.004 · Windows Credential Manager
  "T1555.004": "",
    // T1555.005 · Password Managers
  "T1555.005": "",
    // T1555.006 · Cloud Secrets Management Stores
  "T1555.006": "",
  // T1557 · Adversary-in-the-Middle  [also: Collection]
  "T1557": "",
    // T1557.001 · Name Resolution Poisoning and SMB Relay  [also: Collection]
  "T1557.001": "",
    // T1557.002 · ARP Cache Poisoning  [also: Collection]
  "T1557.002": "",
    // T1557.003 · DHCP Spoofing  [also: Collection]
  "T1557.003": "",
    // T1557.004 · Evil Twin  [also: Collection]
  "T1557.004": "",
  // T1558 · Steal or Forge Kerberos Tickets
  "T1558": "",
    // T1558.001 · Golden Ticket
  "T1558.001": "",
    // T1558.002 · Silver Ticket
  "T1558.002": "",
    // T1558.003 · Kerberoasting
  "T1558.003": "",
    // T1558.004 · AS-REP Roasting
  "T1558.004": "",
    // T1558.005 · Ccache Files
  "T1558.005": "",
  // T1606 · Forge Web Credentials
  "T1606": "",
    // T1606.001 · Web Cookies
  "T1606.001": "",
    // T1606.002 · SAML Tokens
  "T1606.002": "",
  // T1621 · Multi-Factor Authentication Request Generation
  "T1621": "",
  // T1649 · Steal or Forge Authentication Certificates
  "T1649": "",

// ── Discovery ────────────────────────────────────────────────────────────────
  // T1007 · System Service Discovery
  "T1007": "",
  // T1010 · Application Window Discovery
  "T1010": "",
  // T1012 · Query Registry
  "T1012": "",
  // T1016 · System Network Configuration Discovery
  "T1016": "",
    // T1016.001 · Internet Connection Discovery
  "T1016.001": "",
    // T1016.002 · Wi-Fi Discovery
  "T1016.002": "",
  // T1018 · Remote System Discovery
  "T1018": "",
  // T1033 · System Owner/User Discovery
  "T1033": "",
  // T1046 · Network Service Discovery
  "T1046": "",
  // T1049 · System Network Connections Discovery
  "T1049": "",
  // T1057 · Process Discovery
  "T1057": "",
  // T1069 · Permission Groups Discovery
  "T1069": "",
    // T1069.001 · Local Groups
  "T1069.001": "",
    // T1069.002 · Domain Groups
  "T1069.002": "",
    // T1069.003 · Cloud Groups
  "T1069.003": "",
  // T1082 · System Information Discovery
  "T1082": "",
  // T1083 · File and Directory Discovery
  "T1083": "",
  // T1087 · Account Discovery
  "T1087": "",
    // T1087.001 · Local Account
  "T1087.001": "",
    // T1087.002 · Domain Account
  "T1087.002": "",
    // T1087.003 · Email Account
  "T1087.003": "",
    // T1087.004 · Cloud Account
  "T1087.004": "",
  // T1120 · Peripheral Device Discovery
  "T1120": "",
  // T1124 · System Time Discovery
  "T1124": "",
  // T1135 · Network Share Discovery
  "T1135": "",
  // T1201 · Password Policy Discovery
  "T1201": "",
  // T1217 · Browser Information Discovery
  "T1217": "",
  // T1482 · Domain Trust Discovery
  "T1482": "",
  // T1518 · Software Discovery
  "T1518": "",
    // T1518.001 · Security Software Discovery
  "T1518.001": "",
    // T1518.002 · Backup Software Discovery
  "T1518.002": "",
  // T1526 · Cloud Service Discovery
  "T1526": "",
  // T1538 · Cloud Service Dashboard
  "T1538": "",
  // T1580 · Cloud Infrastructure Discovery
  "T1580": "",
  // T1613 · Container and Resource Discovery
  "T1613": "",
  // T1614 · System Location Discovery
  "T1614": "",
    // T1614.001 · System Language Discovery
  "T1614.001": "",
  // T1615 · Group Policy Discovery
  "T1615": "",
  // T1619 · Cloud Storage Object Discovery
  "T1619": "",
  // T1652 · Device Driver Discovery
  "T1652": "",
  // T1654 · Log Enumeration
  "T1654": "",
  // T1673 · Virtual Machine Discovery
  "T1673": "",
  // T1680 · Local Storage Discovery
  "T1680": "",

// ── Lateral Movement ─────────────────────────────────────────────────────────
  // T1021 · Remote Services
  "T1021": "",
    // T1021.001 · Remote Desktop Protocol
  "T1021.001": "",
    // T1021.002 · SMB/Windows Admin Shares
  "T1021.002": "",
    // T1021.003 · Distributed Component Object Model
  "T1021.003": "",
    // T1021.004 · SSH
  "T1021.004": "",
    // T1021.005 · VNC
  "T1021.005": "",
    // T1021.006 · Windows Remote Management
  "T1021.006": "",
    // T1021.007 · Cloud Services
  "T1021.007": "",
    // T1021.008 · Direct Cloud VM Connections
  "T1021.008": "",
  // T1051 · Shared Webroot
  "T1051": "",
  // T1080 · Taint Shared Content
  "T1080": "",
  // T1210 · Exploitation of Remote Services
  "T1210": "",
  // T1534 · Internal Spearphishing
  "T1534": "",
  // T1550 · Use Alternate Authentication Material
  "T1550": "",
    // T1550.001 · Application Access Token
  "T1550.001": "",
    // T1550.002 · Pass the Hash
  "T1550.002": "",
    // T1550.003 · Pass the Ticket
  "T1550.003": "",
    // T1550.004 · Web Session Cookie
  "T1550.004": "",
  // T1563 · Remote Service Session Hijacking
  "T1563": "",
    // T1563.001 · SSH Hijacking
  "T1563.001": "",
    // T1563.002 · RDP Hijacking
  "T1563.002": "",
  // T1570 · Lateral Tool Transfer
  "T1570": "",

// ── Collection ───────────────────────────────────────────────────────────────
  // T1005 · Data from Local System
  "T1005": "",
  // T1025 · Data from Removable Media
  "T1025": "",
  // T1039 · Data from Network Shared Drive
  "T1039": "",
  // T1074 · Data Staged
  "T1074": "",
    // T1074.001 · Local Data Staging
  "T1074.001": "",
    // T1074.002 · Remote Data Staging
  "T1074.002": "",
  // T1113 · Screen Capture
  "T1113": "",
  // T1114 · Email Collection
  "T1114": "",
    // T1114.001 · Local Email Collection
  "T1114.001": "",
    // T1114.002 · Remote Email Collection
  "T1114.002": "",
    // T1114.003 · Email Forwarding Rule
  "T1114.003": "",
  // T1115 · Clipboard Data
  "T1115": "",
  // T1119 · Automated Collection
  "T1119": "",
  // T1123 · Audio Capture
  "T1123": "",
  // T1125 · Video Capture
  "T1125": "",
  // T1185 · Browser Session Hijacking
  "T1185": "",
  // T1213 · Data from Information Repositories
  "T1213": "",
    // T1213.001 · Confluence
  "T1213.001": "",
    // T1213.002 · Sharepoint
  "T1213.002": "",
    // T1213.003 · Code Repositories
  "T1213.003": "",
    // T1213.004 · Customer Relationship Management Software
  "T1213.004": "",
    // T1213.005 · Messaging Applications
  "T1213.005": "",
    // T1213.006 · Databases
  "T1213.006": "",
  // T1530 · Data from Cloud Storage
  "T1530": "",
  // T1560 · Archive Collected Data
  "T1560": "",
    // T1560.001 · Archive via Utility
  "T1560.001": "",
    // T1560.002 · Archive via Library
  "T1560.002": "",
    // T1560.003 · Archive via Custom Method
  "T1560.003": "",
  // T1602 · Data from Configuration Repository
  "T1602": "",
    // T1602.001 · SNMP (MIB Dump)
  "T1602.001": "",
    // T1602.002 · Network Device Configuration Dump
  "T1602.002": "",

// ── Command and Control ──────────────────────────────────────────────────────
  // T1001 · Data Obfuscation
  "T1001": "",
    // T1001.001 · Junk Data
  "T1001.001": "",
    // T1001.002 · Steganography
  "T1001.002": "",
    // T1001.003 · Protocol or Service Impersonation
  "T1001.003": "",
  // T1008 · Fallback Channels
  "T1008": "",
  // T1026 · Multiband Communication
  "T1026": "",
  // T1043 · Commonly Used Port
  "T1043": "",
  // T1071 · Application Layer Protocol
  "T1071": "",
    // T1071.001 · Web Protocols
  "T1071.001": "",
    // T1071.002 · File Transfer Protocols
  "T1071.002": "",
    // T1071.003 · Mail Protocols
  "T1071.003": "",
    // T1071.004 · DNS
  "T1071.004": "",
    // T1071.005 · Publish/Subscribe Protocols
  "T1071.005": "",
  // T1090 · Proxy
  "T1090": "",
    // T1090.001 · Internal Proxy
  "T1090.001": "",
    // T1090.002 · External Proxy
  "T1090.002": "",
    // T1090.003 · Multi-hop Proxy
  "T1090.003": "",
    // T1090.004 · Domain Fronting
  "T1090.004": "",
  // T1092 · Communication Through Removable Media
  "T1092": "",
  // T1095 · Non-Application Layer Protocol
  "T1095": "",
  // T1102 · Web Service
  "T1102": "",
    // T1102.001 · Dead Drop Resolver
  "T1102.001": "",
    // T1102.002 · Bidirectional Communication
  "T1102.002": "",
    // T1102.003 · One-Way Communication
  "T1102.003": "",
  // T1104 · Multi-Stage Channels
  "T1104": "",
  // T1105 · Ingress Tool Transfer
  "T1105": "",
  // T1132 · Data Encoding
  "T1132": "",
    // T1132.001 · Standard Encoding
  "T1132.001": "",
    // T1132.002 · Non-Standard Encoding
  "T1132.002": "",
  // T1219 · Remote Access Tools
  "T1219": "",
    // T1219.001 · IDE Tunneling
  "T1219.001": "",
    // T1219.002 · Remote Desktop Software
  "T1219.002": "",
    // T1219.003 · Remote Access Hardware
  "T1219.003": "",
  // T1568 · Dynamic Resolution
  "T1568": "",
    // T1568.001 · Fast Flux DNS
  "T1568.001": "",
    // T1568.002 · Domain Generation Algorithms
  "T1568.002": "",
    // T1568.003 · DNS Calculation
  "T1568.003": "",
  // T1571 · Non-Standard Port
  "T1571": "",
  // T1572 · Protocol Tunneling
  "T1572": "",
  // T1573 · Encrypted Channel
  "T1573": "",
    // T1573.001 · Symmetric Cryptography
  "T1573.001": "",
    // T1573.002 · Asymmetric Cryptography
  "T1573.002": "",
  // T1665 · Hide Infrastructure
  "T1665": "",

// ── Exfiltration ─────────────────────────────────────────────────────────────
  // T1011 · Exfiltration Over Other Network Medium
  "T1011": "",
    // T1011.001 · Exfiltration Over Bluetooth
  "T1011.001": "",
  // T1020 · Automated Exfiltration
  "T1020": "",
    // T1020.001 · Traffic Duplication
  "T1020.001": "",
  // T1029 · Scheduled Transfer
  "T1029": "",
  // T1030 · Data Transfer Size Limits
  "T1030": "",
  // T1041 · Exfiltration Over C2 Channel
  "T1041": "",
  // T1048 · Exfiltration Over Alternative Protocol
  "T1048": "",
    // T1048.001 · Exfiltration Over Symmetric Encrypted Non-C2 Protocol
  "T1048.001": "",
    // T1048.002 · Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
  "T1048.002": "",
    // T1048.003 · Exfiltration Over Unencrypted Non-C2 Protocol
  "T1048.003": "",
  // T1052 · Exfiltration Over Physical Medium
  "T1052": "",
    // T1052.001 · Exfiltration over USB
  "T1052.001": "",
  // T1537 · Transfer Data to Cloud Account
  "T1537": "",
  // T1567 · Exfiltration Over Web Service
  "T1567": "",
    // T1567.001 · Exfiltration to Code Repository
  "T1567.001": "",
    // T1567.002 · Exfiltration to Cloud Storage
  "T1567.002": "",
    // T1567.003 · Exfiltration to Text Storage Sites
  "T1567.003": "",
    // T1567.004 · Exfiltration Over Webhook
  "T1567.004": "",

// ── Impact ───────────────────────────────────────────────────────────────────
  // T1485 · Data Destruction
  "T1485": "",
    // T1485.001 · Lifecycle-Triggered Deletion
  "T1485.001": "",
  // T1486 · Data Encrypted for Impact
  "T1486": "",
  // T1489 · Service Stop
  "T1489": "",
  // T1490 · Inhibit System Recovery
  "T1490": "",
  // T1491 · Defacement
  "T1491": "",
    // T1491.001 · Internal Defacement
  "T1491.001": "",
    // T1491.002 · External Defacement
  "T1491.002": "",
  // T1495 · Firmware Corruption
  "T1495": "",
  // T1496 · Resource Hijacking
  "T1496": "",
    // T1496.001 · Compute Hijacking
  "T1496.001": "",
    // T1496.002 · Bandwidth Hijacking
  "T1496.002": "",
    // T1496.003 · SMS Pumping
  "T1496.003": "",
    // T1496.004 · Cloud Service Hijacking
  "T1496.004": "",
  // T1498 · Network Denial of Service
  "T1498": "",
    // T1498.001 · Direct Network Flood
  "T1498.001": "",
    // T1498.002 · Reflection Amplification
  "T1498.002": "",
  // T1499 · Endpoint Denial of Service
  "T1499": "",
    // T1499.001 · OS Exhaustion Flood
  "T1499.001": "",
    // T1499.002 · Service Exhaustion Flood
  "T1499.002": "",
    // T1499.003 · Application Exhaustion Flood
  "T1499.003": "",
    // T1499.004 · Application or System Exploitation
  "T1499.004": "",
  // T1529 · System Shutdown/Reboot
  "T1529": "",
  // T1531 · Account Access Removal
  "T1531": "",
  // T1561 · Disk Wipe
  "T1561": "",
    // T1561.001 · Disk Content Wipe
  "T1561.001": "",
    // T1561.002 · Disk Structure Wipe
  "T1561.002": "",
  // T1565 · Data Manipulation
  "T1565": "",
    // T1565.001 · Stored Data Manipulation
  "T1565.001": "",
    // T1565.002 · Transmitted Data Manipulation
  "T1565.002": "",
    // T1565.003 · Runtime Data Manipulation
  "T1565.003": "",
  // T1657 · Financial Theft
  "T1657": "",
  // T1667 · Email Bombing
  "T1667": "",

// ══════════════════════════════════════════════════════════════════════════════
// MOBILE-ONLY — ATT&CK Mobile v19
//
// Enterprise notes take precedence. Techniques that share a name with an Enterprise
// technique (e.g. Phishing: Mobile T1660 ↔ Enterprise T1566) automatically display
// the Enterprise note via canonicalId lookup — no entry is needed here for those.
//
// The entries below cover Mobile techniques that have NO Enterprise equivalent.
// ══════════════════════════════════════════════════════════════════════════════

// ── Initial Access (Mobile) ──────────────────────────────────────────────────
  // T1444 · Masquerade as Legitimate Application  [also: Defense Evasion]
  "T1444": "",
  // T1451 · SIM Card Swap
  "T1451": "",
  // T1456 · Drive-By Compromise
  "T1456": "",
  // T1461 · Lockscreen Bypass
  "T1461": "",
  // T1475 · Deliver Malicious App via Authorized App Store
  "T1475": "",
  // T1476 · Deliver Malicious App via Other Means
  "T1476": "",
  // T1477 · Exploit via Radio Interfaces
  "T1477": "",
  // T1661 · Application Versioning  [also: Defense Evasion]
  "T1661": "",
  // T1664 · Exploitation for Initial Access
  "T1664": "",

// ── Persistence (Mobile) ─────────────────────────────────────────────────────
  // T1399 · Modify Trusted Execution Environment  [also: Persistence]
  "T1399": "",
  // T1403 · Modify Cached Executable Code
  "T1403": "",
  // T1541 · Foreground Persistence  [also: Persistence]
  "T1541": "",
  // T1577 · Compromise Application Executable
  "T1577": "",
    // T1624.001 · Broadcast Receivers
  "T1624.001": "",
    // T1625.001 · System Runtime API Hijacking
  "T1625.001": "",
  // T1645 · Compromise Client Software Binary
  "T1645": "",
  // T1676 · Linked Devices  [also: Persistence]
  "T1676": "",

// ── Privilege Escalation (Mobile) ────────────────────────────────────────────
  // T1405 · Exploit TEE Vulnerability  [also: Privilege Escalation]
  "T1405": "",
    // T1626.001 · Device Administrator Permissions
  "T1626.001": "",

// ── Defense Evasion (Mobile) ─────────────────────────────────────────────────
  // T1407 · Download New Code at Runtime
  "T1407": "",
  // T1604 · Proxy Through Victim
  "T1604": "",
  // T1617 · Hooking
  "T1617": "",
    // T1627.001 · Geofencing
  "T1627.001": "",
    // T1628.001 · Suppress Application Icon
  "T1628.001": "",
    // T1628.002 · User Evasion
  "T1628.002": "",
    // T1628.003 · Conceal Multimedia Files
  "T1628.003": "",
  // T1629 · Impair Defenses
  "T1629": "",
    // T1629.001 · Prevent Application Removal
  "T1629.001": "",
    // T1629.002 · Device Lockout
  "T1629.002": "",
  // T1630 · Indicator Removal on Host
  "T1630": "",
    // T1630.001 · Uninstall Malicious Application
  "T1630.001": "",
    // T1630.003 · Disguise Root/Jailbreak Indicators
  "T1630.003": "",
    // T1655.001 · Match Legitimate Name or Location
  "T1655.001": "",
  // T1670 · Virtualization Solution
  "T1670": "",

// ── Credential Access (Mobile) ───────────────────────────────────────────────
  // T1413 · Access Sensitive Data in Device Logs  [also: Credential Access]
  "T1413": "",
  // T1453 · Abuse Accessibility Features  [also: Credential Access]
  "T1453": "",
  // T1517 · Access Notifications  [also: Credential Access]
  "T1517": "",
  // T1634 · Credentials from Password Store
  "T1634": "",
    // T1635.001 · URI Hijacking
  "T1635.001": "",

// ── Discovery (Mobile) ───────────────────────────────────────────────────────
  // T1423 · Network Service Scanning
  "T1423": "",
  // T1430 · Location Tracking  [also: Discovery]
  "T1430": "",
    // T1430.001 · Remote Device Management Services  [also: Discovery]
  "T1430.001": "",
    // T1430.002 · Impersonate SS7 Nodes  [also: Discovery]
  "T1430.002": "",

// ── Lateral Movement (Mobile) ────────────────────────────────────────────────
  // T1427 · Attack PC via USB Connection
  "T1427": "",

// ── Collection (Mobile) ──────────────────────────────────────────────────────
  // T1409 · Stored Application Data
  "T1409": "",
  // T1616 · Call Control  [also: Impact, Command and Control]
  "T1616": "",
  // T1636 · Protected User Data
  "T1636": "",
    // T1636.001 · Calendar Entries
  "T1636.001": "",
    // T1636.002 · Call Log
  "T1636.002": "",
    // T1636.003 · Contact List
  "T1636.003": "",
    // T1636.004 · SMS Messages
  "T1636.004": "",
    // T1636.005 · Accounts
  "T1636.005": "",

// ── Command and Control (Mobile) ─────────────────────────────────────────────
    // T1521.003 · SSL Pinning
  "T1521.003": "",
  // T1644 · Out of Band Data
  "T1644": "",
  // T1663 · Remote Access Software
  "T1663": "",

// ── Impact (Mobile) ──────────────────────────────────────────────────────────
  // T1582 · SMS Control
  "T1582": "",
  // T1643 · Generate Traffic from Victim
  "T1643": "",

// ── Network Effects (Mobile) ─────────────────────────────────────────────────
  // T1449 · Exploit SS7 to Redirect Phone Calls/SMS
  "T1449": "",

// ── Remote Service Effects (Mobile) ──────────────────────────────────────────
  // T1469 · Remotely Wipe Data Without Authorization
  "T1469": "",
  // T1470 · Obtain Device Cloud Backups
  "T1470": "",

// ══════════════════════════════════════════════════════════════════════════════
// ICS-ONLY — ATT&CK ICS v19
//
// Enterprise notes take precedence. Techniques that share a name with an Enterprise
// technique (e.g. Valid Accounts: ICS T0859 ↔ Enterprise T1078) automatically display
// the Enterprise note via canonicalId lookup — no entry is needed here for those.
//
// The entries below cover ICS techniques that have NO Enterprise equivalent.
// ══════════════════════════════════════════════════════════════════════════════

// ── Initial Access (ICS) ─────────────────────────────────────────────────────
  // T0848 · Rogue Master
  "T0848": "",
  // T0860 · Wireless Compromise
  "T0860": "",
  // T0864 · Transient Cyber Asset
  "T0864": "",
  // T0883 · Internet Accessible Device
  "T0883": "",

// ── Execution (ICS) ──────────────────────────────────────────────────────────
  // T0807 · Command-Line Interface
  "T0807": "",
  // T0821 · Modify Controller Tasking
  "T0821": "",
  // T0858 · Change Operating Mode  [also: Evasion]
  "T0858": "",
  // T0871 · Execution through API
  "T0871": "",
  // T0874 · Hooking  [also: Privilege Escalation]
  "T0874": "",
  // T0895 · Autorun Image
  "T0895": "",

// ── Persistence (ICS) ────────────────────────────────────────────────────────
  // T0873 · Project File Infection
  "T0873": "",
    // T0873.001 · Siemens Project File Format
  "T0873.001": "",
  // T0889 · Modify Program
  "T0889": "",
  // T1693 · Modify Firmware  [also: Inhibit Response Function, Impair Process Control]
  "T1693": "",
    // T1693.002 · Module Firmware  [also: Inhibit Response Function, Impair Process Control]
  "T1693.002": "",
  // T1694 · Insecure Credentials  [also: Lateral Movement]
  "T1694": "",
    // T1694.001 · Default Credentials  [also: Lateral Movement]
  "T1694.001": "",
    // T1694.002 · Hardcoded Credentials  [also: Lateral Movement]
  "T1694.002": "",

// ── Evasion (ICS) ────────────────────────────────────────────────────────────
  // T0820 · Exploitation for Evasion
  "T0820": "",
  // T0872 · Indicator Removal on Host
  "T0872": "",
  // T1692 · Unauthorized Message  [also: Impair Process Control]
  "T1692": "",
    // T1692.001 · Command Message  [also: Impair Process Control]
  "T1692.001": "",
    // T1692.002 · Reporting Message  [also: Impair Process Control]
  "T1692.002": "",

// ── Discovery (ICS) ──────────────────────────────────────────────────────────
  // T0840 · Network Connection Enumeration
  "T0840": "",
    // T0846.001 · Port Scan
  "T0846.001": "",
    // T0846.002 · Broadcast Discovery
  "T0846.002": "",
    // T0846.003 · Multicast Discovery
  "T0846.003": "",
  // T0887 · Wireless Sniffing  [also: Collection]
  "T0887": "",
  // T0888 · Remote System Information Discovery
  "T0888": "",

// ── Lateral Movement (ICS) ───────────────────────────────────────────────────
  // T0843 · Program Download
  "T0843": "",
    // T0843.001 · Download All
  "T0843.001": "",
    // T0843.002 · Online Edit
  "T0843.002": "",
    // T0843.003 · Program Append
  "T0843.003": "",

// ── Collection (ICS) ─────────────────────────────────────────────────────────
  // T0801 · Monitor Process State
  "T0801": "",
  // T0845 · Program Upload
  "T0845": "",
  // T0861 · Point & Tag Identification
  "T0861": "",
  // T0868 · Detect Operating Mode
  "T0868": "",
  // T0877 · I/O Image
  "T0877": "",

// ── Command and Control (ICS) ────────────────────────────────────────────────
  // T0869 · Standard Application Layer Protocol
  "T0869": "",
  // T0884 · Connection Proxy
  "T0884": "",

// ── Inhibit Response Function (ICS) ──────────────────────────────────────────
  // T0800 · Activate Firmware Update Mode
  "T0800": "",
  // T0814 · Denial of Service
  "T0814": "",
  // T0816 · Device Restart/Shutdown
  "T0816": "",
  // T0835 · Manipulate I/O Image
  "T0835": "",
  // T0838 · Modify Alarm Settings
  "T0838": "",
  // T0878 · Alarm Suppression
  "T0878": "",
  // T0892 · Change Credential
  "T0892": "",
  // T1691 · Block Operational Technology Message
  "T1691": "",
    // T1691.001 · Command Message
  "T1691.001": "",
    // T1691.002 · Reporting Message
  "T1691.002": "",
  // T1695 · Block Communications
  "T1695": "",
    // T1695.001 · Serial COM
  "T1695.001": "",
    // T1695.002 · Ethernet
  "T1695.002": "",
    // T1695.003 · Wi-Fi
  "T1695.003": "",

// ── Impair Process Control (ICS) ─────────────────────────────────────────────
  // T0806 · Brute Force I/O
  "T0806": "",
  // T0836 · Modify Parameter
  "T0836": "",

// ── Impact (ICS) ─────────────────────────────────────────────────────────────
  // T0813 · Denial of Control
  "T0813": "<p>Link to article when hackers took over https://www.theguardian.com/us-news/2017/apr/09/dallas-hackers-sirens-alarms-emergency-system emergency sirens in Dallas</p> ",
  // T0815 · Denial of View
  "T0815": "",
  // T0826 · Loss of Availability
  "T0826": "",
  // T0827 · Loss of Control
  "T0827": "",
  // T0828 · Loss of Productivity and Revenue
  "T0828": "",
  // T0829 · Loss of View
  "T0829": "",
  // T0831 · Manipulation of Control
  "T0831": "",
  // T0832 · Manipulation of View
  "T0832": "",
  // T0837 · Loss of Protection
  "T0837": "",
  // T0879 · Damage to Property
  "T0879": "",
  // T0880 · Loss of Safety
  "T0880": "",
  // T0882 · Theft of Operational Information
  "T0882": "",

// ══════════════════════════════════════════════════════════════════════════════
// LEGACY — Revoked or deprecated Enterprise IDs retained from earlier builds.
// These are no longer active in ATT&CK v19. Keep any written notes; remove
// the placeholder empties if you prefer a cleaner file.
// ══════════════════════════════════════════════════════════════════════════════

  // T1022
  "T1022": "",
  // T1562.001
  "T1562.001": "",
  // T1562.003
  "T1562.003": "",
  // T1562.006
  "T1562.006": "",
  // T1574.002
  "T1574.002": "",

};
