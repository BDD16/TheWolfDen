# Ethical Disclosure and Incident Response Report — Tron Campaign (IMG_0118.JPG)

*Author:* Blake De Garza  
*Date:* 2025-10-15  
*Classification:* Coordinated Ethical Disclosure – Multi-Stage Cross-Platform Exploitation

---

## 🧩 Ethical Disclosure Report — *Tron Behavioral Network: IMG_0118.JPG Campaign*

**Author:** Blake De Garza  
**Date:** 2025-10-15  
**Classification:** Multi Stage Cross Platform Exploitation  

(Full detailed analysis and mitigations omitted here for brevity; see sections below)

---

# macOS Technical Bug Analysis — IMG_0118.JPG & Associated Payloads

**Author:** Blake De Garza**  
**Date:** 2025-10-14**  

Primary sources: Sandbox dynamic execution logs parsed and correlated with PlantUML visualizations.

## Executive Summary

The file `IMG_0118.JPG` behaves as a stage0 loader on macOS. Sandbox and payload artifacts indicate the JPG contained a hidden resource fork that launched a downloader/persistence chain leveraging macOS system services and Microsoft Office integration points (font cache, LaunchAgents, QuickLook) to fetch secondary payloads from CDN infrastructure (`*.cdn.office.net`, `odc.officeapps.live.com`, `smoot.apple.com`) and establish persistence and telemetry.

### Infection Chain (High Level)

```
IMG_0118.JPG (T+0s)
  └─(exec via /bin/zsh)→ LaunchAgent load (com.microsoft.update.agent.plist)
      └─(stage1) metadata/templates CDN contact → binary downloader
         └─(stage2) payload fetch from Office CDNs & Apple CDNs
            └─(stage3) drop modified TTFs into Office FontCache + QuickLook interactions
               └─(stage4) persistence (LaunchAgent/PrivilegedHelperTools) + telemetry
```

### Key Observations

- Executed via `/bin/zsh -c "/Users/run/IMG_0118.jpg"`  
- LaunchAgent loaded: `/Library/LaunchAgents/com.microsoft.update.agent.plist`  
- File writes under Office Group Container font cache  
- TLS connections to Office CDN and Apple CDN endpoints  

---

## Technical Findings (macOS focused)

### 1. Execution & Initial Trigger
The JPG was executed directly, suggesting either a disguised binary or a resource fork. Evidence of `sudo` + `/bin/zsh` indicates privilege escalation attempts.

**ATT&CK mappings:**  
T1569.001 Launchctl, T1543.001 Launch Agent, T1564.009 Hidden/Resource Forks.

### 2. Launch Agents & Persistence
Creates `/Library/LaunchAgents/com.microsoft.update.agent.plist` and uses `/Library/PrivilegedHelperTools/com.microsoft.autoupdate.helper`.  
Remains resident post-removal, reloading automatically.

### 3. Font Cache & QuickLook Abuse
Drops malformed TTFs under:
`~/Library/Group Containers/UBF8T346G9.Office/FontCache/`  
These fonts contain corrupted tables (`name`, `glyf`, `cmap`), potentially executing during preview rendering (QuickLookUIHelper).

### 4. Network Infrastructure & CDN Abuse
**CDN endpoints:**
- `metadata.templates.cdn.office.net`
- `binaries.templates.cdn.office.net`
- `odc.officeapps.live.com`
- `cdn2.smoot.apple.com`, `api2.smoot.apple.com`
- `ocsp.edge.digicert.com` (legitimate cert validation)
- DNS fallback to `8.8.8.8`

### 5. Process & System Interactions
Observed processes: QuickLookUIHelper, storeuid, Microsoft AutoUpdate, pkreporter.  
Potential camouflage through Apple telemetry daemons.

---

## Windows Considerations (Brief)

CDN payloads may include Windows branches (DLLs, MSI).  
Analogous persistence: Scheduled Tasks, registry hijack (`.dat` handler).

---

## Impact Assessment (macOS)

| Dimension | Impact | Description |
|------------|---------|-------------|
| Confidentiality | Medium | Potential exfil via telemetry endpoints |
| Integrity | High | Persistent privilege escalation |
| Availability | Low | No destructive behavior observed |

---

## Remediation & Hardening (macOS)

### Immediate Response
- Isolate host  
- Collect artifacts (`ls -la@`, `xattr -l`, logs)  
- Remove LaunchAgents and PrivilegedHelperTools  
- Rebuild QuickLook/font caches  

### Commands

```bash
sudo launchctl bootout gui/$(id -u) /Library/LaunchAgents/com.microsoft.update.agent.plist
sudo rm /Library/LaunchAgents/com.microsoft.update.agent.plist
sudo rm /Library/PrivilegedHelperTools/com.microsoft.autoupdate.helper
rm -rf ~/Library/Group\ Containers/UBF8T346G9.Office/FontCache/*
qlmanage -r cache
```

### Hardening
- Disable automatic preview of attachments  
- Enforce Gatekeeper & notarization  
- Monitor LaunchAgent writes and QuickLook triggers  

---

## Hunting Queries

```bash
mdfind -name com.microsoft.update.agent.plist
sudo find / -type f -path '*Group Containers*UBF8T346G9.Office*FontCache*'
log show --info --predicate 'process == "launchd" OR process == "QuickLookUIHelper"' --last 1h
```

---

## IOCs

**Files**
- `/Users/run/IMG_0118.jpg`
- `/Library/LaunchAgents/com.microsoft.update.agent.plist`
- `/Library/PrivilegedHelperTools/com.microsoft.autoupdate.helper`
- `~/Library/Group Containers/UBF8T346G9.Office/FontCache/...`

**Network**
- `metadata.templates.cdn.office.net` → 23.10.230.236  
- `binaries.templates.cdn.office.net` → 23.10.239.251  
- `odc.officeapps.live.com` → 52.109.124.141  
- `cdn2.smoot.apple.com`, `api2.smoot.apple.com`  
- DNS fallback: 8.8.8.8  

---

## Conclusion

IMG_0118.JPG acts as a steganographic execution trigger that abuses macOS trusted components (LaunchAgents, QuickLook, Office font caches).  
The use of legitimate CDN infrastructure, font-level payloads, and resource forks creates an evasive, persistent threat requiring both immediate cleanup and future telemetry-based monitoring.

---

## Appendix — SHA256 Reference Table

| SHA256 | File / Path | Source |
|---------|--------------|--------|
| 4c41e4bc290496111489622fb119392b393b2a61f3b588f64c65ebd4368ed7db | hier_officeFontsPreview_4_42.ttf | Sandbox |
| b951ec03a58100ff2a8781191312af1d164646f67b7ea42f0dbc76ea15b904a9 | IMG_0118.JPG | Sandbox |
| c949d1f02630fb8bd979377309fc55316276d49fd0cbcdefb0fd5210bac44d25 | SearchHoverUnifiedTileModelCache.dat | FontFile_Payload |
| 7c00a941d7a04048f469ffb986ff7e8bf349f149639cc474a463da4a607c0a70 | manifest.json | FontFile_Payload |
| ab451f6f5a137251e2cd58a138fbc75b85da7d6a1f42b5f9153d3431b380f967 | Local State (Edge) | FontFile_Payload |

---

**End of Report**  
© 2025 — Coordinated Ethical Disclosure – Blake D
