# SBT-DF204 — Case Study 1: Investigating Harassment Email Traffic With Wireshark

Forensic reconstruction of a harassment email communication from a packet capture — HTTP POST recovery, cookie-based identity analysis, and attribution assessment under shared-network limitations.

---

## Author

| Field | Detail |
| :--- | :--- |
| **Student** | Ibrahim Diseh Garba |
| **Registration No.** | `2025/FWSD/11521` |
| **Programme** | Fellowship in Web Application Security & Digital Forensics |
| **Institution** | International Cybersecurity and Digital Forensics Academy (ICDFA) |
| **Course** | SBT-DF204 — Computer Forensics Case Studies |
| **Instructor** | Aminu Idris, AMCPN |
| **Batch** | BATCH-B2025 · L1/S2 |
| **Submission Date** | 5 October 2026 |

--- 

## Overview

This repository contains the forensic analysis of a packet capture supplied as part of the SBT-DF204 Nitroba University Harassment Scenario (Digital Corpora). The complaint alleges that a student in **Chemistry 109** sent repeated harassing emails to a teacher, **Lily Tuckrige**, via the anonymous web service `willselfdestruct.com`. The capture was taken at the boundary of a shared student residence where an **open, unpassworded wireless router** provides internet access.

The analysis preserves the original evidence with SHA-256 verification, isolates the POST request that submitted the harassment message, reconstructs the full HTTP dialogue via Follow TCP Stream, extracts the client MAC address and Gmail cookie-based identity, and cross-references a matching name on the Chemistry 109 roster.

Attribution is presented as **high confidence for the device** and **moderate-to-high confidence for the individual**, because the shared open network does not permit IP-to-person proof.

---

## Objectives

1. Acquire and preserve the supplied traffic capture with a documented hash and verified working copy.
2. Use Wireshark display filters to locate HTTP activity against `willselfdestruct.com`.
3. Reconstruct the transmitted message using Follow TCP Stream.
4. Identify the client device via MAC address and correlate it with cookie evidence.
5. Assess whether the evidence supports attribution to a student on the Chemistry 109 roster.
6. Document a timeline using exact PCAP timestamps and identify the time zone displayed.
7. State the conclusion with a confidence level and at least two limitations.

---

## Environment

| Component | Value |
| :--- | :--- |
| Operating System | Kali Linux 2025.3 (VMware) |
| Packet Analysis | Wireshark 4.x, TShark 4.x |
| Evidence Source | Digital Corpora — Nitroba Harassment Scenario |
| Capture Size | 56,180,821 bytes |
| Analysis Mode | Offline only — no live network contacted |

---

## Methodology

| Step | Action | Filter / Command |
| :---: | :--- | :--- |
| 1 | Verify integrity | `sha256sum` on original and working copy |
| 2 | Locate willselfdestruct traffic | `http.host contains "willselfdestruct"` |
| 3 | Isolate the POST | `http.request.method == "POST" && http.host contains "willselfdestruct"` |
| 4 | Extract form data | `frame.number == 83601` with `-e urlencoded-form.key -e urlencoded-form.value` |
| 5 | Reconstruct the dialogue | `tshark -q -z follow,tcp,ascii,1707` |
| 6 | Identify the device | `frame.number == 83601` with `-e eth.src` |
| 7 | Find identity evidence | `eth.addr == 00:17:f2:e2:c0:ce && http.cookie contains "gmail"` |
| 8 | Build timeline | `-e frame.time` across the filtered frames |

---

## Key Findings

| Indicator | Value |
| :--- | :--- |
| Capture file | `nitroba.pcap` — 56,180,821 bytes |
| SHA-256 | `2b77a9eaefc1d6af163d1ba793c96dbccacb04e6befdf1a0b01f8c67553ec2fb` |
| Client IP | `192.168.15.4` |
| Service IP | `69.25.94.22` (`www.willselfdestruct.com`) |
| POST frame | `83601` at `2008-07-22 02:04:24.311700 EDT` |
| TCP stream | `1707` |
| Source MAC | `00:17:f2:e2:c0:ce` (OUI registered to Apple, Inc.) |
| Form recipient | `lilytuckrige@yahoo.com` |
| Form subject | `you can't find us` |
| Form message | `and you can't hide from us. Stop teaching. Start running.` |
| Gmail cookie | `gmail=chat=jcoachj@gmail.com/475090` |
| Gmail frames | 79023, 79030, 79032, 79037, 79044, 79049, 79053 |
| Candidate identity | `jcoachj@gmail.com` |
| Roster match | Johnny Coach (Chemistry 109) |
| Confidence | High (device, 95%) · Moderate-to-High (individual, 75–85%) |

### Verdict

The device at MAC `00:17:f2:e2:c0:ce` submitted the harassment POST at frame 83601. The same MAC carried a Gmail chat cookie identifying a Gmail account that pattern-matches **Johnny Coach** on the roster. Because the network is an **open shared wireless network**, IP-level evidence cannot prove the operator. MAC + cookie + roster combination supports moderate-to-high personal attribution — **not proof beyond reasonable doubt**.

---

### License

Submitted as academic coursework for SBT-DF204 Case Study 1 at ICDFA. Contents may not be redistributed, reused, or reproduced without written permission from the author and ICDFA.

© 2026 Ibrahim Diseh Garba. All rights reserved.
