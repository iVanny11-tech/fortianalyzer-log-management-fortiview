![FortiAnalyzer Log Management & FortiView](banner.svg)

# FortiAnalyzer Log Management & FortiView – Investigating Threats from Raw Logs

> **Platform:** FortiAnalyzer (Centralized Logging) + FortiGate NGFW
> **Tools Used:** FortiAnalyzer GUI & CLI, FortiGate, Nikto Web Scanner, PuTTY, Linux Shell
> **Skills Demonstrated:** Log Import & Management, Log View Filtering, Custom Views, IPS Configuration, FortiView Threat Hunting, Traffic Analysis, CLI Diagnostics

---

## Project Summary

In this project, I worked with **FortiAnalyzer** as the central logging and analysis platform for a small FortiGate environment. I imported historical FortiGate log files, generated live traffic, examined that traffic in Log View, built a custom log view, configured IPS protection for a web server, launched a real attack against it with the Nikto scanner, and then used **FortiView** to detect and trace that attack back to its source. I finished by using FortiAnalyzer's CLI diagnostics to check log throughput and storage health.

---

## Environment

![Network Topology](diagram-network-topology.svg)

BR1-FGT-1 and FortiAnalyzer aren't part of this traffic path — they sit outside it, receiving logs from it. That log flow (and how it leads to the findings below) is broken out separately in [Log & Attack Investigation Flow](#log--attack-investigation-flow).

| Device             | Role                                           | Address / Notes              |
|---------------------|-------------------------------------------------|-------------------------------|
| HQ-NGFW-1           | Edge FortiGate NGFW (main lab firewall)         | Management GUI                |
| HQ-ISFW             | Internal segmentation firewall                  | Management GUI                |
| BR1-FGT-1           | Branch FortiGate (logs imported, not live)      | FGVM02TM24013504               |
| FortiAnalyzer       | Centralized log collection & analysis (ADOM1)   | 10.0.13.125                    |
| LINUX-ISP           | External attacker host (ran Nikto)              | 100.65.0.254                   |
| Target Web Server   | Apache2, reached through a Virtual IP           | 100.65.0.200 → 10.0.11.50      |

---

## Log & Attack Investigation Flow

![Log and Attack Investigation Flow](diagram-log-and-attack-flow.svg)

Three sources feed FortiAnalyzer — two live (HQ-NGFW-1, HQ-ISFW), one historical (BR1-FGT-1, imported from file). From there, the same data splits into two analysis styles: Log View for raw record inspection, FortiView for aggregated threat hunting. Each style led to a different kind of finding, walked through step by step below.

---

## What I Did

### 1. Imported Historical Log Files into FortiAnalyzer

Before generating any live traffic, I used FortiAnalyzer's **Log View → Logs → Import** feature to load several pre-collected sets of FortiGate log files (text, native, and CSV formats, covering late March through April) so that historical data was available for analysis without waiting on live traffic.

![Import Log File Dialog](01-import-log-file-dialog.png)

I browsed through the backup log folders on the jump host to select the correct archives for each device before uploading them.

![Log File Sets in the File Browser](02-log-file-sets-browser.png)

---

### 2. Reviewed the Firewall Policy Generating the Traffic

Before analyzing logs, I checked the **Internet** firewall policy on HQ-NGFW-1 that actually produces the traffic FortiAnalyzer would log — incoming on port4 (LAN), outgoing on port2 (WAN), with AntiVirus, Web Filter, and DNS Filter security profiles enabled.

![Firewall Policy "Internet"](03-firewall-policy-internet.png)

---

### 3. Generated Live Traffic for Analysis

To have real, current traffic to analyze (rather than only historical imports), I ran a traffic-generation script from the internal Ubuntu desktop. This simulated multiple users browsing, streaming, and using file-sharing apps so FortiAnalyzer would have a realistic mix of logs to work with.

```bash
./traffic-generation.sh
```

![Traffic Generation Script Output](04-traffic-generation-script.png)

---

### 4. Examined Logs with Log View

With traffic flowing, I used **Log View → Logs** to inspect the raw traffic logs and drill into individual entries (source, destination, action, application, and policy fields).

![Log View – Traffic Logs](05-log-view-traffic-logs.png)

I also checked the **Security: Summary** dashboard for a quick aggregated view of top Application Control categories and top IPS attacks before drilling into specific log types like Web Filter and Application Control.

![Security: Summary Dashboard](06-security-summary-dashboard.png)

One useful finding here: filtering Application Control logs for P2P/BitTorrent traffic showed an **Action of "pass"** under **Policy ID 1** — meaning the Internet policy was allowing BitTorrent traffic through even though it was being logged as a flagged application. In a real environment, that's a signal the policy needs tightening.

---

### 5. Built a Custom View for Application Control

Rather than re-applying the same filters every time, I saved a **Custom View** named "Application Control Logs for Last 1 Day" scoped to Application Control logs across all devices. This made it easy to repeatedly check which users were generating Dropbox, YouTube, Vimeo, and BitTorrent traffic.

![Custom View Results – Application Control](07-custom-view-appcontrol-results.png)

---

### 6. Configured an IPS Sensor for the Web Server

To protect the target web server, I built an IPS sensor named **WEBSERVER_Protection**, filtered to signatures targeting **Server**-side software, so FortiGate would only load signatures relevant to an exposed web server.

![IPS Sensor – WEBSERVER_Protection](08-ips-sensor-webserver-protection.png)

---

### 7. Verified the Target Web Server

Before attacking it, I confirmed the Apache2 web server was reachable through its public-facing Virtual IP.

![Apache2 Default Page – Target Server](09-apache-target-page.png)

---

### 8. Simulated a Web Attack with Nikto

From the external **LINUX-ISP** host, connected over SSH via PuTTY, I ran the Nikto web vulnerability scanner against the target's public IP to generate real attack traffic for FortiAnalyzer to detect.

```bash
nikto.pl -host 100.65.0.200
```

![Nikto Attack Output](10-nikto-attack-output.png)

---

### 9. Investigated the Attack in FortiView

With the attack running, I switched to **FortiView → Threats → Top Threats** to see detected threats ranked by score, then filtered for **Threat Level = High** to cut out the noise.

![FortiView – Top Threats Overview](11-fortiview-top-threats-overview.png)

Drilling into one of the high-severity entries (a `tcp_syn_flood` detection) showed the exact source IP responsible, along with the blocked/allowed counts and threat score — tracing the attack straight back to its origin.

![FortiView – Threat Source Drill-Down](12-fortiview-tcp-syn-flood-source.png)

I then checked **Threats & Events**, which plots detected threats on a live world map and lists the top threat destinations — a fast way to spot where attacks are landing.

![FortiView – Threat Map](13-fortiview-threat-map.png)

---

### 10. Analysed Traffic Patterns in FortiView

Switching to **FortiView → Traffic Analysis**, I reviewed overall bytes sent/received and the Top Country/Region breakdown, then drilled into a specific country to see which applications (DNS, HTTPS browsing, NTP, Dropbox) were generating that traffic.

![FortiView – Traffic Analysis by Country](14-fortiview-traffic-analysis-country.png)

---

### 11. Checked Log Rate and Storage via CLI

To confirm FortiAnalyzer itself was healthy under load, I used CLI diagnostics to break down the log insertion rate by log type (Traffic, Attack, Virus, Web Filter, Application Control, etc.):

```bash
diagnose fortilogd lograte
diagnose fortilogd lograte-device
diagnose fortilogd lograte-type
```

![CLI – Log Rate by Type](15-cli-fortilogd-lograte-type.png)

I also checked per-device disk usage and quota allocation to make sure storage wasn't close to its limit:

```bash
diagnose log device
```

![CLI – Log Device Storage Usage](17-cli-diagnose-log-device.png)

---

### 12. Reviewed the FortiAnalyzer Performance Dashboard

Finally, I checked the FortiAnalyzer **Dashboard** widgets for system utilization, insert rate vs. receive rate, and log insert lag time — confirming the platform was keeping up with the traffic generated during the lab.

![FortiAnalyzer Dashboard – Insert Rate & Lag Time](16-fortianalyzer-dashboard-insert-rate.png)

---

## Results

- Backfilled FortiAnalyzer with historical branch-office log files so analysis wasn't limited to live traffic only
- Used Log View filters and a saved Custom View to isolate P2P/BitTorrent and Dropbox activity tied to a specific policy
- Detected and traced a real Nikto-driven attack against the web server through FortiView's Top Threats, all the way down to the source IP and signature
- Confirmed FortiAnalyzer's log insert rate, lag time, and storage consumption stayed healthy throughout the test

---

## Key Learnings

- FortiAnalyzer can import historical/offline log files per device — useful for forensics or backfilling data for a device that wasn't always forwarding logs live
- Log View and FortiView serve different purposes: Log View is best for inspecting raw, detailed log records; FortiView is built for aggregated, threat- and traffic-centric pivoting
- Custom Views save a filtered query for one-click reuse instead of re-building filters every time
- An IPS sensor scoped to "Server" targets keeps signature matching focused on what's actually exposed, instead of loading every signature in the database
- CLI diagnostics (`diagnose fortilogd ...`) give a more real-time, granular view of FortiAnalyzer's own health than the GUI dashboard summarizes on its own
- Correlating a known attack (the Nikto run) with what shows up in FortiView's Top Threats is a quick way to confirm detection is actually working end-to-end, not just configured

---

*Part of my Fortinet security portfolio — [github.com/iVanny11-tech](https://github.com/iVanny11-tech)*
