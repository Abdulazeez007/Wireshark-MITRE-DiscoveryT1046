# Wireshark-MITRE-DiscoveryT1046
MITRE Discovery-T1046 Investigation Using Wireshark 

---
# 🛡️ Wireshark Lab: MITRE ATT&CK – T1046 Network Service Discovery

## 🎯 Objective

Understand how to identify and analyze network scanning behavior using Wireshark based on MITRE ATT&CK technique **T1046 – Network Service Discovery**.

---

## 🔍 Overview

**Network Service Discovery** is frequently used by adversaries to identify active systems, services, and open ports within a target network.

### 👥 Threat Actor Examples

| Threat Actor | Description |
|--------------|-------------|
| **Agrius** | Used **WinEggDrop**, an open-source port scanner, to scan victim networks. |
| **APT32 (G0050)** | Conducted scans for open ports, running services, OS fingerprinting, and vulnerabilities. |
| **APT39 (G0087)** | Used **CrackMapExec** and a custom port scanner called **BLUETORCH**. |
| **APT41 (G0096)** | Employed **WIDETONE**, a malware variant, for subnet port scans. |

Scanning helps adversaries discover what ports/services are available, which facilitates lateral movement and exploitation.

---

## 🧪 Lab Instructions

### 1. 📂 Open the PCAP File
- Launch Wireshark and open `Discovery-Scan.pcap`.
- Go to **Capture File Properties**.
  - **First Packet**: `2024-02-02 14:40:36 (UTC)`
  - **Last Packet**: `2024-02-02 14:40:43 (UTC)`
  - **Duration**: `6 seconds`

> ℹ️ **Note:** Set your Wireshark Time Display Format to **UTC** for consistency across all labs.

---

### 2. 📊 View Protocol Hierarchy
- Go to `Statistics > Protocol Hierarchy`
- Observe the presence of protocols such as:
  - **HTTP**
  - **ARP**
  - **DNS**

These may indicate scanning, name resolution, or basic communications.

---

### 3. 📡 Check IPv4 Conversations
- Navigate to `Statistics > Conversations > IPv4 tab`
- Sort by **Bytes** (descending)
- The top two IPs are **external** – not the main focus in the Discovery phase.
- Focus instead on **internal traffic**, particularly from:
  - **192.168.1.212 → 192.168.1.101–104**

---

### 4. 🔌 Examine TCP Ports
- Go to `Statistics > Conversations > TCP tab`
- Sort by **Port**
- IP `192.168.1.212` is scanning the following **20 ports**:

21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080

---

### 5. 📚 Review TCP Handshake (SYN → SYN/ACK → ACK)
- When scanning, attackers send **SYN** flags.
- Open ports respond with **SYN/ACK**.
- Closed ports typically respond with **RST/ACK**.

**Important:** 
- Open ports = Target sends **SYN/ACK** back to the scanning host.
- The **destination IP** in those responses will be `192.168.1.212`.

---

### 6. 🔎 Identify SYN/ACK Responses
- Locate:
  - **First SYN Packet**: `Packet #11 @ 14:40:36`
  - **First SYN/ACK Response**: `Packet #26`

---

### 7. 🧪 Build Display Filter for SYN/ACK
- Select the SYN/ACK packet (e.g., Packet #26)
- Expand the **Transmission Control Protocol** field
- Right-click **Flags (0x012 SYN, ACK)**:
  - `Prepare as Filter > Selected`

---

### 8. ➕ Add Destination IP to the Filter
- Expand the **Internet Protocol** section
- Right-click **Destination IP (192.168.1.212)**:
  - `Prepare as Filter > ...and Selected`

---

### 9. 🧹 Apply and Review Filtered Results
- Apply the combined filter.
- You should see **14 packets**, each representing an open port on the scanned hosts.
- Sort by **Source IP** to identify:
  - Which IPs responded
  - Which ports were open on each

---

## ✅ Summary

- This lab demonstrates **T1046 – Network Service Discovery** in action.
Port scanning is a critical initial step in the attack chain, enabling adversaries to enumerate internal assets.
- Wireshark allows defenders to analyze TCP behavior and detect early scanning activities.

Understanding the TCP handshake and visualizing traffic patterns is crucial for detecting adversarial reconnaissance in real-time.*

---
Here's the updated **Markdown lab guide**, now with a **Mitigation Steps** section added professionally at the end to respond to the findings from the Wireshark investigation of **MITRE ATT\&CK T1046 – Network Service Discovery**:

---

```markdown
# 🧾 Wireshark Lab: T1046 Network Discovery – Investigation Findings & Mitigation

## 🔍 Post-Investigation Results

Following the analysis of the packet capture file `Discovery-Scan.pcap`, activity consistent with **MITRE ATT&CK T1046 – Network Service Discovery** was identified. Below are the summarized findings:

---

### 1️⃣ What IP address is responsible for this discovery technique?

**Answer:**  
🖥️ `192.168.1.212`  
This internal host initiated multiple scans targeting other internal IPs.

---

### 2️⃣ What is the date and time of the first SYN event? (UTC)

**Answer:**  
🗓️ `2024-02-02 14:40:36 UTC`  
Indicates the beginning of the port scanning activity.

---

### 3️⃣ What is the packet number of the first SYN/ACK response?

**Answer:**  
📦 **Packet Number:** `26`  
This packet marks the first response from a host with an open port.

---

### 4️⃣ How many internal IPs were targeted by the scan?

**Answer:**  
🌐 **Targeted IPs:** `4`  
Targets:  
- `192.168.1.101`  
- `192.168.1.102`  
- `192.168.1.103`  
- `192.168.1.104`

---

### 5️⃣ How many unique ports were scanned?

**Answer:**  
🔢 **Distinct Ports:** `20`  
Ports scanned include:
`21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080`

---

### 6️⃣ Which IPs were found to have RDP (port 3389) open?

**Answer:**  
🔐 **RDP-Enabled Hosts:**
- `192.168.1.102`
- `192.168.1.104`

These hosts responded with **SYN/ACK** to scanning attempts on port **3389**.

---

> 🔒 **Note:** External IP addresses observed in the capture have been masked for confidentiality and were not related to the internal discovery technique.

---

## 🛡️ Mitigation and Response Steps

To reduce the risk of future reconnaissance or lateral movement within the environment, the following **mitigation steps** are recommended:

---

### 🔒 1. **Isolate the Scanning Host**
- Immediately quarantine or investigate `192.168.1.212` to confirm if the activity was authorized or malicious.
- Remove from the network if suspicious activity is confirmed.

---

### 🔍 2. **Review and Harden RDP Access**
- **Limit RDP exposure**: Restrict port 3389 to trusted administrative subnets.
- Implement **Network Level Authentication (NLA)** and **multi-factor authentication (MFA)** for remote access.

---

### 🧱 3. **Implement Network Segmentation**
- Isolate sensitive systems (e.g., servers with RDP, databases) from end-user networks.
- Use VLANs and firewalls to enforce access control.

---

### 📜 4. **Enable and Review Firewall Logs**
- Enable host-based and perimeter firewall logging to monitor and alert on port scans or unusual traffic.
- Create detection rules in your SIEM for excessive SYN packets or horizontal scanning behavior.

---

### 🧰 5. **Deploy Intrusion Detection/Prevention Systems (IDS/IPS)**
- Configure tools like **Snort**, **Suricata**, or **Zeek** to detect scanning behavior.
- Use MITRE ATT&CK mappings in your detection logic for **T1046** patterns.

---

### 🧼 6. **Limit Unused Ports**
- Disable services/ports that are not required on internal systems.
- Regularly audit systems for exposed services.

---

### 🔐 7. **Apply Least Privilege Access Controls**
- Ensure that internal machines do not have unnecessary permissions or exposure.
- Use role-based access control (RBAC) to limit access to sensitive systems.

---

### 📆 8. **Conduct Regular Network Discovery Drills**
- Simulate internal discovery behavior using red team tools in a controlled environment.
- Validate whether existing controls and alerting mechanisms work effectively.

---

> ✅ *Addressing internal reconnaissance early helps prevent attackers from advancing through the kill chain. Effective segmentation, monitoring, and least privilege are your best defense.*

---


## 📎 Notes

- Ensure the time zone is always set to **UTC** in Wireshark.
- Focus on **internal communications** when dealing with discovery tactics.
- This lab is foundational for identifying malicious reconnaissance activity.

---
