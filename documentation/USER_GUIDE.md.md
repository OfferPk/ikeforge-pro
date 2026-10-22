# IKEForge Pro \- User Guide & Operations Manual

> **Step-by-step operational manual for network security engineers, cloud infrastructure architects, and DevSecOps teams deploying Zero-Trust IKEv2 and IPsec site-to-site VPNs.**

---

## 1\. Quickstart: Web Application Studio

The **IKEForge Pro Web Studio** is completely self-contained, requiring zero external runtime dependencies. Open `source-code/index.html` directly in any web browser:

\# Optional local web server

cd product\_125/source-code

python3 \-m http.server 8080

\# Open http\://localhost:8080 in your browser

### Studio Interface Overview:

1. **Industry Presets**:  
   - **Enterprise CNSA AES-256-GCM (Grade A+)**: High-security baseline adhering to NSA Commercial National Security Algorithm Suite (AES-256-GCM, SHA-384, DH Group 19).  
   - **AWS Cloud Transit VPN (Grade A+)**: Calibrated for AWS Site-to-Site VPN connections terminating on AWS Transit Gateways or Virtual Private Gateways.  
   - **Legacy Vulnerable 3DES-MD5-DH2 (Grade F)**: Demonstrates critical vulnerabilities including Sweet32 (3DES), MD5 collision weaknesses, and Logjam-vulnerable 1024-bit Diffie-Hellman groups.  
2. **RFC 7296 IKEv2 Parameters**: Adjust Exchange Types, Initiator/Responder SPIs, Encryption Ciphers, PRFs, Diffie-Hellman Groups, and Pre-Shared Keys.  
3. **Peer Negotiation & Root-Cause Analyzer**: Side-by-side comparison of Initiator and Responder proposals with active error injection to test defense against `NO_PROPOSAL_CHOSEN`, `INVALID_KE_PAYLOAD`, `AUTHENTICATION_FAILED`, and `TS_UNACCEPTABLE`.  
4. **10-Point Zero-Trust Cryptographic Scorecard**: Real-time evaluation against NIST SP 800-77 Rev. 1 and NSA CNSA standards (0–100%, Grades A+ to F).  
5. **Wireshark Hex Dissector**: Monospace byte-aligned hex dump with 1-click clipboard export and binary `.pcap` capture file generation.  
6. **Multi-Platform Synthesizer**: Instant production configuration generation for Cisco IOS-XE, Fortinet FortiOS, Palo Alto PAN-OS, Linux strongSwan, and AWS Terraform HCL.

---

## 2\. DevSecOps Python CLI Tool Operations

The standalone Python CLI tool (`build/ikeforge-cli.py`) operates in Linux, macOS, and Windows environments without installing external packages:

### 2.1 Packet Dissection & Wireshark Hex Dump

./build/ikeforge-cli.py \--dissect

### 2.2 Testing Proposal Negotiation & Handshake Matching

./build/ikeforge-cli.py \--preset build/presets/enterprise-cnsa-aes-gcm.json \--negotiate

### 2.3 Running 10-Point Zero-Trust Cryptographic Audits

\# Audit Enterprise CNSA preset

./build/ikeforge-cli.py \--preset build/presets/enterprise-cnsa-aes-gcm.json \--audit

\# Audit vulnerable legacy deployment

./build/ikeforge-cli.py \--preset build/presets/legacy-vulnerable-3des-md5.json \--audit

### 2.4 Generating Binary PCAP Capture Files

Generate standard `.pcap` files for testing network decoders or validating with Wireshark:

./build/ikeforge-cli.py \--preset build/presets/enterprise-cnsa-aes-gcm.json \--pcap enterprise-ikev2.pcap

\# Inspect with tcpdump or Wireshark

tcpdump \-n \-r enterprise-ikev2.pcap

### 2.5 Automated CI/CD Pipeline Gating (`--strict`)

Integrate IKEForge Pro into CI/CD pipelines to validate infrastructure-as-code repository commits:

\- name: Audit IKEv2 / IPsec Cryptographic Hardening

  run: |

    python3 build/ikeforge-cli.py \\

      \--preset build/presets/production-vpn.json \\

      \--strict

*Exit Code 0: Audit Score \$\\ge 80\$ (Grade A/A+) and zero critical cryptographic vulnerabilities. Pipeline proceeds.* *Exit Code 1: Audit Score \$\< 80\$ (Grade B/C/F) or 3DES/MD5/DH2 detected. Pipeline halts.*

---

## 3\. Production Configuration Examples

### 3.1 Cisco IOS-XE Route-Based VTI (Phase 3 DMVPN / P2P)

crypto ikev2 proposal IKEV2-PROP-CNSA

 encryption aes-gcm-256

 prf sha384

 group 19

\!

crypto ikev2 profile IKEV2-PROFILE

 match address local 198.51.100.10

 match identity remote address 203.0.113.1 255.255.255.255

 identity local address 198.51.100.10

 authentication remote pre-share

 authentication local pre-share

 keyring local IKEV2-KEYRING

 dpd 10 3 periodic

 lifetime 28800

\!

crypto ipsec transform-set TS-AES-GCM esp-gcm 256

 mode transport

\!

crypto ipsec profile IPSEC-PROFILE-VTI

 set transform-set TS-AES-GCM

 set ikev2-profile IKEV2-PROFILE

 set pfs group19

 set security-association lifetime seconds 3600

\!

interface Tunnel100

 description SITE-TO-SITE-IKEV2-IPSEC-VTI

 ip address 10.254.10.1 255.255.255.252

 ip mtu 1400

 ip tcp adjust-mss 1360

 tunnel source GigabitEthernet0/0/0

 tunnel mode ipsec ipv4

 tunnel destination 203.0.113.1

 tunnel protection ipsec profile IPSEC-PROFILE-VTI

---

## 4\. Troubleshooting High-Impact IKEv2 Failures

1. **`NO_PROPOSAL_CHOSEN (14)`**:  
   - *Cause*: Encryption (ENCR), PRF, or integrity algorithm mismatch between Initiator and Responder proposals.  
   - *Resolution*: Ensure both peers offer matching ciphers (e.g., both configure `aes-gcm-256` and `prf sha384`).  
2. **`INVALID_KE_PAYLOAD (17)`**:  
   - *Cause*: Initiator generated Diffie-Hellman public key using a DH group the Responder rejects.  
   - *Resolution*: The Responder sends this notify indicating its required DH Group. Realign Phase 1 DH groups (e.g., standardize on Group 19 / ECP 256).  
3. **`AUTHENTICATION_FAILED (24)`**:  
   - *Cause*: Pre-shared key secret mismatch or identity mismatch (`IDi` / `IDr`).  
   - *Resolution*: Re-enter the exact PSK secret on both endpoints and verify local/remote identity types.  
4. **`TS_UNACCEPTABLE (38)`**:  
   - *Cause*: Traffic Selector mismatch. Route-based VPNs propose `0.0.0.0/0`, but policy-based firewalls require exact subnets.  
   - *Resolution*: Enable route-based traffic selector narrowing on the policy firewall or configure exact subnets in Phase 2\.