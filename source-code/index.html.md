

IKEv2

# **IKEForge Pro**

IETF RFC 7296 (IKEv2) & RFC 4301/4303 IPsec ESP Cryptographic Protocol Studio  
RFC 7296 IKEv2 NSA CNSA SUITE RFC 3948 NAT-T (4500) RFC 4303 IPsec ESP  
Enterprise CNSA AES-256-GCM (Grade A+) AWS Cloud Transit VPN (Grade A+) Legacy Vulnerable 3DES-MD5-DH2 (Grade F)

RFC 7296 IKEv2 Header & Transform Parameters PDU: 272B

Exchange Type IKE\_SA\_INIT (34) IKE\_AUTH (35) CREATE\_CHILD\_SA (36) INFORMATIONAL (37)  
Initiator SPI (Hex)  
Encryption Cipher (ENCR) ENCR\_AES\_GCM\_256 (AEAD) ENCR\_AES\_GCM\_128 (AEAD) ENCR\_AES\_CBC\_256 ENCR\_3DES (Insecure)  
Pseudo-Random Function (PRF) PRF\_HMAC\_SHA2\_384 PRF\_HMAC\_SHA2\_256 PRF\_HMAC\_SHA2\_512 PRF\_HMAC\_MD5 (Insecure)  
Diffie-Hellman Group (D-H) Group 19 (ECP 256 / NIST P-256) Group 20 (ECP 384 / NIST P-384) Group 14 (MODP 2048\) Group 2 (MODP 1024 \- Insecure)  
NAT-Traversal (RFC 3948\) Enabled (Floats to UDP 4500\) Disabled (Native UDP 500\)  
Pre-Shared Key (PSK Secret)

Peer Negotiation & Root-Cause Analyzer ESTABLISHED

IKE\_SA\_INIT & IKE\_AUTH NEGOTIATION SUCCEEDED  
Proposals fully aligned. SAs established with AES-256-GCM and Group 19 ECDH.

Initiator (Local)

ENCR: **AES-GCM-256**  
PRF: **SHA-384**  
D-H: **Group 19 (ECP 256\)**  
NAT-T: **UDP 4500**  
Responder (Remote)

ENCR: **AES-GCM-256**  
PRF: **SHA-384**  
D-H: **Group 19 (ECP 256\)**  
NAT-T: **UDP 4500**

Inject Negotiation Error to Test Defense No Error (Clean Negotiation) Simulate ENCR Mismatch \-\> NO\_PROPOSAL\_CHOSEN (14) Simulate DH Group Mismatch \-\> INVALID\_KE\_PAYLOAD (17) Simulate PSK Mismatch \-\> AUTHENTICATION\_FAILED (24) Simulate Subnet Narrowing \-\> TS\_UNACCEPTABLE (38)

10-Point Zero-Trust IKEv2 / IPsec Cryptographic Scorecard PASSING

A+

**100 / 100 Points NSA CNSA & NIST Compliant**  
All 10 cryptographic cipher, PRF, DH group, and forward secrecy controls satisfied.

RFC 7296 IKEv2 28-Octet Header & Payload Hex Dissector  
Copy Hex Download PCAP  
0000 a1 b2 c3 d4 e5 f6 07 18 00 00 00 00 00 00 00 00 |................|

Multi-Platform Production Synthesizer Copy Config  
Cisco IOS-XE Fortinet FortiOS Palo Alto PAN-OS Linux strongSwan AWS Terraform  
\! Generating configuration...