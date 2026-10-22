# IKEForge Pro \- Architecture & Technical Specification

> **IETF RFC 7296 (Internet Key Exchange Protocol Version 2 \- IKEv2), RFC 4301/4303 (IPsec ESP Architecture), RFC 3948 (NAT-Traversal), and NIST SP 800-77 / NSA CNSA Cryptographic Baselines**

---

## 1\. Executive Summary & Protocol Overview

The **Internet Key Exchange Protocol Version 2 (IKEv2 / IETF RFC 7296\)** is the gold-standard protocol for mutual authentication, cryptographic key negotiation, and dynamic Security Association (SA) management across enterprise site-to-site IPsec Virtual Private Networks (VPNs).

IKEv2 operates alongside the **IPsec Encapsulating Security Payload (ESP / RFC 4303\)** to provide confidentiality, integrity, data origin authentication, and anti-replay protection across untrusted underlay networks.

\+-----------------------------------------------------------------------------------------+

|                               IKEv2 ARCHITECTURAL SUMMARY                               |

\+--------------------------+---------------------------------------+----------------------+

| Layer / Domain           | Standard / Mechanism                  | Operational Purpose  |

\+--------------------------+---------------------------------------+----------------------+

| Control Plane (Phase 1\)  | IETF RFC 7296 (IKEv2)                 | Mutual authentication|

|                          | UDP Port 500 / UDP Port 4500 (NAT-T)  | and IKE SA keys.     |

\+--------------------------+---------------------------------------+----------------------+

| Data Plane (Phase 2\)     | RFC 4301 / RFC 4303 (IPsec ESP)       | Line-rate encrypted  |

|                          | IP Protocol 50 (or UDP 4500 en-route) | payload transit.     |

\+--------------------------+---------------------------------------+----------------------+

| Key Exchange (D-H)       | RFC 5903 / RFC 8247 (ECP 256/384)     | Ephemeral Diffie-    |

|                          | Curve P-256 (Group 19\) / Group 20     | Hellman derivation.  |

\+--------------------------+---------------------------------------+----------------------+

| Modern AEAD Encryption   | RFC 4106 (AES-GCM-256)                | Combined encryption  |

|                          | NSA CNSA & NIST SP 800-77 Baseline    | and authentication.  |

\+--------------------------+---------------------------------------+----------------------+

| Resiliency & Liveness    | RFC 3706 DPD (Dead Peer Detection)    | Sub-10s failure      |

|                          | RFC 3948 NAT-T Floating               | detection and NAT.   |

\+--------------------------+---------------------------------------+----------------------+

---

## 2\. IETF RFC 7296 IKEv2 Packet Anatomy & Fixed Header

Every IKEv2 message begins with a mandatory **28-octet fixed header**, followed by chained variable-length payloads:

 0                   1                   2                   3

 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                       Initiator's SPI                         |

|                                                               |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                       Responder's SPI                         |

|                                                               |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|  Next Payload | MjrVer| MnrVer| Exchange Type |     Flags     |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                          Message ID                           |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                            Length                             |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

| Payloads (SA, KE, Nonce, ID, AUTH, TS, Notify) ...

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

### 2.1 Fixed Header Fields

- **Initiator SPI (64 bits)**: A unique 8-octet value chosen by the Initiator to identify the IKE SA.  
- **Responder SPI (64 bits)**: A unique 8-octet value chosen by the Responder (all zeros in the initial `IKE_SA_INIT` request).  
- **Next Payload (8 bits)**: Indicates the payload type immediately following the header (e.g., `33` for Security Association).  
- **Version (8 bits)**: `0x20` for IKEv2 (Major Version 2, Minor Version 0).  
- **Exchange Type (8 bits)**:  
  - `34` (`IKE_SA_INIT`): Initial cryptographic negotiation and key exchange.  
  - `35` (`IKE_AUTH`): Identity exchange and mutual authentication.  
  - `36` (`CREATE_CHILD_SA`): Creation of additional IPsec SAs or rekeying.  
  - `37` (`INFORMATIONAL`): DPD heartbeats, error notifications, and deletions.  
- **Flags (8 bits)**:  
  - Bit 3 (`0x08`): Initiator (set when sent by the entity that initiated the IKE SA).  
  - Bit 5 (`0x20`): Response (set when sent in reply to a request).  
- **Message ID (32 bits)**: Sequence number used to match requests with responses and ensure reliable delivery.  
- **Length (32 bits)**: Total length in octets of the IKE header plus all chained payloads.

---

## 3\. The IKEv2 Two-Exchange Handshake Lifecycle

Initiator                                   Responder

\-----------------------------------------------------------------

1\. IKE\_SA\_INIT Request:

   HDR, SAi1, KEi, Ni, \[N(NAT\_DETECTION\_SOURCE\_IP), N(NAT\_DETECTION\_DESTINATION\_IP)\]

   \----------------------------------------\>

                                            2\. IKE\_SA\_INIT Response:

                                               HDR, SAr1, KEr, Nr, \[CERTREQ\],

                                               \[N(NAT\_DETECTION\_SOURCE\_IP), N(NAT\_DETECTION\_DESTINATION\_IP)\]

   \<----------------------------------------

\[Derives SKEYSEED, SK\_d, SK\_ai, SK\_ar, SK\_ei, SK\_er, SK\_pi, SK\_pr\]

3\. IKE\_AUTH Request:

   HDR, SK {IDi, \[CERT,\] \[CERTREQ,\] \[IDr,\] AUTH, SAi2, TSi, TSr}

   \----------------------------------------\>

                                            4\. IKE\_AUTH Response:

                                               HDR, SK {IDr, \[CERT,\] AUTH, SAr2, TSi, TSr}

   \<----------------------------------------

\[Secure Child SA Active \- IPsec ESP Traffic Flows\]

---

## 4\. NAT-Traversal (RFC 3948\) & Floating to UDP Port 4500

### 4.1 The NAT Problem with ESP

Standard IPsec ESP is encapsulated directly in IP Protocol 50\. Because Layer 4 Port Address Translation (PAT) firewalls require TCP/UDP port headers to track multiplexed sessions, **raw ESP packets cannot traverse NAT**.

### 4.2 How IKEv2 Solves It

1. In `IKE_SA_INIT`, both peers exchange `NAT_DETECTION_SOURCE_IP` and `NAT_DETECTION_DESTINATION_IP` notifications containing: \$\$\\text{Hash} \= \\text{SHA1}(\\text{SPI}\_i \\parallel \\text{SPI}\_r \\parallel \\text{IP} \\parallel \\text{Port})\$\$  
2. If either hash does not match the received IP and port, **NAT presence is confirmed**.  
3. Beginning with `IKE_AUTH`, all subsequent IKEv2 and ESP traffic dynamically **floats from UDP Port 500 to UDP Port 4500**.  
4. **The Non-ESP Marker**: To distinguish between IKEv2 packets and ESP packets arriving on UDP port 4500:  
   - IKEv2 packets prepend a 4-octet **Non-ESP Marker (`0x00000000`)** before the 28-octet IKE header.  
   - ESP packets place the 32-bit Security Parameter Index (SPI) in the first 4 octets (which can never be `0x00000000`).

---

## 5\. Root-Cause Analysis of Negotiation Mismatches

| Notify Error Code | RFC 7296 Value | Root Cause |
| :---- | :---: | :---- |
| **`NO_PROPOSAL_CHOSEN`** | `14` | Encryption cipher (ENCR), PRF, or integrity algorithm mismatch between Initiator and Responder proposals. |
| **`INVALID_KE_PAYLOAD`** | `17` | Diffie-Hellman Group mismatch. Responder sends this notify specifying its required DH Group. |
| **`AUTHENTICATION_FAILED`** | `24` | Pre-Shared Key (PSK) secret mismatch, certificate authority mismatch, or corrupt identity signature. |
| **`TS_UNACCEPTABLE`** | `38` | Traffic Selector narrowing mismatch (e.g., Initiator proposes `0.0.0.0/0` for route-based VPN, but Responder requires exact policy subnet matching). |

---

## 6\. 10-Point Zero-Trust IKEv2 & IPsec Cryptographic Audit

| Control ID | Evaluation Domain | Weight | Standards Baseline |
| :---- | :---- | :---: | :---- |
| **IKE-SEC-01** | Encryption Cipher Security | 15 pts | Enforces AES-256-GCM (AEAD). Deprecates 3DES (CVE-2016-2183 Sweet32). |
| **IKE-SEC-02** | PRF Cryptographic Hygiene | 15 pts | Enforces SHA-384 / SHA-512. Strictly bans broken MD5 / SHA-1. |
| **IKE-SEC-03** | Diffie-Hellman Group Hardening | 15 pts | Requires Group 19 (ECP 256\) or Group 14\. Bans Group 2 (1024-bit Logjam). |
| **IKE-SEC-04** | Perfect Forward Secrecy (PFS) | 10 pts | Mandates fresh DH exchange for Child SA rekeying. |
| **IKE-SEC-05** | NAT-Traversal (RFC 3948\) Auto-Floating | 10 pts | Verifies UDP 4500 floating and 20s keepalives for cloud/NAT traversal. |
| **IKE-SEC-06** | Dead Peer Detection (DPD / RFC 3706\) | 10 pts | Sub-10s failure detection prevents dead SA traffic blackholes. |
| **IKE-SEC-07** | Pre-Shared Key (PSK) High-Entropy | 8 pts | \$\\ge 24\$ alphanumeric and symbolic characters to prevent brute-force cracking. |
| **IKE-SEC-08** | Anti-Replay Window Protection | 6 pts | Minimum 64-packet window drops intercepted replay attacks. |
| **IKE-SEC-09** | SA Rekey Lifetime Calibration | 6 pts | IKE \$\\le 28800\$s (8h), Child SA \$\\le 3600\$s (1h) limits cryptanalytic exposure. |
| **IKE-SEC-10** | Extended Sequence Numbers (ESN) | 5 pts | 64-bit sequence numbers eliminate rollover collisions on 10G+ links. |

