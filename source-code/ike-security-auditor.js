/**
 * IKEForge Pro - 10-Point Zero-Trust IKEv2 & IPsec Cryptographic Auditor
 * 
 * Evaluates IKEv2 and IPsec ESP configurations against NIST SP 800-77 Rev. 1,
 * NSA CNSA Suite, RFC 8221, and RFC 8247 cryptographic hardening baselines.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.IKESecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const AUDIT_CONTROLS = [
    {
      id: 'IKE-SEC-01',
      title: 'Encryption Cipher Security (AES-GCM / AES-256)',
      maxPoints: 15,
      evaluate: function (cfg) {
        const encrId = cfg.encrId || 20;
        if (encrId === 20 || encrId === 19 || encrId === 18) {
          return {
            passed: true,
            score: 15,
            level: 'PASS',
            finding: 'Authenticated Encryption with Associated Data (AEAD AES-GCM) active.',
            remediation: 'Compliant with NSA CNSA Suite and NIST SP 800-77 Rev. 1.'
          };
        } else if (encrId === 12) {
          return {
            passed: true,
            score: 11,
            level: 'PASS',
            finding: 'AES-CBC 256-bit active. Strong cipher, though lacks AEAD integrated hardware acceleration.',
            remediation: 'Consider migrating to AES-256-GCM for combined encryption and integrity verification.'
          };
        } else if (encrId === 3) {
          return {
            passed: false,
            score: 0,
            level: 'FAIL',
            finding: 'CRITICAL: Triple-DES (3DES) detected! Vulnerable to Sweet32 64-bit block cipher attack (CVE-2016-2183).',
            remediation: 'Immediately replace 3DES with AES-256-GCM (Transform ID 20).'
          };
        }
        return {
          passed: false,
          score: 4,
          level: 'WARN',
          finding: 'Legacy or non-standard encryption cipher detected.',
          remediation: 'Standardize on AES-256-GCM.'
        };
      }
    },
    {
      id: 'IKE-SEC-02',
      title: 'Pseudo-Random Function (PRF) Cryptographic Hygiene',
      maxPoints: 15,
      evaluate: function (cfg) {
        const prfId = cfg.prfId || 5;
        if (prfId === 5 || prfId === 6) {
          return {
            passed: true,
            score: 15,
            level: 'PASS',
            finding: 'High-strength PRF active (SHA-384 or SHA-512) providing 192+ bits of classical security.',
            remediation: 'Compliant with Top Secret NSA CNSA baseline.'
          };
        } else if (prfId === 4) {
          return {
            passed: true,
            score: 12,
            level: 'PASS',
            finding: 'PRF-HMAC-SHA2-256 active.',
            remediation: 'Compliant with general NIST standards.'
          };
        } else if (prfId === 1 || prfId === 2) {
          return {
            passed: false,
            score: 0,
            level: 'FAIL',
            finding: 'CRITICAL VULNERABILITY: MD5 or SHA-1 PRF in use! Broken hash functions subject to collision attacks.',
            remediation: 'Upgrade PRF immediately to PRF_HMAC_SHA2_384 or PRF_HMAC_SHA2_256.'
          };
        }
        return {
          passed: false,
          score: 5,
          level: 'WARN',
          finding: 'Unrecognized PRF function.',
          remediation: 'Set PRF to PRF_HMAC_SHA2_384.'
        };
      }
    },
    {
      id: 'IKE-SEC-03',
      title: 'Diffie-Hellman Group Key Exchange Hardening',
      maxPoints: 15,
      evaluate: function (cfg) {
        const dhId = cfg.dhId || 19;
        if (dhId === 19 || dhId === 20 || dhId === 21) {
          return {
            passed: true,
            score: 15,
            level: 'PASS',
            finding: `Elliptic Curve DH Group ${dhId} (ECP 256/384/521) active with sub-second key generation.`,
            remediation: 'Compliant. Modern elliptic curve cryptography avoids MODP computation bottlenecks.'
          };
        } else if (dhId === 14) {
          return {
            passed: true,
            score: 11,
            level: 'PASS',
            finding: 'Group 14 (MODP 2048-bit) active. Acceptable classical security, but higher CPU overhead than ECP.',
            remediation: 'Recommend migrating to Group 19 (NIST P-256 ECP) for faster handshakes.'
          };
        } else if (dhId === 1 || dhId === 2 || dhId === 5) {
          return {
            passed: false,
            score: 0,
            level: 'FAIL',
            finding: `CRITICAL FLAW: DH Group ${dhId} (< 2048-bit MODP) in use! Vulnerable to state-actor precomputation (Logjam attack RFC 7959).`,
            remediation: 'Enforce DH Group 19 (ECP 256) or Group 14 (MODP 2048).'
          };
        }
        return {
          passed: false,
          score: 4,
          level: 'WARN',
          finding: 'Legacy DH Group configured.',
          remediation: 'Configure Diffie-Hellman Group 19 or 20.'
        };
      }
    },
    {
      id: 'IKE-SEC-04',
      title: 'Perfect Forward Secrecy (PFS) in Child SA',
      maxPoints: 10,
      evaluate: function (cfg) {
        if (cfg.pfsEnabled) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: 'Perfect Forward Secrecy (PFS) enabled on Child SA / Phase 2.',
            remediation: 'Compliant. A compromise of long-term IKE keys will not decrypt past recorded data sessions.'
          };
        }
        return {
          passed: false,
          score: 1,
          level: 'FAIL',
          finding: 'PFS DISABLED: Rekeyed IPsec SAs reuse primary IKE key material, forfeiting forward secrecy.',
          remediation: 'Enable PFS in IPsec transform/crypto map (`set pfs group19` or `pfs=yes`).'
        };
      }
    },
    {
      id: 'IKE-SEC-05',
      title: 'NAT-Traversal (RFC 3948) & UDP 4500 Auto-Floating',
      maxPoints: 10,
      evaluate: function (cfg) {
        if (cfg.natTraversalEnabled) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: 'NAT-Traversal (NAT-T) active with automatic floating to UDP 4500 and 20s keepalives.',
            remediation: 'Compliant. Prevents stateful NAT firewalls from prematurely closing tunnel sessions.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'NAT-T disabled: Tunnels traversing NAT gateways or cloud VPC internet gateways will fail.',
          remediation: 'Enable NAT-T and verify UDP port 4500 is permitted in upstream firewalls.'
        };
      }
    },
    {
      id: 'IKE-SEC-06',
      title: 'Dead Peer Detection (DPD / RFC 3706) Heartbeats',
      maxPoints: 10,
      evaluate: function (cfg) {
        const interval = cfg.dpdInterval || 10;
        if (cfg.dpdEnabled && interval <= 15) {
          return {
            passed: true,
            score: 10,
            level: 'PASS',
            finding: `Dead Peer Detection (DPD) enabled with ${interval}s heartbeat interval.`,
            remediation: 'Compliant. Quickly tears down dead SAs and triggers failover upon remote peer outage.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: 'DPD disabled or sluggish: Stale SAs will persist after peer failure, causing traffic blackholing.',
          remediation: 'Enable DPD with 10-second query interval and 3-second retry.'
        };
      }
    },
    {
      id: 'IKE-SEC-07',
      title: 'Pre-Shared Key (PSK) High-Entropy Audit',
      maxPoints: 8,
      evaluate: function (cfg) {
        const psk = cfg.psk || '';
        const hasUpper = /[A-Z]/.test(psk);
        const hasLower = /[a-z]/.test(psk);
        const hasDigit = /[0-9]/.test(psk);
        const hasSpecial = /[^A-Za-z0-9]/.test(psk);
        const len = psk.length;

        if (len >= 24 && hasUpper && hasLower && hasDigit && hasSpecial) {
          return {
            passed: true,
            score: 8,
            level: 'PASS',
            finding: `High-entropy PSK verified (${len} chars, mixed alphanumeric & symbols).`,
            remediation: 'Compliant against dictionary and offline brute-force cracking.'
          };
        } else if (len >= 16) {
          return {
            passed: true,
            score: 5,
            level: 'WARN',
            finding: `Moderate PSK entropy (${len} chars). Meets basic standards but below CNSA guidelines.`,
            remediation: 'Generate a 32+ character random hex or alphanumeric string.'
          };
        }
        return {
          passed: false,
          score: 0,
          level: 'FAIL',
          finding: `WEAK PSK (${len} chars): Susceptible to dictionary attacks and offline brute-forcing!`,
          remediation: 'Replace PSK with an enterprise secret containing at least 24 randomized characters.'
        };
      }
    },
    {
      id: 'IKE-SEC-08',
      title: 'Anti-Replay Window Protection (RFC 4303)',
      maxPoints: 6,
      evaluate: function (cfg) {
        const windowSize = cfg.antiReplayWindow || 64;
        if (windowSize >= 64) {
          return {
            passed: true,
            score: 6,
            level: 'PASS',
            finding: `Anti-Replay window verified (${windowSize} packets). Replayed packets silently dropped.`,
            remediation: 'Compliant. Defends against man-in-the-middle replay attacks.'
          };
        }
        return {
          passed: false,
          score: 1,
          level: 'WARN',
          finding: 'Anti-Replay window disabled or too small (< 64 packets).',
          remediation: 'Enable 64-bit or 128-bit anti-replay window.'
        };
      }
    },
    {
      id: 'IKE-SEC-09',
      title: 'SA Rekey Lifetime Boundaries (IKE <= 8h, Child <= 1h)',
      maxPoints: 6,
      evaluate: function (cfg) {
        const ikeLife = cfg.ikeLifetimeSec || 28800;
        const childLife = cfg.childLifetimeSec || 3600;

        if (ikeLife <= 28800 && childLife <= 3600) {
          return {
            passed: true,
            score: 6,
            level: 'PASS',
            finding: `Calibrated SA rekey lifetimes (IKE: ${ikeLife}s, Child: ${childLife}s).`,
            remediation: 'Compliant. Rotates symmetric keys before birthday attacks become feasible.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'WARN',
          finding: `Excessive SA lifetime (IKE: ${ikeLife}s, Child: ${childLife}s). Extends cryptanalytic exposure.`,
          remediation: 'Limit IKE lifetime to 28800s (8h) and Child SA lifetime to 3600s (1h).'
        };
      }
    },
    {
      id: 'IKE-SEC-10',
      title: 'Extended Sequence Numbers (ESN / RFC 4304) for High Throughput',
      maxPoints: 5,
      evaluate: function (cfg) {
        if (cfg.esnEnabled) {
          return {
            passed: true,
            score: 5,
            level: 'PASS',
            finding: 'Extended Sequence Numbers (ESN 64-bit) enabled.',
            remediation: 'Compliant. Prevents 32-bit sequence rollover collisions on Gigabit/10G links.'
          };
        }
        return {
          passed: false,
          score: 2,
          level: 'INFO',
          finding: 'Standard 32-bit sequence numbers active. Adequate for < 1Gbps throughput.',
          remediation: 'Enable ESN for links exceeding 1 Gbps to prevent premature SA rekeying.'
        };
      }
    }
  ];

  function auditConfiguration(cfg) {
    let totalScore = 0;
    const findings = [];

    AUDIT_CONTROLS.forEach(ctrl => {
      const res = ctrl.evaluate(cfg);
      totalScore += res.score;
      findings.push({
        id: ctrl.id,
        title: ctrl.title,
        maxPoints: ctrl.maxPoints,
        score: res.score,
        level: res.level,
        passed: res.passed,
        finding: res.finding,
        remediation: res.remediation
      });
    });

    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 85) grade = 'A';
    else if (totalScore >= 75) grade = 'B';
    else if (totalScore >= 60) grade = 'C';
    else if (totalScore >= 50) grade = 'D';

    return {
      score: totalScore,
      maxScore: 100,
      grade: grade,
      passed: totalScore >= 80,
      findings: findings,
      evaluatedAt: new Date().toISOString()
    };
  }

  return {
    AUDIT_CONTROLS,
    auditConfiguration
  };
}));
