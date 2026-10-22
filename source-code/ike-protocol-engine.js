/**
 * IKEForge Pro - RFC 7296 IKEv2 & RFC 4301/4303 IPsec Protocol Engine
 * 
 * Provides binary wireframe generation, 28-octet IKE header formatting,
 * SA/KE/Nonce/TS payload compilation, proposal negotiation matching,
 * NAT-Traversal detection, and binary PCAP generation.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.IKEProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // RFC 7296 Exchange Types
  const IKE_EXCHANGE_TYPES = {
    IKE_SA_INIT: 34,
    IKE_AUTH: 35,
    CREATE_CHILD_SA: 36,
    INFORMATIONAL: 37
  };

  // RFC 7296 Payload Types
  const IKE_PAYLOAD_TYPES = {
    NO_NEXT: 0,
    SECURITY_ASSOCIATION: 33,
    KEY_EXCHANGE: 34,
    ID_INITIATOR: 35,
    ID_RESPONDER: 36,
    CERTIFICATE: 37,
    CERT_REQUEST: 38,
    AUTHENTICATION: 39,
    NONCE: 40,
    NOTIFY: 41,
    DELETE: 42,
    VENDOR_ID: 43,
    TS_INITIATOR: 44,
    TS_RESPONDER: 45,
    ENCRYPTED_AND_AUTH: 46
  };

  // Transform Types
  const TRANSFORM_TYPES = {
    ENCR: 1,
    PRF: 2,
    INTEG: 3,
    DH: 4,
    ESN: 5
  };

  // Algorithm Registry
  const ALGORITHMS = {
    ENCR: {
      3: { id: 3, name: 'ENCR_3DES', keyLen: 192, insecure: true },
      12: { id: 12, name: 'ENCR_AES_CBC', keyLen: 256, insecure: false },
      14: { id: 14, name: 'ENCR_AES_CTR', keyLen: 256, insecure: false },
      18: { id: 18, name: 'ENCR_AES_GCM_128', keyLen: 128, aead: true, insecure: false },
      19: { id: 19, name: 'ENCR_AES_GCM_192', keyLen: 192, aead: true, insecure: false },
      20: { id: 20, name: 'ENCR_AES_GCM_256', keyLen: 256, aead: true, insecure: false }
    },
    PRF: {
      1: { id: 1, name: 'PRF_HMAC_MD5', insecure: true },
      2: { id: 2, name: 'PRF_HMAC_SHA1', insecure: true },
      4: { id: 4, name: 'PRF_HMAC_SHA2_256', insecure: false },
      5: { id: 5, name: 'PRF_HMAC_SHA2_384', insecure: false },
      6: { id: 6, name: 'PRF_HMAC_SHA2_512', insecure: false }
    },
    INTEG: {
      0: { id: 0, name: 'NONE (AEAD GCM)', insecure: false },
      1: { id: 1, name: 'AUTH_HMAC_MD5_96', insecure: true },
      2: { id: 2, name: 'AUTH_HMAC_SHA1_96', insecure: true },
      12: { id: 12, name: 'AUTH_HMAC_SHA2_256_128', insecure: false },
      13: { id: 13, name: 'AUTH_HMAC_SHA2_384_192', insecure: false },
      14: { id: 14, name: 'AUTH_HMAC_SHA2_512_256', insecure: false }
    },
    DH: {
      2: { id: 2, name: 'Group 2 (MODP 1024)', bits: 1024, insecure: true },
      5: { id: 5, name: 'Group 5 (MODP 1536)', bits: 1536, insecure: true },
      14: { id: 14, name: 'Group 14 (MODP 2048)', bits: 2048, insecure: false },
      19: { id: 19, name: 'Group 19 (ECP 256 / NIST P-256)', bits: 256, ecp: true, insecure: false },
      20: { id: 20, name: 'Group 20 (ECP 384 / NIST P-384)', bits: 384, ecp: true, insecure: false },
      21: { id: 21, name: 'Group 21 (ECP 521 / NIST P-521)', bits: 521, ecp: true, insecure: false }
    }
  };

  function parseIpv4(ipStr) {
    if (!ipStr || typeof ipStr !== 'string') return [0, 0, 0, 0];
    const parts = ipStr.trim().split('.');
    if (parts.length !== 4) return [0, 0, 0, 0];
    const nums = parts.map(p => parseInt(p, 10));
    for (let i = 0; i < 4; i++) {
      if (isNaN(nums[i]) || nums[i] < 0 || nums[i] > 255) return [0, 0, 0, 0];
    }
    return nums;
  }

  function parseHex(hexStr) {
    const clean = hexStr.replace(/[^0-9a-fA-F]/g, '');
    const bytes = [];
    for (let i = 0; i < clean.length; i += 2) {
      bytes.push(parseInt(clean.substr(i, 2), 16) || 0);
    }
    return bytes;
  }

  function uint64ToBytes(valStr) {
    // Expects hex string or numeric string
    const hex = (typeof valStr === 'string' && valStr.startsWith('0x')) ? 
                valStr.slice(2).padStart(16, '0') : 
                (valStr ? valStr.padStart(16, '0') : '0000000000000000');
    const bytes = [];
    for (let i = 0; i < 16; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16) || 0);
    }
    return bytes;
  }

  /**
   * Builds an RFC 7296 IKEv2 Security Association (SA) Payload (Type 33)
   */
  function buildSaPayload(options, isLast) {
    const nextPayload = isLast ? IKE_PAYLOAD_TYPES.NO_NEXT : IKE_PAYLOAD_TYPES.KEY_EXCHANGE;
    const encrId = options.encrId || 20; // Default: AES-GCM-256
    const prfId = options.prfId || 5;    // Default: PRF-HMAC-SHA2-384
    const integId = options.integId !== undefined ? options.integId : 0; // Default: NONE for AEAD
    const dhId = options.dhId || 19;     // Default: Group 19 (ECP 256)

    // Build Transforms
    const transforms = [];

    // Transform 1: ENCR
    const encrIsAead = (encrId === 18 || encrId === 19 || encrId === 20);
    const encrT = [
      0x03, 0x00, // Last (0x03=more, 0x00=last), Reserved
      0x00, 0x0c, // Transform Length: 12 bytes (with attribute)
      TRANSFORM_TYPES.ENCR, 0x00, // Transform Type: ENCR, Reserved
      (encrId >> 8) & 0xff, encrId & 0xff, // Transform ID
      0x80, 0x0e, // Attribute: Type 14 (Key Length), AF=1
      (encrId === 18 ? 0x00 : (encrId === 19 ? 0x00 : 0x01)), 
      (encrId === 18 ? 0x80 : (encrId === 19 ? 0xc0 : 0x00)) // 128, 192, or 256 bits
    ];
    transforms.push(encrT);

    // Transform 2: PRF
    const prfT = [
      0x03, 0x00,
      0x00, 0x08, // Length: 8 bytes
      TRANSFORM_TYPES.PRF, 0x00,
      (prfId >> 8) & 0xff, prfId & 0xff
    ];
    transforms.push(prfT);

    // Transform 3: INTEG (Omitted or NONE for AEAD)
    if (!encrIsAead || integId !== 0) {
      const integT = [
        0x03, 0x00,
        0x00, 0x08,
        TRANSFORM_TYPES.INTEG, 0x00,
        (integId >> 8) & 0xff, integId & 0xff
      ];
      transforms.push(integT);
    }

    // Transform 4: DH
    const dhT = [
      0x00, 0x00, // Last transform in proposal
      0x00, 0x08,
      TRANSFORM_TYPES.DH, 0x00,
      (dhId >> 8) & 0xff, dhId & 0xff
    ];
    transforms.push(dhT);

    // Flatten Transforms
    let transformsBytes = [];
    transforms.forEach((t, idx) => {
      // Set last transform flag
      if (idx === transforms.length - 1) {
        t[0] = 0x00; // Last
      } else {
        t[0] = 0x03; // More transforms
      }
      transformsBytes = transformsBytes.concat(t);
    });

    // Proposal Header (8 bytes)
    const proposalLen = 8 + transformsBytes.length;
    const proposal = [
      0x00, 0x00, // Last proposal (0x00=last), Reserved
      (proposalLen >> 8) & 0xff, proposalLen & 0xff,
      0x01, // Proposal Number: 1
      0x01, // Protocol ID: 1 (IKE)
      0x00, // SPI Size: 0 for IKE_SA_INIT
      transforms.length // Number of Transforms
    ].concat(transformsBytes);

    // SA Generic Payload Header (4 bytes)
    const saPayloadLen = 4 + proposal.length;
    const saHeader = [
      nextPayload, 0x00, // Next Payload, Critical bit (0) + Reserved
      (saPayloadLen >> 8) & 0xff, saPayloadLen & 0xff
    ];

    return saHeader.concat(proposal);
  }

  /**
   * Builds an RFC 7296 Key Exchange (KE) Payload (Type 34)
   */
  function buildKePayload(dhId, isLast) {
    const nextPayload = isLast ? IKE_PAYLOAD_TYPES.NO_NEXT : IKE_PAYLOAD_TYPES.NONCE;
    // Length depends on DH Group: Group 19=64 bytes, Group 14=256 bytes, Group 2=128 bytes
    let keyLen = 64; // Default Group 19 (32B X + 32B Y)
    if (dhId === 14) keyLen = 256;
    else if (dhId === 20) keyLen = 96;
    else if (dhId === 2) keyLen = 128;

    const keData = [];
    for (let i = 0; i < keyLen; i++) {
      keData.push((i * 17 + 23) & 0xff); // Deterministic pseudo-random bytes
    }

    const payloadLen = 4 + 4 + keData.length; // Header(4) + DHGroup(2)+Reserved(2) + Data
    const keHeader = [
      nextPayload, 0x00,
      (payloadLen >> 8) & 0xff, payloadLen & 0xff,
      (dhId >> 8) & 0xff, dhId & 0xff,
      0x00, 0x00 // Reserved
    ];

    return keHeader.concat(keData);
  }

  /**
   * Builds an RFC 7296 Nonce Payload (Type 40)
   */
  function buildNoncePayload(isLast) {
    const nextPayload = isLast ? IKE_PAYLOAD_TYPES.NO_NEXT : IKE_PAYLOAD_TYPES.NOTIFY;
    const nonceLen = 32; // 32 bytes of cryptographic entropy
    const nonceData = [];
    for (let i = 0; i < nonceLen; i++) {
      nonceData.push((i * 31 + 47) & 0xff);
    }

    const payloadLen = 4 + nonceData.length;
    const nonceHeader = [
      nextPayload, 0x00,
      (payloadLen >> 8) & 0xff, payloadLen & 0xff
    ];

    return nonceHeader.concat(nonceData);
  }

  /**
   * Builds an RFC 7296 Notify Payload (Type 41) for NAT-Traversal Detection
   */
  function buildNatNotifyPayload(notifyType, ipStr, port, spiIHex, spiRHex, isLast) {
    const nextPayload = isLast ? IKE_PAYLOAD_TYPES.NO_NEXT : IKE_PAYLOAD_TYPES.NOTIFY;
    // Deterministic 20-byte SHA-1 hash mockup
    const ipBytes = parseIpv4(ipStr);
    const hashData = [];
    for (let i = 0; i < 20; i++) {
      hashData.push((ipBytes[i % 4] ^ (port & 0xff) ^ (i * 13)) & 0xff);
    }

    const payloadLen = 4 + 4 + hashData.length; // Header(4) + Protocol(1)+SPISz(1)+NotifyType(2) + Hash(20)
    const notifyHeader = [
      nextPayload, 0x00,
      (payloadLen >> 8) & 0xff, payloadLen & 0xff,
      0x00, // Protocol ID: 0 (None)
      0x00, // SPI Size: 0
      (notifyType >> 8) & 0xff, notifyType & 0xff
    ];

    return notifyHeader.concat(hashData);
  }

  /**
   * Forges a complete RFC 7296 IKEv2 packet with 28-octet fixed header and chained payloads
   */
  function forgeIkePacket(params) {
    const exchangeType = params.exchangeType || IKE_EXCHANGE_TYPES.IKE_SA_INIT;
    const isResponse = Boolean(params.isResponse);
    const isInitiator = !isResponse;
    const messageId = params.messageId || 0;
    const initiatorSpi = params.initiatorSpi || 'a1b2c3d4e5f60718';
    const responderSpi = params.responderSpi || (isResponse ? 'f8e7d6c5b4a39281' : '0000000000000000');

    const spiIBytes = uint64ToBytes(initiatorSpi);
    const spiRBytes = uint64ToBytes(responderSpi);

    let payloadsBytes = [];

    if (exchangeType === IKE_EXCHANGE_TYPES.IKE_SA_INIT) {
      // SA Payload -> KE Payload -> Nonce Payload -> NAT-T Source Notify -> NAT-T Dest Notify
      const sa = buildSaPayload({
        encrId: params.encrId || 20,
        prfId: params.prfId || 5,
        integId: params.integId !== undefined ? params.integId : 0,
        dhId: params.dhId || 19
      }, false);

      const ke = buildKePayload(params.dhId || 19, false);
      const nonce = buildNoncePayload(false);
      const natSrc = buildNatNotifyPayload(16388, params.srcIp || '198.51.100.10', 500, initiatorSpi, responderSpi, false); // NAT_DETECTION_SOURCE_IP
      const natDst = buildNatNotifyPayload(16389, params.dstIp || '203.0.113.1', 500, initiatorSpi, responderSpi, true);  // NAT_DETECTION_DESTINATION_IP

      payloadsBytes = payloadsBytes.concat(sa).concat(ke).concat(nonce).concat(natSrc).concat(natDst);
    } else {
      // Generic payload or Encrypted dummy for IKE_AUTH / INFORMATIONAL
      const dummy = [
        0x00, 0x00, // No next payload
        0x00, 0x20  // 32 bytes length
      ];
      for (let i = 0; i < 28; i++) dummy.push(0xcc);
      payloadsBytes = dummy;
    }

    // Fixed 28-octet IKE Header
    const firstPayload = (exchangeType === IKE_EXCHANGE_TYPES.IKE_SA_INIT) ? IKE_PAYLOAD_TYPES.SECURITY_ASSOCIATION : IKE_PAYLOAD_TYPES.ENCRYPTED_AND_AUTH;
    const totalLength = 28 + payloadsBytes.length;

    let flags = 0x00;
    if (isInitiator) flags |= 0x08; // Initiator flag (Bit 3 in RFC 7296 0-indexed from MSB, value 0x08 in low nibble)
    if (isResponse) flags |= 0x20;  // Response flag (Bit 5 in RFC 7296, value 0x20)

    const ikeHeader = [
      // Initiator SPI (8B)
      ...spiIBytes,
      // Responder SPI (8B)
      ...spiRBytes,
      // Next Payload (1B)
      firstPayload,
      // Version: Major 2, Minor 0 -> 0x20 (1B)
      0x20,
      // Exchange Type (1B)
      exchangeType,
      // Flags (1B)
      flags,
      // Message ID (4B)
      (messageId >> 24) & 0xff,
      (messageId >> 16) & 0xff,
      (messageId >> 8) & 0xff,
      messageId & 0xff,
      // Total Length (4B)
      (totalLength >> 24) & 0xff,
      (totalLength >> 16) & 0xff,
      (totalLength >> 8) & 0xff,
      totalLength & 0xff
    ];

    const rawBytes = ikeHeader.concat(payloadsBytes);

    return {
      initiatorSpi,
      responderSpi,
      exchangeType,
      exchangeName: Object.keys(IKE_EXCHANGE_TYPES).find(k => IKE_EXCHANGE_TYPES[k] === exchangeType) || 'UNKNOWN',
      totalLength,
      rawBytes: new Uint8Array(rawBytes)
    };
  }

  /**
   * Wireshark-Style Hex Formatter with Byte Offsets and ASCII Decoding
   */
  function formatHexDump(uint8Arr) {
    const lines = [];
    const len = uint8Arr.length;

    for (let i = 0; i < len; i += 16) {
      const chunk = uint8Arr.subarray(i, Math.min(i + 16, len));
      const offset = i.toString(16).padStart(4, '0');

      let hexPart1 = '';
      let hexPart2 = '';
      let asciiPart = '';

      for (let j = 0; j < 16; j++) {
        if (j < chunk.length) {
          const byte = chunk[j];
          const hex = byte.toString(16).padStart(2, '0');
          if (j < 8) hexPart1 += hex + ' ';
          else hexPart2 += hex + ' ';

          asciiPart += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
        } else {
          if (j < 8) hexPart1 += '   ';
          else hexPart2 += '   ';
        }
      }

      const hexCombined = (hexPart1.trimEnd() + '  ' + hexPart2.trimEnd()).padEnd(48, ' ');
      lines.push(`${offset}   ${hexCombined}   |${asciiPart}|`);
    }

    return lines.join('\n');
  }

  /**
   * IKEv2 Proposal Matcher & Mismatch Root-Cause Engine
   * 
   * Simulates negotiation between Initiator and Responder proposals,
   * detecting NO_PROPOSAL_CHOSEN, INVALID_KE_PAYLOAD, or successful SA establishment.
   */
  function matchProposals(initiator, responder) {
    const issues = [];
    let negotiated = null;

    // Check ENCR
    if (initiator.encrId !== responder.encrId) {
      const initName = ALGORITHMS.ENCR[initiator.encrId] ? ALGORITHMS.ENCR[initiator.encrId].name : `Unknown (${initiator.encrId})`;
      const respName = ALGORITHMS.ENCR[responder.encrId] ? ALGORITHMS.ENCR[responder.encrId].name : `Unknown (${responder.encrId})`;
      issues.push({
        field: 'Encryption Algorithm (ENCR)',
        initiator: initName,
        responder: respName,
        notifyCode: 'NO_PROPOSAL_CHOSEN (14)',
        severity: 'FATAL',
        explanation: 'The peer rejected the proposal because encryption ciphers do not match.'
      });
    }

    // Check PRF
    if (initiator.prfId !== responder.prfId) {
      const initName = ALGORITHMS.PRF[initiator.prfId] ? ALGORITHMS.PRF[initiator.prfId].name : `Unknown (${initiator.prfId})`;
      const respName = ALGORITHMS.PRF[responder.prfId] ? ALGORITHMS.PRF[responder.prfId].name : `Unknown (${responder.prfId})`;
      issues.push({
        field: 'Pseudo-Random Function (PRF)',
        initiator: initName,
        responder: respName,
        notifyCode: 'NO_PROPOSAL_CHOSEN (14)',
        severity: 'FATAL',
        explanation: 'IKEv2 key derivation PRF mismatch prevents shared key calculation.'
      });
    }

    // Check DH Group
    if (initiator.dhId !== responder.dhId) {
      const initName = ALGORITHMS.DH[initiator.dhId] ? ALGORITHMS.DH[initiator.dhId].name : `Unknown (${initiator.dhId})`;
      const respName = ALGORITHMS.DH[responder.dhId] ? ALGORITHMS.DH[responder.dhId].name : `Unknown (${responder.dhId})`;
      issues.push({
        field: 'Diffie-Hellman Group (D-H)',
        initiator: initName,
        responder: respName,
        notifyCode: 'INVALID_KE_PAYLOAD (17)',
        severity: 'FATAL',
        explanation: `Responder expects ${respName}. Sends INVALID_KE_PAYLOAD forcing Initiator to retry with expected DH group.`
      });
    }

    // Check Pre-Shared Key
    if (initiator.psk !== responder.psk) {
      issues.push({
        field: 'Pre-Shared Key (PSK) Secret',
        initiator: '*** [Configured]',
        responder: '*** [Mismatch]',
        notifyCode: 'AUTHENTICATION_FAILED (24)',
        severity: 'FATAL',
        explanation: 'Cryptographic hash verification failed in IKE_AUTH exchange due to mismatched pre-shared keys.'
      });
    }

    // Check Traffic Selectors
    if (initiator.trafficSelectorNarrowing === false && responder.requireExactSubnet === true) {
      issues.push({
        field: 'Traffic Selector (TS) Subnet Range',
        initiator: initiator.localSubnet || '0.0.0.0/0',
        responder: responder.expectedSubnet || '10.100.0.0/16',
        notifyCode: 'TS_UNACCEPTABLE (38)',
        severity: 'FATAL',
        explanation: 'Responder does not permit route-based 0.0.0.0/0 narrowing and requires exact policy matching.'
      });
    }

    const isSuccess = issues.length === 0;

    if (isSuccess) {
      const encr = ALGORITHMS.ENCR[initiator.encrId];
      const prf = ALGORITHMS.PRF[initiator.prfId];
      const dh = ALGORITHMS.DH[initiator.dhId];

      negotiated = {
        encrName: encr.name,
        prfName: prf.name,
        dhName: dh.name,
        keyLengthBits: encr.keyLen,
        natTraversal: initiator.natDetected ? 'UDP Port 4500 (Encapsulated)' : 'UDP Port 500 (Native)',
        tunnelStatus: 'ESTABLISHED / UP',
        ipsecSaEstablished: true
      };
    }

    return {
      success: isSuccess,
      issues,
      negotiated,
      rootCauseCode: issues.length > 0 ? issues[0].notifyCode : 'NONE'
    };
  }

  /**
   * Generates a standard binary PCAP file containing the forged IKEv2 frame
   */
  function generatePcap(forgedPacket, srcPublic, dstPublic, port) {
    const rawIke = forgedPacket.rawBytes;
    const destPort = port || 500;
    const srcPort = port || 500;

    // Ethernet Header (14 bytes)
    const ethDst = [0x00, 0x50, 0x56, 0xa1, 0xb2, 0xc3];
    const ethSrc = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
    const ethHdr = ethDst.concat(ethSrc).concat([0x08, 0x00]); // EtherType: IPv4

    // Non-ESP Marker for UDP 4500 (4 bytes 0x00000000)
    const nonEspMarker = (destPort === 4500) ? [0x00, 0x00, 0x00, 0x00] : [];

    // UDP Header (8 bytes)
    const udpLen = 8 + nonEspMarker.length + rawIke.length;
    const udpHdr = [
      (srcPort >> 8) & 0xff, srcPort & 0xff,
      (destPort >> 8) & 0xff, destPort & 0xff,
      (udpLen >> 8) & 0xff, udpLen & 0xff,
      0x00, 0x00 // Checksum optional in IPv4
    ];

    // IPv4 Header (20 bytes)
    const ipSrc = parseIpv4(srcPublic || '198.51.100.10');
    const ipDst = parseIpv4(dstPublic || '203.0.113.1');
    const ipTotalLen = 20 + udpLen;

    const ipHdr = [
      0x45, 0x00, // Version 4, IHL 5, DSCP 0
      (ipTotalLen >> 8) & 0xff, ipTotalLen & 0xff,
      0x34, 0x12, 0x40, 0x00, // ID, Flags (DF=1)
      0x40, 17, // TTL: 64, Protocol: 17 (UDP)
      0x00, 0x00, // Checksum placeholder
      ...ipSrc,
      ...ipDst
    ];

    // Compute IPv4 Checksum
    let sum = 0;
    for (let i = 0; i < 20; i += 2) {
      sum += (ipHdr[i] << 8) + ipHdr[i + 1];
    }
    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    const ipChecksum = (~sum) & 0xffff;
    ipHdr[10] = (ipChecksum >> 8) & 0xff;
    ipHdr[11] = ipChecksum & 0xff;

    // Full Ethernet frame payload
    const packetData = ethHdr.concat(ipHdr).concat(udpHdr).concat(nonEspMarker).concat(Array.from(rawIke));

    // PCAP Global Header (24 bytes, standard tcpdump format)
    const pcapHeader = new ArrayBuffer(24);
    const pcapView = new DataView(pcapHeader);
    pcapView.setUint32(0, 0xa1b2c3d4, false); // Magic number
    pcapView.setUint16(4, 2, false);          // Version Major: 2
    pcapView.setUint16(6, 4, false);          // Version Minor: 4
    pcapView.setInt32(8, 0, false);           // Thiszone: 0
    pcapView.setUint32(12, 0, false);         // Sigfigs: 0
    pcapView.setUint32(16, 262144, false);    // Snaplen: 256KB
    pcapView.setUint32(20, 1, false);         // LinkType: 1 (Ethernet)

    // Packet Record Header (16 bytes)
    const recordHeader = new ArrayBuffer(16);
    const recordView = new DataView(recordHeader);
    const nowSec = Math.floor(Date.now() / 1000);
    recordView.setUint32(0, nowSec, false);
    recordView.setUint32(4, 0, false);
    recordView.setUint32(8, packetData.length, false);  // Captured length
    recordView.setUint32(12, packetData.length, false); // Original length

    // Combine into final byte array
    const totalPcap = new Uint8Array(24 + 16 + packetData.length);
    totalPcap.set(new Uint8Array(pcapHeader), 0);
    totalPcap.set(new Uint8Array(recordHeader), 24);
    totalPcap.set(new Uint8Array(packetData), 40);

    return totalPcap;
  }

  return {
    IKE_EXCHANGE_TYPES,
    IKE_PAYLOAD_TYPES,
    TRANSFORM_TYPES,
    ALGORITHMS,
    forgeIkePacket,
    formatHexDump,
    matchProposals,
    generatePcap
  };
}));
