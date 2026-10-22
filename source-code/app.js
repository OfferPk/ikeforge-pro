/**
 * IKEForge Pro - Web Studio Controller & Preset Manager
 */

(function () {
  'use strict';

  const PRESETS = {
    'enterprise-cnsa': {
      exchangeType: 34,
      initiatorSpi: 'a1b2c3d4e5f60718',
      responderSpi: '0000000000000000',
      encrId: 20, // AES-GCM-256
      prfId: 5,   // SHA-384
      integId: 0, // NONE (AEAD)
      dhId: 19,   // Group 19 (ECP 256)
      psk: 'EnterpriseIkeV2#ZeroTrust2026!',
      natTraversalEnabled: true,
      pfsEnabled: true,
      dpdEnabled: true,
      dpdInterval: 10,
      antiReplayWindow: 64,
      ikeLifetimeSec: 28800,
      childLifetimeSec: 3600,
      esnEnabled: true
    },
    'aws-cloud-transit': {
      exchangeType: 34,
      initiatorSpi: 'b8c9d0e1f2a34567',
      responderSpi: '0000000000000000',
      encrId: 20,
      prfId: 5,
      integId: 0,
      dhId: 19,
      psk: 'AwsCloudTransit#IkeV2_2026!',
      natTraversalEnabled: true,
      pfsEnabled: true,
      dpdEnabled: true,
      dpdInterval: 10,
      antiReplayWindow: 128,
      ikeLifetimeSec: 28800,
      childLifetimeSec: 3600,
      esnEnabled: true
    },
    'legacy-vulnerable': {
      exchangeType: 34,
      initiatorSpi: '1122334455667788',
      responderSpi: '0000000000000000',
      encrId: 3,  // 3DES (Sweet32 vulnerability!)
      prfId: 1,   // MD5 (Broken!)
      integId: 1, // MD5
      dhId: 2,    // Group 2 (1024-bit Logjam!)
      psk: 'cisco123', // Weak PSK
      natTraversalEnabled: false,
      pfsEnabled: false,
      dpdEnabled: false,
      dpdInterval: 60,
      antiReplayWindow: 32,
      ikeLifetimeSec: 86400,
      childLifetimeSec: 28800,
      esnEnabled: false
    }
  };

  let currentConfig = Object.assign({}, PRESETS['enterprise-cnsa']);
  let activeTab = 'cisco';
  let forgedPacketCache = null;

  // DOM Elements
  const selectExchange = document.getElementById('select-exchange');
  const inputInitSpi = document.getElementById('input-init-spi');
  const selectEncr = document.getElementById('select-encr');
  const selectPrf = document.getElementById('select-prf');
  const selectDh = document.getElementById('select-dh');
  const selectNatt = document.getElementById('select-natt');
  const inputPsk = document.getElementById('input-psk');
  const badgePduLen = document.getElementById('badge-pdu-len');

  const badgeTunnelStatus = document.getElementById('badge-tunnel-status');
  const negDiagBanner = document.getElementById('neg-diag-banner');
  const negDiagTitle = document.getElementById('neg-diag-title');
  const negDiagDesc = document.getElementById('neg-diag-desc');
  const selectSimulateError = document.getElementById('select-simulate-error');

  const mInitEncr = document.getElementById('m-init-encr');
  const mInitPrf = document.getElementById('m-init-prf');
  const mInitDh = document.getElementById('m-init-dh');
  const mInitNatt = document.getElementById('m-init-natt');

  const mRespEncr = document.getElementById('m-resp-encr');
  const mRespPrf = document.getElementById('m-resp-prf');
  const mRespDh = document.getElementById('m-resp-dh');
  const mRespNatt = document.getElementById('m-resp-natt');

  const auditGradeCircle = document.getElementById('audit-grade-circle');
  const auditScoreText = document.getElementById('audit-score-text');
  const auditComplianceText = document.getElementById('audit-compliance-text');
  const auditScoreBar = document.getElementById('audit-score-bar');
  const auditStatusBadge = document.getElementById('audit-status-badge');
  const findingsContainer = document.getElementById('findings-container');

  const hexDissectorBox = document.getElementById('hex-dissector-box');
  const synthesizerOutputBox = document.getElementById('synthesizer-output-box');

  const btnCopyHex = document.getElementById('btn-copy-hex');
  const btnDownloadPcap = document.getElementById('btn-download-pcap');
  const btnCopyConfig = document.getElementById('btn-copy-config');
  const presetButtons = document.querySelectorAll('.btn-preset');
  const tabButtons = document.querySelectorAll('.tab-btn');

  function updateUiFromConfig() {
    selectExchange.value = currentConfig.exchangeType;
    inputInitSpi.value = currentConfig.initiatorSpi;
    selectEncr.value = currentConfig.encrId;
    selectPrf.value = currentConfig.prfId;
    selectDh.value = currentConfig.dhId;
    selectNatt.value = currentConfig.natTraversalEnabled ? 'true' : 'false';
    inputPsk.value = currentConfig.psk;

    recomputeAll();
  }

  function readConfigFromUi() {
    currentConfig.exchangeType = parseInt(selectExchange.value, 10);
    currentConfig.initiatorSpi = inputInitSpi.value.trim() || 'a1b2c3d4e5f60718';
    currentConfig.encrId = parseInt(selectEncr.value, 10);
    currentConfig.prfId = parseInt(selectPrf.value, 10);
    currentConfig.dhId = parseInt(selectDh.value, 10);
    currentConfig.natTraversalEnabled = (selectNatt.value === 'true');
    currentConfig.psk = inputPsk.value.trim() || 'EnterpriseIkeV2#ZeroTrust2026!';

    // Adjust integId for AEAD
    if (currentConfig.encrId === 18 || currentConfig.encrId === 19 || currentConfig.encrId === 20) {
      currentConfig.integId = 0;
    } else {
      currentConfig.integId = (currentConfig.prfId === 1) ? 1 : 12;
    }

    recomputeAll();
  }

  function recomputeAll() {
    // 1. Forge IKE Packet
    forgedPacketCache = IKEProtocolEngine.forgeIkePacket({
      exchangeType: currentConfig.exchangeType,
      initiatorSpi: currentConfig.initiatorSpi,
      responderSpi: currentConfig.responderSpi,
      encrId: currentConfig.encrId,
      prfId: currentConfig.prfId,
      integId: currentConfig.integId,
      dhId: currentConfig.dhId,
      srcIp: '198.51.100.10',
      dstIp: '203.0.113.1'
    });

    badgePduLen.textContent = `PDU: ${forgedPacketCache.totalLength}B`;
    hexDissectorBox.textContent = IKEProtocolEngine.formatHexDump(forgedPacketCache.rawBytes);

    // 2. Negotiation Matcher
    const simulatedError = selectSimulateError.value;
    const initiatorProp = {
      encrId: currentConfig.encrId,
      prfId: currentConfig.prfId,
      dhId: currentConfig.dhId,
      psk: currentConfig.psk,
      natDetected: currentConfig.natTraversalEnabled,
      trafficSelectorNarrowing: true
    };

    const responderProp = Object.assign({}, initiatorProp);
    if (simulatedError === 'encr_mismatch') {
      responderProp.encrId = (initiatorProp.encrId === 20) ? 12 : 20;
    } else if (simulatedError === 'dh_mismatch') {
      responderProp.dhId = (initiatorProp.dhId === 19) ? 14 : 19;
    } else if (simulatedError === 'psk_mismatch') {
      responderProp.psk = 'MismatchSecretPassword!';
    } else if (simulatedError === 'ts_mismatch') {
      initiatorProp.trafficSelectorNarrowing = false;
      responderProp.requireExactSubnet = true;
    }

    // Render Matrix Text
    const encrObj = IKEProtocolEngine.ALGORITHMS.ENCR[initiatorProp.encrId] || { name: 'Unknown' };
    const prfObj = IKEProtocolEngine.ALGORITHMS.PRF[initiatorProp.prfId] || { name: 'Unknown' };
    const dhObj = IKEProtocolEngine.ALGORITHMS.DH[initiatorProp.dhId] || { name: 'Unknown' };
    mInitEncr.textContent = encrObj.name;
    mInitPrf.textContent = prfObj.name;
    mInitDh.textContent = dhObj.name;
    mInitNatt.textContent = currentConfig.natTraversalEnabled ? 'UDP 4500' : 'UDP 500';

    const respEncrObj = IKEProtocolEngine.ALGORITHMS.ENCR[responderProp.encrId] || { name: 'Unknown' };
    const respPrfObj = IKEProtocolEngine.ALGORITHMS.PRF[responderProp.prfId] || { name: 'Unknown' };
    const respDhObj = IKEProtocolEngine.ALGORITHMS.DH[responderProp.dhId] || { name: 'Unknown' };
    mRespEncr.textContent = respEncrObj.name;
    mRespPrf.textContent = respPrfObj.name;
    mRespDh.textContent = respDhObj.name;
    mRespNatt.textContent = responderProp.natDetected ? 'UDP 4500' : 'UDP 500';

    const matchRes = IKEProtocolEngine.matchProposals(initiatorProp, responderProp);

    if (matchRes.success) {
      badgeTunnelStatus.textContent = 'ESTABLISHED';
      badgeTunnelStatus.className = 'badge badge-emerald';
      negDiagBanner.className = 'diag-banner diag-protected';
      negDiagTitle.textContent = 'IKE_SA_INIT & IKE_AUTH NEGOTIATION SUCCEEDED';
      negDiagDesc.textContent = `Proposals aligned. Secure Child SA active via ${matchRes.negotiated.natTraversal} with ${matchRes.negotiated.encrName}.`;
    } else {
      badgeTunnelStatus.textContent = matchRes.rootCauseCode.split(' ')[0];
      badgeTunnelStatus.className = 'badge badge-rose';
      negDiagBanner.className = 'diag-banner diag-critical';
      const issue = matchRes.issues[0];
      negDiagTitle.textContent = `NEGOTIATION FAILED: ${issue.notifyCode}`;
      negDiagDesc.textContent = `${issue.field} mismatch. Initiator: ${issue.initiator} vs Peer: ${issue.responder}. ${issue.explanation}`;
    }

    // 3. 10-Point Zero-Trust Security Audit
    const audit = IKESecurityAuditor.auditConfiguration({
      encrId: currentConfig.encrId,
      prfId: currentConfig.prfId,
      dhId: currentConfig.dhId,
      pfsEnabled: currentConfig.pfsEnabled,
      natTraversalEnabled: currentConfig.natTraversalEnabled,
      dpdEnabled: currentConfig.dpdEnabled,
      dpdInterval: currentConfig.dpdInterval,
      psk: currentConfig.psk,
      antiReplayWindow: currentConfig.antiReplayWindow,
      ikeLifetimeSec: currentConfig.ikeLifetimeSec,
      childLifetimeSec: currentConfig.childLifetimeSec,
      esnEnabled: currentConfig.esnEnabled
    });

    auditScoreText.textContent = `${audit.score} / 100 Points`;
    auditGradeCircle.textContent = audit.grade;
    auditGradeCircle.className = `grade-circle grade-${audit.grade.toLowerCase().replace('+', 'plus')}`;
    auditScoreBar.style.width = `${audit.score}%`;

    if (audit.passed) {
      auditScoreBar.style.background = 'var(--primary-emerald)';
      auditComplianceText.textContent = 'NSA CNSA & NIST Compliant';
      auditComplianceText.style.color = 'var(--primary-emerald)';
      auditStatusBadge.textContent = 'PASSING';
      auditStatusBadge.className = 'badge badge-emerald';
    } else {
      auditScoreBar.style.background = 'var(--primary-rose)';
      auditComplianceText.textContent = 'Non-Compliant / Audit Failure';
      auditComplianceText.style.color = 'var(--primary-rose)';
      auditStatusBadge.textContent = 'CRITICAL FAILS';
      auditStatusBadge.className = 'badge badge-rose';
    }

    // Render findings
    findingsContainer.innerHTML = '';
    audit.findings.forEach(f => {
      const div = document.createElement('div');
      div.className = `finding-item ${f.level.toLowerCase()}`;
      div.innerHTML = `
        <div style="display: flex; justify-content: space-between; font-weight: 700; margin-bottom: 0.2rem;">
          <span>[${f.level}] ${f.id} - ${f.title}</span>
          <span style="font-family: var(--font-mono);">${f.score}/${f.maxPoints} pts</span>
        </div>
        <div style="color: var(--text-muted); font-size: 0.78rem;">${f.finding}</div>
      `;
      findingsContainer.appendChild(div);
    });

    // 4. Update Synthesizer
    renderSynthesizerConfig();
  }

  function renderSynthesizerConfig() {
    const synthParams = {
      peerIp: '203.0.113.1',
      localIp: '198.51.100.10',
      psk: currentConfig.psk || 'EnterpriseIkeV2#ZeroTrust2026!',
      tunnelId: 100,
      tunnelLocalIp: '10.254.10.1',
      tunnelRemoteIp: '10.254.10.2'
    };

    let text = '';
    if (activeTab === 'cisco') {
      text = IKEConfigSynthesizer.synthesizeCiscoIosXe(synthParams);
    } else if (activeTab === 'fortinet') {
      text = IKEConfigSynthesizer.synthesizeFortinet(synthParams);
    } else if (activeTab === 'paloalto') {
      text = IKEConfigSynthesizer.synthesizePaloAlto(synthParams);
    } else if (activeTab === 'strongswan') {
      text = IKEConfigSynthesizer.synthesizeStrongSwan(synthParams);
    } else if (activeTab === 'terraform') {
      text = IKEConfigSynthesizer.synthesizeTerraformAws(synthParams);
    }
    synthesizerOutputBox.textContent = text;
  }

  // Event Listeners
  [selectExchange, inputInitSpi, selectEncr, selectPrf, selectDh, selectNatt, inputPsk, selectSimulateError].forEach(el => {
    el.addEventListener('change', readConfigFromUi);
    el.addEventListener('input', readConfigFromUi);
  });

  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      presetButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const presetKey = btn.getAttribute('data-preset');
      if (PRESETS[presetKey]) {
        currentConfig = Object.assign({}, PRESETS[presetKey]);
        selectSimulateError.value = 'none';
        updateUiFromConfig();
      }
    });
  });

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeTab = btn.getAttribute('data-tab');
      renderSynthesizerConfig();
    });
  });

  btnCopyHex.addEventListener('click', () => {
    navigator.clipboard.writeText(hexDissectorBox.textContent).then(() => {
      btnCopyHex.textContent = 'Copied!';
      setTimeout(() => btnCopyHex.textContent = 'Copy Hex', 2000);
    });
  });

  btnCopyConfig.addEventListener('click', () => {
    navigator.clipboard.writeText(synthesizerOutputBox.textContent).then(() => {
      btnCopyConfig.textContent = 'Copied!';
      setTimeout(() => btnCopyConfig.textContent = 'Copy Config', 2000);
    });
  });

  btnDownloadPcap.addEventListener('click', () => {
    if (!forgedPacketCache) return;
    const port = currentConfig.natTraversalEnabled ? 4500 : 500;
    const pcapBytes = IKEProtocolEngine.generatePcap(forgedPacketCache, '198.51.100.10', '203.0.113.1', port);
    const blob = new Blob([pcapBytes], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ikev2-capture-${currentConfig.initiatorSpi}-${Date.now()}.pcap`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Initial load
  updateUiFromConfig();
})();
