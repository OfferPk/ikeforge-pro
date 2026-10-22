/**
 * IKEForge Pro - Multi-Platform IKEv2 & IPsec Configuration Synthesizer
 * 
 * Synthesizes production-hardened configurations for Cisco IOS-XE,
 * Fortinet FortiOS, Palo Alto PAN-OS, Linux strongSwan (swanctl), and AWS Site-to-Site VPN.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.IKEConfigSynthesizer = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function synthesizeCiscoIosXe(params) {
    const peerIp = params.peerIp || '203.0.113.1';
    const localIp = params.localIp || '198.51.100.10';
    const psk = params.psk || 'CiscoIkeV2#ZeroTrust2026!';
    const tunnelId = params.tunnelId || 100;
    const tunnelLocalIp = params.tunnelLocalIp || '10.254.10.1';
    const tunnelRemoteIp = params.tunnelRemoteIp || '10.254.10.2';

    return `! ==============================================================================
! Cisco IOS-XE Production-Hardened IKEv2 / IPsec Route-Based VPN Configuration
! Standards: RFC 7296 (IKEv2), RFC 4301/4303 (IPsec ESP), NSA CNSA AES-256-GCM
! ==============================================================================

! 1. IKEv2 Proposal & Policy (Phase 1)
crypto ikev2 proposal IKEV2-PROP-CNSA
 encryption aes-gcm-256
 prf sha384
 group 19
!
crypto ikev2 policy IKEV2-POL-CNSA
 proposal IKEV2-PROP-CNSA
!

! 2. IKEv2 Keyring & Profile
crypto ikev2 keyring IKEV2-KEYRING
 peer PEER-GATEWAY
  address ${peerIp}
  pre-shared-key local ${psk}
  pre-shared-key remote ${psk}
!
crypto ikev2 profile IKEV2-PROFILE
 match address local ${localIp}
 match identity remote address ${peerIp} 255.255.255.255
 identity local address ${localIp}
 authentication remote pre-share
 authentication local pre-share
 keyring local IKEV2-KEYRING
 dpd 10 3 periodic
 lifetime 28800
!

! 3. IPsec Transform-Set & Profile (Phase 2 Child SA with PFS)
crypto ipsec transform-set TS-AES-GCM esp-gcm 256
 mode transport
!
crypto ipsec profile IPSEC-PROFILE-VTI
 set transform-set TS-AES-GCM
 set ikev2-profile IKEV2-PROFILE
 set pfs group19
 set security-association lifetime seconds 3600
!

! 4. Route-Based Virtual Tunnel Interface (VTI) with MTU Clamping
interface Tunnel${tunnelId}
 description SITE-TO-SITE-IKEV2-IPSEC-VTI
 ip address ${tunnelLocalIp} 255.255.255.252
 ip mtu 1400
 ip tcp adjust-mss 1360
 tunnel source GigabitEthernet0/0/0
 tunnel mode ipsec ipv4
 tunnel destination ${peerIp}
 tunnel protection ipsec profile IPSEC-PROFILE-VTI
!
ip route 10.200.0.0 255.255.0.0 Tunnel${tunnelId}
`;
  }

  function synthesizeFortinet(params) {
    const peerIp = params.peerIp || '203.0.113.1';
    const localIntf = params.localIntf || 'port1';
    const psk = params.psk || 'FortinetIkeV2#ZeroTrust2026!';
    const vpnName = params.vpnName || 'VPN_PRIMARY_IPSEC';

    return `# ==============================================================================
# Fortinet FortiOS (7.x / 8.x) Production IKEv2 Phase 1 & Phase 2 Configuration
# ==============================================================================
config vpn ipsec phase1-interface
    edit "${vpnName}"
        set interface "${localIntf}"
        set ike-version 2
        set keylife 28800
        set peertype any
        set net-device disable
        set proposal aes256gcm-prfsha384
        set dhgrp 19
        set remote-gw ${peerIp}
        set psksecret "${psk}"
        set dpd-retryinterval 5
        set dpd-retrycount 3
        set dpd enable
        set auto-negotiate enable
    next
end

config vpn ipsec phase2-interface
    edit "${vpnName}_p2"
        set phase1name "${vpnName}"
        set proposal aes256gcm
        set dhgrp 19
        set keylifeseconds 3600
        set auto-negotiate enable
        set keepalive enable
    next
end
`;
  }

  function synthesizePaloAlto(params) {
    const peerIp = params.peerIp || '203.0.113.1';
    const psk = params.psk || 'PaloAltoIkeV2#ZeroTrust2026!';
    const gatewayName = params.gatewayName || 'GW-IKEV2-CORE';

    return `# ==============================================================================
# Palo Alto Networks PAN-OS (10.x / 11.x) CLI Configuration
# ==============================================================================
set network ike crypto-profiles ike-crypto-profiles IKE-PROF-CNSA hash sha384 dh-group group19 encryption aes-256-gcm lifetime seconds 28800
set network ipsec crypto-profiles ipsec-crypto-profiles IPSEC-PROF-CNSA esp encryption aes-256-gcm dh-group group19 lifetime seconds 3600

set network ike gateway ${gatewayName} version ikev2 ikev2-crypto-profile IKE-PROF-CNSA
set network ike gateway ${gatewayName} authentication pre-shared-key key "${psk}"
set network ike gateway ${gatewayName} peer-address ip ${peerIp}
set network ike gateway ${gatewayName} local-address ip 198.51.100.10 interface ethernet1/1
set network ike gateway ${gatewayName} protocol-common dpd enable yes interval 10 retry 3

set network tunnel ipsec TUNNEL-TO-REMOTE auto-key ike-gateway ${gatewayName} ipsec-crypto-profile IPSEC-PROF-CNSA
set network tunnel ipsec TUNNEL-TO-REMOTE tunnel-interface tunnel.10
`;
  }

  function synthesizeStrongSwan(params) {
    const peerIp = params.peerIp || '203.0.113.1';
    const psk = params.psk || 'StrongSwanIkeV2#ZeroTrust2026!';

    return `# ==============================================================================
# Linux strongSwan 5.x / 6.x Modern swanctl Configuration (/etc/swanctl/conf.d/ike.conf)
# ==============================================================================
connections {
    site-to-site {
        version = 2
        local_addrs = %defaultroute
        remote_addrs = ${peerIp}

        local {
            auth = psk
            id = @local-gateway.corp.net
        }
        remote {
            auth = psk
            id = @remote-gateway.corp.net
        }

        children {
            net-to-net {
                local_ts = 10.100.0.0/16
                remote_ts = 10.200.0.0/16
                esp_proposals = aes256gcm16-esn-ecp256
                dpd_action = restart
                close_action = restart
                start_action = start
                lifetime = 1h
            }
        }

        proposals = aes256gcm16-prfsha384-ecp256
        dpd_delay = 10s
        dpd_timeout = 30s
    }
}

secrets {
    ike-primary {
        id = @remote-gateway.corp.net
        secret = "${psk}"
    }
}
`;
  }

  function synthesizeTerraformAws(params) {
    const peerIp = params.peerIp || '198.51.100.10';
    const psk = params.psk || 'AwsVpnIkeV2#ZeroTrust2026!';

    return `# ==============================================================================
# Terraform HCL: AWS Site-to-Site IKEv2 / IPsec VPN Connection
# Enforces AES-256-GCM, SHA-384, and DH Group 19 (NIST P-256)
# ==============================================================================
resource "aws_customer_gateway" "main" {
  bgp_asn    = 65000
  ip_address = "${peerIp}"
  type       = "ipsec.1"

  tags = {
    Name = "Enterprise-Customer-Gateway"
  }
}

resource "aws_vpn_connection" "main" {
  vpn_gateway_id      = aws_vpn_gateway.vpn_gw.id
  customer_gateway_id = aws_customer_gateway.main.id
  type                = "ipsec.1"
  static_routes_only  = false

  # Phase 1 (IKEv2) Encryption & Integrity
  tunnel1_ike_versions                 = ["ikev2"]
  tunnel1_phase1_encryption_algorithms = ["AES256-GCM-16"]
  tunnel1_phase1_integrity_algorithms  = ["SHA2-384"]
  tunnel1_phase1_dh_group_numbers      = [19]
  tunnel1_preshared_key                = "${psk}"

  # Phase 2 (ESP) Child SA
  tunnel1_phase2_encryption_algorithms = ["AES256-GCM-16"]
  tunnel1_phase2_integrity_algorithms  = ["SHA2-384"]
  tunnel1_phase2_dh_group_numbers      = [19]

  tunnel1_dpd_timeout_seconds          = 30
  tunnel1_dpd_timeout_action           = "restart"
}
`;
  }

  return {
    synthesizeCiscoIosXe,
    synthesizeFortinet,
    synthesizePaloAlto,
    synthesizeStrongSwan,
    synthesizeTerraformAws
  };
}));
