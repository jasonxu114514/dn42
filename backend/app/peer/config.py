from app.db.models import Node, PeerRequest


def render_user_config(peer: PeerRequest, node: Node) -> str:
    return f"""# Generated dn42 peer config for AS{peer.asn} on node {node.name}
# This is an MVP preview. Confirm addresses and ports before deploying.

[Interface]
# PrivateKey = <your-private-key>
# Address = <your-link-address>

[Peer]
PublicKey = <our-node-public-key>
Endpoint = {node.agent_url}
AllowedIPs = 172.16.0.0/12, fd00::/8
PersistentKeepalive = 25

# BGP
# Neighbor ASN: <our-asn>
# Your ASN: {peer.asn}
"""


def render_operator_config(peer: PeerRequest, node: Node) -> str:
    return f"""# Operator preview for request #{peer.id}

# WireGuard peer
[Peer]
PublicKey = {peer.wg_public_key}
Endpoint = {peer.endpoint}
AllowedIPs = <assigned-link-address>

# BIRD protocol sketch
protocol bgp dn42_{peer.asn}_{node.name} {{
  local as <our-asn>;
  neighbor <peer-link-address> as {peer.asn};
  ipv4 {{ import filter dn42_import; export filter dn42_export; }};
  ipv6 {{ import filter dn42_import; export filter dn42_export; }};
}}
"""
