# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Network topology view (Milestone 21).

An honest asset map: every host NetVulnX has actually observed (Asset
rows from completed scans), grouped into /24 "zones", drawn as
server-side SVG — no JavaScript, no external libraries, works offline.

What the picture MEANS (and what it does not):
* A node is a host we scanned. Its color is the worst severity among
  that host's open findings (grey = no open findings).
* A zone box is a /24 subnet derived from the host's own IP address —
  a rough trust boundary, not a discovered VLAN.
* A line between two hosts means they were observed in the SAME scan
  (shared scan vantage point), nothing more. We do not claim to have
  discovered routing, lateral-movement paths, or traffic flows.
The legend on the page says exactly this.
"""
import ipaddress
import math

_SEV_COLOR = {
    "critical": "#d32f2f",
    "high": "#ef6c00",
    "medium": "#f9a825",
    "low": "#0288d1",
    "info": "#757575",
}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def zone_of(ip):
    """Rough /24 trust zone for an IPv4 address; /64 for IPv6. Falls back
    to the raw address when it is not parseable."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv4Address):
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
    else:
        net = ipaddress.ip_network(f"{ip}/64", strict=False)
    return str(net)


def build_topology(assets):
    """assets: iterable of (asset, worst_severity_or_None, port_count,
    service_names). Returns (zones, edges) where zones maps zone label ->
    list of node dicts and edges is a list of (ip_a, ip_b) pairs observed
    in the same scan."""
    zones = {}
    by_scan = {}
    for asset, worst, port_count, services in assets:
        node = {
            "ip": asset.ip_address,
            "hostname": asset.hostname,
            "worst": worst,
            "color": _SEV_COLOR.get(worst, "#9e9e9e"),
            "ports": port_count,
            "services": services[:4],
            "scan_id": asset.scan_id,
        }
        zones.setdefault(zone_of(asset.ip_address), []).append(node)
        by_scan.setdefault(asset.scan_id, []).append(asset.ip_address)
    edges = set()
    for ips in by_scan.values():
        for i in range(len(ips)):
            for j in range(i + 1, len(ips)):
                edges.add(tuple(sorted((ips[i], ips[j]))))
    return zones, sorted(edges)


def render_svg(zones, edges):
    """Lay out zones left-to-right, nodes in a grid inside each zone."""
    node_w, node_h, gap = 150, 64, 18
    per_row = 4
    zone_gap = 40
    pad = 16
    header_h = 30

    zone_boxes = []
    x = pad
    pos = {}  # ip -> (cx, cy)
    for zone_label in sorted(zones):
        nodes = zones[zone_label]
        rows = math.ceil(len(nodes) / per_row)
        w = per_row * (node_w + gap) - gap + pad * 2
        h = header_h + rows * (node_h + gap) - gap + pad * 2
        for idx, node in enumerate(nodes):
            r, c = divmod(idx, per_row)
            nx = x + pad + c * (node_w + gap)
            ny = pad + header_h + r * (node_h + gap)
            pos[node["ip"]] = (nx + node_w / 2, ny + node_h / 2)
            node["_x"], node["_y"] = nx, ny
        zone_boxes.append((zone_label, x, w, h, nodes))
        x += w + zone_gap
    total_w = x - zone_gap + pad
    total_h = max((h for _, _, _, h, _ in zone_boxes), default=200) + pad * 2

    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" '
             f'height="{total_h}" role="img" '
             f'aria-label="Network topology map">']
    # Edges first (under the nodes).
    for a, b in edges:
        if a in pos and b in pos:
            x1, y1 = pos[a]
            x2, y2 = pos[b]
            parts.append(
                f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
                f'stroke="#bdbdbd" stroke-width="1.5"/>')
    for zone_label, zx, zw, zh, nodes in zone_boxes:
        parts.append(
            f'<rect x="{zx}" y="{pad}" width="{zw}" height="{zh}" rx="10" '
            f'fill="#f5f7fa" stroke="#cfd8dc"/>')
        parts.append(
            f'<text x="{zx + pad}" y="{pad + 20}" font-size="13" '
            f'font-weight="bold" fill="#37474f">{_esc(zone_label)}</text>')
        for node in nodes:
            nx, ny = node["_x"], node["_y"]
            label = node["hostname"] or node["ip"]
            svc = ", ".join(node["services"]) or "no open ports"
            parts.append(
                f'<rect x="{nx}" y="{ny}" width="{node_w}" height="{node_h}" '
                f'rx="8" fill="white" stroke="{node["color"]}" '
                f'stroke-width="3"/>')
            parts.append(
                f'<text x="{nx + 10}" y="{ny + 20}" font-size="12" '
                f'font-weight="bold" fill="#212121">{_esc(label[:20])}</text>')
            if node["hostname"]:
                parts.append(
                    f'<text x="{nx + 10}" y="{ny + 36}" font-size="11" '
                    f'fill="#616161">{_esc(node["ip"])}</text>')
            parts.append(
                f'<text x="{nx + 10}" y="{ny + 52}" font-size="11" '
                f'fill="#616161">{node["ports"]} ports · {_esc(svc[:28])}</text>')
    parts.append("</svg>")
    return "\n".join(parts)


def _esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))
