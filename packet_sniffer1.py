try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether
    import sys
    import os
except ImportError:
    print("Scapy is not installed. Please install it using: pip install scapy")
    print("On Linux, you might also need to install libpcap-dev: sudo apt-get install libpcap-dev")
    sys.exit(1)

INTERFACE = '\\Device\\NPF_{7C3B5226-41AE-4340-8283-3C6BBF3D52E3}'
PACKET_COUNT = 10

def packet_callback(packet):
    print("\n" + "="*50)

    if packet.haslayer(Ether):
        print(f"Ethernet Layer:")
        print(f"  Source MAC: {packet[Ether].src}")
        print(f"  Destination MAC: {packet[Ether].dst}")
        print(f"  Type: {packet[Ether].type}")

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"IP Layer:")
        print(f"  Source IP: {ip_layer.src}")
        print(f"  Destination IP: {ip_layer.dst}")
        print(f"  Protocol: {ip_layer.proto} ({get_protocol_name(ip_layer.proto)})")
        print(f"  TTL (Time to Live): {ip_layer.ttl}")
        print(f"  Length: {ip_layer.len} bytes")

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"TCP Layer:")
            print(f"  Source Port: {tcp_layer.sport}")
            print(f"  Destination Port: {tcp_layer.dport}")
            print(f"  Flags: {tcp_layer.flags}")
            print(f"  Sequence Number: {tcp_layer.seq}")
            print(f"  Acknowledgement Number: {tcp_layer.ack}")
            print(f"  Window Size: {tcp_layer.window}")
            if packet.haslayer(Raw):
                print(f"  Payload (TCP): {packet[Raw].load.hex()}")

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"UDP Layer:")
            print(f"  Source Port: {udp_layer.sport}")
            print(f"  Destination Port: {udp_layer.dport}")
            print(f"  Length: {udp_layer.len}")
            if packet.haslayer(Raw):
                print(f"  Payload (UDP): {packet[Raw].load.hex()}")

        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            print(f"ICMP Layer:")
            print(f"  Type: {icmp_layer.type} ({get_icmp_type_name(icmp_layer.type)})")
            print(f"  Code: {icmp_layer.code}")
            if hasattr(icmp_layer, 'id'):
                print(f"  ID: {icmp_layer.id}")
            if hasattr(icmp_layer, 'seq'):
                print(f"  Sequence: {icmp_layer.seq}")
            if packet.haslayer(Raw):
                print(f"  Payload (ICMP): {packet[Raw].load.hex()}")

    elif not packet.haslayer(IP):
        print("Non-IP Packet (e.g., ARP, RARP, etc.) - Details not fully parsed by this script.")

    if packet.haslayer(Raw) and not (packet.haslayer(TCP) or packet.haslayer(UDP) or packet.haslayer(ICMP)):
        print(f"Raw Data (Unhandled Layer): {packet[Raw].load.hex()}")

    print("="*50)

def get_protocol_name(proto_num):
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        2: "IGMP",
        89: "OSPF",
        47: "GRE",
        50: "ESP",
        51: "AH",
        132: "SCTP"
    }
    return protocols.get(proto_num, f"Unknown ({proto_num})")

def get_icmp_type_name(icmp_type):
    icmp_types = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        4: "Source Quench",
        5: "Redirect",
        8: "Echo Request",
        9: "Router Advertisement",
        10: "Router Solicitation",
        11: "Time Exceeded",
        12: "Parameter Problem",
        13: "Timestamp Request",
        14: "Timestamp Reply",
        15: "Information Request",
        16: "Information Reply",
        17: "Address Mask Request",
        18: "Address Mask Reply"
    }
    return icmp_types.get(icmp_type, f"Unknown ({icmp_type})")

def start_sniffing():
    print(f"Starting packet capture on interface: {INTERFACE if INTERFACE else 'all interfaces'}")
    print(f"Capturing {PACKET_COUNT if PACKET_COUNT > 0 else 'unlimited'} packets...")
    print("Press Ctrl+C to stop the capture at any time.")

    try:
        sniff(prn=packet_callback, store=0, count=PACKET_COUNT, iface=INTERFACE)
        print("\nPacket capture finished.")
    except PermissionError:
        print("\nPermission denied. You need root/administrator privileges to sniff packets.")
        print("Try running the script with 'sudo python your_script_name.py' on Linux/macOS,")
        print("or as Administrator on Windows.")
    except Exception as e:
        print(f"\nAn error occurred during sniffing: {e}")

if __name__ == "__main__":
    if os.name == 'posix' and os.geteuid() != 0:
        print("Warning: You might need root privileges to sniff packets on this system.")
        print("Consider running with 'sudo python your_script_name.py'")
    elif os.name == 'nt':
        print("On Windows, ensure you run this script as Administrator for sniffing.")

    start_sniffing()
