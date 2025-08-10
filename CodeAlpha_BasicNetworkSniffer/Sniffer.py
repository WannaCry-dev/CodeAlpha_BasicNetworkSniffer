from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        payload_size = len(packet[IP].payload)

        # Map protocol numbers to names
        if proto == 6:
            proto_name = "TCP"
        elif proto == 17:
            proto_name = "UDP"
        else:
            proto_name = str(proto)

        print(f"[+] {ip_src} -> {ip_dst} | Protocol: {proto_name} | Payload size: {payload_size} bytes")

        # Optional: Display TCP/UDP ports if present
        if TCP in packet:
            print(f"    TCP ports: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    UDP ports: {packet[UDP].sport} -> {packet[UDP].dport}")

        # Optional: Show payload content (truncated to 50 chars for readability)
        payload = bytes(packet[IP].payload)
        print(f"    Payload (truncated): {payload[:50]!r}\n")

if __name__ == "__main__":
    print("[*] Starting network sniffer...")
    print("[*] Press Ctrl+C to stop.\n")
    sniff(iface="Wi-Fi", prn=packet_callback, store=False)

