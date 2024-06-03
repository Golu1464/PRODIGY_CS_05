from os import name
from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    """
    Callback function to handle each captured packet.
    Extracts and displays relevant information.
    """
    # Extract IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        print(f"IP Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}")

        # Check for TCP packets
        if protocol == 6 and TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Packet: {src_ip}:{tcp_layer.sport} -> {dst_ip}:{tcp_layer.dport}")
            if Raw in packet:
                print(f"Payload: {packet[Raw].load}")

        # Check for UDP packets
        elif protocol == 17 and UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Packet: {src_ip}:{udp_layer.sport} -> {dst_ip}:{udp_layer.dport}")
            if Raw in packet:
                print(f"Payload: {packet[Raw].load}")

def start_sniffer(interface=None):
    """
    Starts the packet sniffer on the specified network interface.
    """
    print(f"Starting packet sniffer on interface: {interface}")
    sniff(prn=packet_callback, iface=interface, store=False)

if name == "main":
    # Specify the network interface (e.g., 'eth0', 'wlan0', etc.)
    network_interface = "eth0"  # Change this to your network interface
    start_sniffer(network_interface)