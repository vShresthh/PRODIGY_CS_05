import scapy.all as scapy

def sniff_packets(interface):
    """Sniffs packets on the specified interface and prints packet details.

    Args:
        interface (str): The network interface to capture packets from.
    """

    scapy.sniff(iface=interface, store=False, prn=lambda packet: packet_handler(packet))

def packet_handler(packet):
    """Handles captured packets and prints relevant information.

    Args:
        packet (scapy.packet.Packet): The captured packet.
    """

    if packet.haslayer(scapy.IP):
        ip_header = packet[scapy.IP]
        src_ip = ip_header[scapy.IP].src
        dst_ip = ip_header[scapy.IP].dst
        protocol = ip_header[scapy.IP].proto
        print(f"Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}")

if __name__ == "__main__":
    interface = input("Enter the network interface: ")
    sniff_packets(interface)
