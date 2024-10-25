from scapy.all import sniff, IP, ICMP


def packet_callback(packet):
    # Check if packet has the ICMP layer
    if packet.haslayer(ICMP):
        # Check if the packet has TTL=1
        if packet[IP].ttl == 1:
            # Display the packet
            packet.show()


def start_sniffing():
    # Wait for incoming packet, on packet arrival call packet_callback function
    sniff(filter="icmp", prn=packet_callback, count=1)


if __name__ == "__main__":
    start_sniffing()
    exit()
