from scapy.all import IP, send, ICMP


# Implement your ICMP sender here

def send_icmp_packet():
    # Create an IP packet
    ip_packet = IP(dst="receiver", ttl=1)

    # Add ICMP layer onto the ip_packet
    icmp_packet = ip_packet / ICMP()

    # Send the ICMP packet
    send(icmp_packet, verbose=False)


if __name__ == "__main__":
    send_icmp_packet()
    exit()
