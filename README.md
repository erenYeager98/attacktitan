from netfilterqueue import NetfilterQueue
from scapy.all import IP, ICMP

def packet_handler(packet):
    """
    Handles each packet passed to the NFQUEUE.
    Drops ICMP (ping) requests and accepts all others.
    """
    ip_packet = IP(packet.get_payload())  # Extract the IP packet

    # Check if the packet is an ICMP request
    if ip_packet.haslayer(ICMP):
        print(f"Dropping ICMP packet: {ip_packet.summary()}")
        packet.drop()  # Drop the packet
    else:
        print(f"Accepting packet: {ip_packet.summary()}")
        packet.accept()  # Accept the packet

# Create and bind the NetfilterQueue
nfqueue = NetfilterQueue()
nfqueue.bind(0, packet_handler)  # Queue number 0, use packet_handler

try:
    print("Listening for packets in NFQUEUE...")
    nfqueue.run()
except KeyboardInterrupt:
    print("Stopping...")
finally:
    nfqueue.unbind()


sudo nft flush ruleset
sudo nft add table inet filter
sudo nft add chain inet filter input { type filter hook input priority 0\; }
sudo nft add rule inet filter input ip protocol icmp queue num 0
