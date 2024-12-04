from netfilterqueue import NetfilterQueue
from scapy.all import IP

def packet_handler(packet):
    ip_packet = IP(packet.get_payload())
    print(f"Packet: {ip_packet.summary()}")
    
    # Example: Drop all packets
    if ip_packet.haslayer(IP) and ip_packet[IP].proto == 1:  # ICMP
        print("Dropping ICMP packet.")
        packet.drop()
    else:
        packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, packet_handler)

try:
    print("Waiting for packets...")
    nfqueue.run()
except KeyboardInterrupt:
    print("Stopping...")
finally:
    nfqueue.unbind()
