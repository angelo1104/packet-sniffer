import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=handle_packets)


def handle_packets(packet):
    if http.HTTPRequest in packet:
        # http packet.
        print(packet)
    elif scapy.TCP in packet:
        if packet[scapy.TCP].dport == 443:
            # ssl packet.
            print(packet)


def geturl(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


sniff('wlp2s0')
