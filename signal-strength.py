import codecs
import argparse
from scapy.all import *
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

mac = ""
cnt = 0
plt.style.use('fivethirtyeight')

x_val = []
y_val = []

def handler(p):
    global cnt
    if not (p.haslayer(Dot11ProbeResp) or p.haslayer(Dot11ProbeReq) or p.haslayer(Dot11Beacon)):
        return

    rssi = p[RadioTap].dBm_AntSignal
    dst_mac = p[Dot11].addr1
    src_mac = p[Dot11].addr2
    ap_mac = p[Dot11].addr2
    
    if src_mac != mac:
        return
    
    cnt += 1
    info = f"rssi={rssi:2}dBm, dst={dst_mac}, src={src_mac}, ap={ap_mac}"

    if p.haslayer(Dot11ProbeResp):
        ssid = codecs.decode(p[Dot11Elt].info, 'utf-8')
        channel = ord(p[Dot11Elt:3].info)
        print(f"[ProbResp] {info}, chan={channel}, ssid=\"{ssid}\"")
    elif p.haslayer(Dot11ProbeReq):
        print(f"[ProbReq ] {info}")
    elif p.haslayer(Dot11Beacon):
        stats = p[Dot11Beacon].network_stats()
        ssid = str(stats['ssid'])
        channel = ord(p[Dot11Elt:3].info)
        interval = p[Dot11Beacon].beacon_interval
        print(f"[Beacon  ] {info}, chan={channel}, interval={interval}, ssid=\"{ssid}\"")


if __name__ == "__main__":
    
    argument = sys.argv
    del argument[0]
    print(f'Argument : {argument}')

    if len(argument) != 2:
        print("syntax : python signal-strength.py <interface> <mac>\nsample : signal-strength.py mon0 00:11:22:33:44:55")
        quit()
    mac = argument[1].lower()
    sniff(iface=argument[0], prn=handler, store=False)