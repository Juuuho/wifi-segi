import codecs
import argparse
from scapy.all import *
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import threading

mac = ""
interface = ""
cnt = 0
rssi = 0
ssid = ""

x_val = []
y_val = []
plt.style.use('fivethirtyeight')

class SIG_MONITOR(Thread):
    def __init__(self):
        Thread.__init__(self)
    def run(self):
        def handler(p):
            global cnt
            global rssi
            global x_val
            global y_val
            global ssid
            
            if not (p.haslayer(Dot11ProbeResp) or p.haslayer(Dot11ProbeReq) or p.haslayer(Dot11Beacon)):
                return

            rssi = p[RadioTap].dBm_AntSignal
            dst_mac = p[Dot11].addr1
            src_mac = p[Dot11].addr2
            ap_mac = p[Dot11].addr2
            
            if src_mac != mac:
                return

            cnt += 1
            x_val.append(cnt)
            y_val.append(rssi)
            info = f"rssi={rssi:2}dBm, dst={dst_mac}, src={src_mac}, ap={ap_mac}"
            
            # 디버깅
            if p.haslayer(Dot11ProbeResp):
                ssid = codecs.decode(p[Dot11Elt].info, 'utf-8')
            #     channel = ord(p[Dot11Elt:3].info)
            #     print(f"[ProbResp] {info}, chan={channel}, ssid=\"{ssid}\"")
            # elif p.haslayer(Dot11ProbeReq):
            #     print(f"[ProbReq ] {info}")
            elif p.haslayer(Dot11Beacon):
                stats = p[Dot11Beacon].network_stats()
                ssid = str(stats['ssid'])
                # channel = ord(p[Dot11Elt:3].info)
                # interval = p[Dot11Beacon].beacon_interval
                # print(f"[Beacon  ] {info}, chan={channel}, interval={interval}, ssid=\"{ssid}\"")
            
        global interface
        sniff(iface=argument[0], prn=handler, store=False)
    

def animate(i):
    global cnt
    global rssi
    plt.cla()
    plt.plot(x_val, y_val)
    plt.xlabel('Packet Count', fontsize=8)
    plt.ylim(-100, 0)
    plt.legend(['dBm'])
    plt.title('Target: '+ssid+"("+mac+")", fontsize=13)


if __name__ == "__main__":
    
    argument = sys.argv
    del argument[0]
    print(f'Argument : {argument}')

    if len(argument) != 2:
        print("syntax : python signal-strength.py <interface> <mac>\nsample : signal-strength.py mon0 00:11:22:33:44:55")
        quit()
    mac = argument[1].lower()
    
    sigmon = SIG_MONITOR()
    sigmon.start()
    
    ani = FuncAnimation(plt.gcf(), animate, interval = 100)
    plt.show()
    exit(0)
    