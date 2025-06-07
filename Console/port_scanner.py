import subprocess
import ipaddress
from colorama import Fore

def is_valid_ip(target_ip):
    try:
        ipaddress.ip_address(target_ip)
        return True
    except ValueError:
        return False

def nmap_port_scan(target_ip, port_range, debug_mode=False):
    # Il n'est pas nécessaire de boucler ici car nous ne prenons pas l'entrée de l'utilisateur dans cette fonction.
    try:
        # Exécute la commande nmap pour le scan de ports
        cmd = ["nmap", "-p", port_range, target_ip]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        # Affiche la sortie de la commande nmap
        print(result.stdout)

        # Analyse de la sortie nmap pour extraire les ports ouverts
        open_ports = []
        lines = result.stdout.split('\n')
        for line in lines:
            if "/tcp" in line:
                parts = line.split("/")
                open_ports.append(int(parts[0]))

        return open_ports

    except subprocess.CalledProcessError as e:
        # En cas d'erreur, affiche le message d'erreur
        print(f"Erreur lors du scan de ports : {e.stderr}")
        return []
