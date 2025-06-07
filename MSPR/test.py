import psutil
from scapy.all import ARP, Ether, srp
import socket
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json

def choose_interface():
    try:
        interfaces = psutil.net_if_addrs()
        for index, name in enumerate(interfaces, 1):
            print(f"{index}: {name}")
        choice = int(input("Choisissez une interface (numéro): "))
        selected_interface = list(interfaces.keys())[choice - 1]
        return selected_interface
    except (ValueError, IndexError):
        print("Choix invalide. Veuillez sélectionner une interface valide.")
        return choose_interface()

def get_network_info(interface):
    try:
        addrs = psutil.net_if_addrs()[interface]
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.address, addr.netmask
        return None, None
    except KeyError:
        print("L'interface sélectionnée n'existe pas.")
        return None, None

def get_ip_range(ip, netmask):
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    return [str(ip) for ip in network.hosts()]

def scan_network(interface):
    ip, netmask = get_network_info(interface)
    if not ip or not netmask:
        return []

    ip_range = get_ip_range(ip, netmask)
    arp_request_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered = srp(arp_request_broadcast, timeout=2, iface=interface, verbose=False)[0]
    return [{'ip': recv.psrc, 'mac': recv.hwsrc} for send, recv in answered]

def check_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            return sock.connect_ex((ip, port)) == 0
    except socket.error:
        return False

def scan_ports(ip):
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_port, ip, port) for port in range(1, 1025)]
        open_ports = [port for port, future in enumerate(futures, start=1) if future.result()]
        return open_ports

if __name__ == "__main__":
    interface = choose_interface()
    devices = scan_network(interface)

    # Ouvrir le fichier en mode écriture pour commencer un nouveau fichier JSON
    with open('scan_results.json', 'w') as file:
        file.write('[')  # Début de la liste JSON

    print(f"Scanning on interface {interface}...")
    for count, device in enumerate(devices):
        ip = device['ip']
        mac = device['mac']
        print(f"Scanning IP: {ip}, MAC: {mac}")
        open_ports = scan_ports(ip)
        print(f"IP: {ip}, MAC: {mac}, Ports ouverts: {open_ports}")

        result = {'ip': ip, 'mac': mac, 'open_ports': open_ports}
        with open('scan_results.json', 'a') as file:
            json.dump(result, file, indent=4)
            # Ajouter une virgule sauf pour le dernier élément
            if count < len(devices) - 1:
                file.write(',')

    # Fermer la liste JSON à la fin du script
    with open('scan_results.json', 'a') as file:
        file.write(']')

    print("Analyse terminée. Les résultats ont été enregistrés dans 'scan_results.json'.")