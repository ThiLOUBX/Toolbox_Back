import psutil
from scapy.all import ARP, Ether, srp
import socket
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json

def choose_interface():
  data=[]
  interfaces = psutil.net_if_addrs()
  for index, name in enumerate(interfaces,1):
    data.append({'index':index,'interfaces':name}) 
  return data

#def get_network_info(interface):
 #   try:
  #      addrs = psutil.net_if_addrs()[interface]
   #     result = {}
    #    for addr in addrs:
     #       if addr.family == socket.AF_INET:
      #          result['address'] = addr.address
       #         result['netmask'] = addr.netmask
        #return jsonify(result)
    #except KeyError:
     #   print("L'interface sélectionnée n'existe pas.")
      #  return jsonify({'error': 'L\'interface sélectionnée n\'existe pas.'})

def get_network_info(interface):
    try:
        addrs = psutil.net_if_addrs()[interface]
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return {'ip_add':addr.address,'network_host':addr.netmask}
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

#if __name__ == "__main__":
    #interface = choose_interface()
   # devices = scan_network(interface)
  #  scan_results = []

 #   print(f"Scanning on interface {interface}...")
#    for device in devices:
        #ip = device['ip']  # Extraire l'adresse IP du dictionnaire
       # mac = device['mac']
      #  print(f"Scanning IP: {ip}, MAC: {mac}")
     #   open_ports = scan_ports(ip)  # Passez l'adresse IP à scan_ports
    #    print(f"IP: {ip}, MAC: {mac}, Ports ouverts: {open_ports}")
   #     scan_results.append({'ip': ip, 'mac': mac, 'open_ports': open_ports})

  #  with open('scan_results.json', 'w') as file:
 #       json.dump(scan_results, file, indent=4)
#
#    print("Analyse terminée. Les résultats ont été enregistrés dans 'scan_results.json'.")
