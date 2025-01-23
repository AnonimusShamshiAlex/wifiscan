import socket
from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    # Сканируем сеть для получения IP и MAC адресов
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def scan_ports(ip):
    open_ports = []
    for port in range(1, 3390):  # Сканируем все порты от 1 до 65535
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown"

def main():
    ip_range = "192.168.1.0/24"  # Укажите диапазон вашей локальной сети
    devices = scan_network(ip_range)

    for device in devices:
        ip = device['ip']
        mac = device['mac']
        print(f"IP: {ip}, MAC: {mac}")
        open_ports = scan_ports(ip)
        for port in open_ports:
            service_name = get_service_name(port)
            print(f"  Open Port: {port} ({service_name})")

if __name__ == "__main__":
    main()
