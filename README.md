# wifiscan

Это инструмент сканирует локальная сеть на открытые порты IP адресов

Запуск: python wifiscan.py

Если IP другой измините в коде

def main():
    ip_range = "192.168.1.0/24"  # Укажите диапазон вашей локальной сети
    devices = scan_network(ip_range)
