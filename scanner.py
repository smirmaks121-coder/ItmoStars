import socket
import subprocess
import re
import os
from concurrent.futures import ThreadPoolExecutor

# Расширенная база знаний об угрозах портов для экспертного отчета
PORT_INTELLIGENCE = {
    21: {
        "service": "FTP (Устаревший протокол передачи файлов)",
        "threat": "Пароли и файлы передаются внутри сети в открытом (незашифрованном) виде. Хакер может перехватить их с помощью сниффера.",
        "fix": "Отключите службу FTP в настройках устройства или замените её на защищенный аналог SFTP/SCP."
    },
    22: {
        "service": "SSH (Безопасный удаленный доступ)",
        "threat": "Служба защищена, однако открытый порт в локальной сети часто становится целью для автоматических атак перебора паролей (Brute Force).",
        "fix": "Убедитесь, что для доступа используется сложный пароль или авторизация по SSH-ключам. Измените стандартный порт 22 на нестандартный."
    },
    23: {
        "service": "Telnet (Крайне опасный удаленный терминал)",
        "threat": "Критическая уязвимость архитектуры. Любые команды управления и учетные данные передаются текстовым потоком.",
        "fix": "Категорически рекомендуется полностью выключить Telnet на устройстве. Используйте исключительно SSH."
    },
    80: {
        "service": "HTTP (Незащищенный веб-интерфейс)",
        "threat": "Панель управления (админка роутера или камеры) доступна без шифрования. Риск компрометации сессии администратора.",
        "fix": "Включите в настройках устройства обязательное перенаправление на защищенный протокол HTTPS."
    },
    443: {
        "service": "HTTPS (Защищенный веб-интерфейс)",
        "threat": "Служба использует шифрование. Риск минимален, однако уязвимость может крыться в устаревшей версии прошивки самого устройства.",
        "fix": "Регулярно проверяйте и устанавливайте обновления программного обеспечения (firmware) данного узла."
    },
    3389: {
        "service": "RDP (Удаленный рабочий стол Windows)",
        "threat": "Излюбленная цель хакеров и вирусов-вымогателей. Открытый порт RDP без должной защиты ведет к полному захвату контроля над ПК.",
        "fix": "Ограничьте доступ к RDP на уровне брандмауэра Windows, используйте Network Level Authentication (NLA) или подключайтесь строго через VPN."
    }
}

VENDOR_DB = {
    "78:17:be": "Keenetic / Zyxel (Роутер)",
    "00:11:22": "Ubiquiti Networks",
    "b4:f1:da": "Apple (iPhone/Mac)",
    "f4:d4:88": "Apple (MacBook/iPad)",
    "e2:3a:ee": "Samsung Electronics",
    "f4:5c:89": "Xiaomi Communications",
    "00:e0:4c": "Realtek Semiconductor",
    "c4:ad:34": "Huawei Technologies",
    "ff:ff:ff": "Broadcast"
}

BASELINE_FILE = "network_baseline.txt"

def get_vendor(mac):
    if not mac or ":" not in mac:
        return "Generic Device (IoT/ПК)"
    prefix = ":".join(mac.lower().strip().split(":")[:3])
    for key, vendor in VENDOR_DB.items():
        if prefix.startswith(key.lower()):
            return vendor
    return "Generic Device (IoT/ПК)"

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

def check_host_and_os(ip):
    ports_to_check = [21, 22, 23, 80, 443, 3389]
    for port in ports_to_check:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.06)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                    if ttl <= 64:
                        os_guess = "Linux / Android / iOS"
                    elif ttl <= 128:
                        os_guess = "Windows OS"
                    else:
                        os_guess = "Сетевое оборудование"
                except Exception:
                    os_guess = "Не определено (Фильтрация трафика)"
                sock.close()
                return {"ip": ip, "os": os_guess}
        except Exception:
            pass
        sock.close()
    return None

def scan_ports(ip):
    open_ports = []
    for port, info in PORT_INTELLIGENCE.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.12)
        if sock.connect_ex((ip, port)) == 0:
            open_ports.append({
                "port": port, 
                "service": info["service"],
                "threat": info["threat"],
                "fix": info["fix"]
            })
        sock.close()
    return open_ports

def get_arp_table():
    arp_table = []
    try:
        arp_output = subprocess.check_output(["arp", "-an"]).decode("utf-8")
        for line in arp_output.splitlines():
            match = re.search(r"\((.*?)\) at (.*?) on", line)
            if match:
                ip_addr = match.group(1)
                mac_addr = match.group(2)
                if "incomplete" not in mac_addr:
                    parts = [p.zfill(2) for p in mac_addr.split(":")]
                    normalized_mac = ":".join(parts)
                    arp_table.append({"ip": ip_addr, "mac": normalized_mac})
    except Exception:
        pass
    return arp_table

def detect_arp_spoofing(arp_entries):
    mac_seen = {}
    alerts = []
    for entry in arp_entries:
        ip = entry["ip"]
        mac = entry["mac"]
        if mac in mac_seen and mac_seen[mac] != ip:
            alerts.append({
                "type": "ARP-Spoofing",
                "message": f"КРИТИЧЕСКАЯ АТАКА MITM: Обнаружен конфликт адресов! MAC-адрес [{mac}] одновременно принадлежит узлам {ip} и {mac_seen[mac]}."
            })
        else:
            mac_seen[mac] = ip
    return alerts

def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return None
    with open(BASELINE_FILE, "r") as f:
        return set(line.strip().lower() for line in f if line.strip())

def save_baseline(mac_list):
    with open(BASELINE_FILE, "w") as f:
        for mac in mac_list:
            if mac and ":" in mac:
                f.write(f"{mac.lower().strip()}\n")

def calculate_security_score(devices, alerts, is_first_run):
    """Интеллектуальный расчет индекса безопасности (0-100%)."""
    score = 100
    
    # Штраф за критические сетевые атаки
    if alerts:
        score -= 40
        
    # Штраф за чужие устройства (только если белый список уже создан)
    if not is_first_run:
        rogue_count = sum(1 for d in devices if d['status'] == 'rogue')
        score -= (rogue_count * 15)
        
    # Страховка границ
    if score < 0: score = 0
    return score

def scan_network():
    local_ip = get_local_ip()
    if local_ip == '127.0.0.1':
        return {"devices": [], "alerts": [], "score": 0, "first_run": True, "macs": []}

    arp_entries = get_arp_table()
    devices_dict = {entry["ip"]: {"mac": entry["mac"], "os": "IoT / Умное устройство"} for entry in arp_entries}

    security_alerts = detect_arp_spoofing(arp_entries)

    ip_parts = local_ip.split('.')
    base_net = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."
    ips_to_scan = [f"{base_net}{i}" for i in range(1, 255)]

    with ThreadPoolExecutor(max_workers=60) as executor:
        results = executor.map(check_host_and_os, ips_to_scan)
        for res in results:
            if res and res["ip"] != local_ip:
                if res["ip"] in devices_dict:
                    devices_dict[res["ip"]]["os"] = res["os"]
                else:
                    devices_dict[res["ip"]] = {"mac": "00:00:00:00:00:00", "os": res["os"]}

    baseline = load_baseline()
    is_first_run = (baseline is None)
    current_macs = []

    devices = []
    for ip, info in devices_dict.items():
        mac = info["mac"]
        current_macs.append(mac)
        vendor_name = get_vendor(mac)
        
        status_tag = "verified"
        if not is_first_run and mac.lower() not in baseline and mac != "00:00:00:00:00:00":
            status_tag = "rogue"
            security_alerts.append({
                "type": "Rogue-Device",
                "message": f"ОБНАРУЖЕНО НЕИЗВЕСТНОЕ УСТРОЙСТВО в сети: IP {ip}, MAC [{mac}]. Возможно несанкционированное подключение!"
            })

        devices.append({
            'ip': ip, 
            'mac': mac, 
            'hostname': vendor_name,
            'os': info["os"],
            'status': status_tag
        })

    devices.append({
        'ip': local_ip, 
        'mac': '00:00:00:00:00:00 (Self)', 
        'hostname': 'Ваш MacBook Pro (Хост-инспектор)',
        'os': 'macOS (Darwin)',
        'status': 'verified'
    })
    
    devices.sort(key=lambda x: [int(num) for num in x['ip'].split('.') if num.isdigit()])
    
    # Считаем итоговый скоринг
    score = calculate_security_score(devices, security_alerts, is_first_run)
    
    return {"devices": devices, "alerts": security_alerts, "first_run": is_first_run, "macs": current_macs, "score": score}
