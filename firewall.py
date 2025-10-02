from scapy.all import *
import logging
import time
import threading

# 配置日誌
logging.basicConfig(filename="firewall.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# 防火牆規則存儲
ALLOWED_IPS = set()  # 允許的 IP 地址
BLOCKED_PORTS = set()  # 阻止的端口
TRACKED_CONNECTIONS = {}  # 連線追蹤字典

# 動態管理規則函數
def add_allowed_ip(ip):
    ALLOWED_IPS.add(ip)
    logging.info(f"添加允許的 IP: {ip}")

def remove_allowed_ip(ip):
    if ip in ALLOWED_IPS:
        ALLOWED_IPS.remove(ip)
        logging.info(f"移除允許的 IP: {ip}")

def add_blocked_port(port):
    BLOCKED_PORTS.add(port)
    logging.info(f"添加阻止的端口: {port}")

def remove_blocked_port(port):
    if port in BLOCKED_PORTS:
        BLOCKED_PORTS.remove(port)
        logging.info(f"移除阻止的端口: {port}")

# 連線追蹤函數
def track_connection(src_ip, dst_ip, src_port, dst_port, protocol):
    conn_id = (src_ip, dst_ip, src_port, dst_port, protocol)
    if conn_id not in TRACKED_CONNECTIONS:
        TRACKED_CONNECTIONS[conn_id] = time.time()
        logging.info(f"新連線: {conn_id} 已被追蹤")
    else:
        TRACKED_CONNECTIONS[conn_id] = time.time()

# 資料包過濾函數
def packet_filter(pkt):
    if not pkt.haslayer(IP):
        return None  # 非 IP 包直接跳過

    # 獲取源 IP 和目標 IP
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    # 如果源 IP 不在允許列表中，則丟棄
    if src_ip not in ALLOWED_IPS:
        logging.warning(f"阻止來自未授權源 IP {src_ip} 的流量")
        return None

    # 獲取 TCP/UDP 層
    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        # 獲取源端口和目標端口
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            protocol = "TCP"
        else:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = "UDP"

        # 如果目標端口在阻止的端口列表中，則丟棄
        if dst_port in BLOCKED_PORTS:
            logging.warning(f"阻止目標端口 {dst_port} 的流量")
            return None

        # 如果是新的連線，進行連線追蹤
        track_connection(src_ip, dst_ip, src_port, dst_port, protocol)

        # 如果是已經建立的連線，則允許通過
        if (src_ip, dst_ip, src_port, dst_port, protocol) in TRACKED_CONNECTIONS:
            return pkt  # 允許通過

    return None  # 丟棄資料包

# 資料包處理函數
def process_packet(pkt):
    filtered_pkt = packet_filter(pkt)
    if filtered_pkt:
        send(filtered_pkt)  # 允許資料包通過
    else:
        logging.warning(f"丟棄資料包: {pkt.summary()}")

# 啟動嗅探並處理網絡流量
def start_firewall():
    print("防火牆已啟動，正在監控網絡流量...")
    sniff(prn=process_packet, store=0)  # 不需要指定 socket 參數

# 防火牆命令行界面
def firewall_cli():
    while True:
        print("\n防火牆管理命令：")
        print("1. 添加允許的 IP")
        print("2. 移除允許的 IP")
        print("3. 添加阻止的端口")
        print("4. 移除阻止的端口")
        print("5. 顯示當前規則")
        print("6. 啟動防火牆")
        print("7. 退出")
        
        choice = input("請輸入命令選項: ")

        if choice == "1":
            ip = input("請輸入要添加的 IP 地址: ")
            add_allowed_ip(ip)
        elif choice == "2":
            ip = input("請輸入要移除的 IP 地址: ")
            remove_allowed_ip(ip)
        elif choice == "3":
            port = int(input("請輸入要添加的端口: "))
            add_blocked_port(port)
        elif choice == "4":
            port = int(input("請輸入要移除的端口: "))
            remove_blocked_port(port)
        elif choice == "5":
            print("當前規則：")
            print("允許的 IP 地址: ", ALLOWED_IPS)
            print("阻止的端口: ", BLOCKED_PORTS)
            print("連線追蹤: ", TRACKED_CONNECTIONS)
        elif choice == "6":
            start_firewall()
        elif choice == "7":
            print("退出防火牆管理")
            break
        else:
            print("無效的命令")

# 啟動防火牆 CLI
firewall_cli()
