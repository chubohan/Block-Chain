from scapy.all import get_if_addr, conf , sniff, IP, TCP, UDP, ICMP 
import logging
from logging.handlers import RotatingFileHandler
import time
import threading
import os
from collections import deque

# ========== 日誌設定 ==========
log_handler = RotatingFileHandler("firewall.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s", handlers=[log_handler])

# ========== 規則與狀態 ==========
ALLOWED_IPS = set()         # 顯式允許的來源 IP
BLOCKED_PORTS = set()       # 阻擋的目標 port
BLOCKED_IPS = {}            # 被封鎖的 IP : 解封時間 (timestamp)。若值為 None 則永久封鎖
TRACKED_CONNECTIONS = {}    # 連線追蹤 (conn_id -> last_seen_timestamp)

# 自動封鎖設定（可透過 CLI 調整）
AUTO_BLOCK_ENABLED = True
ATTEMPT_THRESHOLD = 20      # 閾值：time_window 內嘗試次數超過此值會封鎖
TIME_WINDOW = 10.0          # 時窗 (秒)
BLOCK_DURATION = 300.0      # 封鎖持續時間 (秒)，0 或 None 表示永久封鎖

# 追蹤來源 IP 嘗試次數：src_ip -> deque([timestamps])
CONN_ATTEMPTS = {}

# 本機資訊與鎖
LOCAL_IP = get_if_addr(conf.iface)
state_lock = threading.Lock()

# ===== 工具函數 =====
def now():
    return time.time()

def add_allowed_ip(ip):
    with state_lock:
        ALLOWED_IPS.add(ip)
    logging.info(f"添加允許的 IP: {ip}")

def remove_allowed_ip(ip):
    with state_lock:
        if ip in ALLOWED_IPS:
            ALLOWED_IPS.remove(ip)
            logging.info(f"移除允許的 IP: {ip}")

def add_blocked_port(port):
    with state_lock:
        BLOCKED_PORTS.add(port)
    logging.info(f"添加阻止的端口: {port}")

def remove_blocked_port(port):
    with state_lock:
        if port in BLOCKED_PORTS:
            BLOCKED_PORTS.remove(port)
            logging.info(f"移除阻止的端口: {port}")

def block_ip(ip, duration=None):
    """封鎖 IP，duration 秒後自動解封；duration None 或 0 表示永久封鎖"""
    unban_at = None
    if duration and duration > 0:
        unban_at = now() + duration
    with state_lock:
        BLOCKED_IPS[ip] = unban_at
    logging.warning(f"自動封鎖 IP {ip}，持續: {duration if duration else '永久'} 秒")

def unblock_ip(ip):
    with state_lock:
        if ip in BLOCKED_IPS:
            del BLOCKED_IPS[ip]
            logging.info(f"手動/自動解封 IP: {ip}")

def track_connection(src_ip, dst_ip, src_port, dst_port, protocol):
    conn_id = (src_ip, dst_ip, src_port, dst_port, protocol)
    with state_lock:
        TRACKED_CONNECTIONS[conn_id] = now()
    logging.info(f"追蹤連線: {conn_id}")

def record_attempt_and_maybe_block(src_ip):
    """紀錄來源嘗試，並視閾值自動封鎖"""
    if not AUTO_BLOCK_ENABLED:
        return

    t = now()
    with state_lock:
        dq = CONN_ATTEMPTS.get(src_ip)
        if dq is None:
            dq = deque()
            CONN_ATTEMPTS[src_ip] = dq
        dq.append(t)
        # 清除過期記錄
        while dq and (t - dq[0]) > TIME_WINDOW:
            dq.popleft()
        # 檢查閾值
        if len(dq) >= ATTEMPT_THRESHOLD:
            # 封鎖該 IP，並清空嘗試記錄以避免重複 log
            block_ip(src_ip, duration=BLOCK_DURATION)
            dq.clear()

def cleanup_blocked_ips_loop():
    """背景執行：定期檢查到期的封鎖並解封，並清理舊的 attempt 記錄"""
    while True:
        time.sleep(5)
        t = now()
        with state_lock:
            # 解封到期 IP
            to_unblock = [ip for ip, unban in BLOCKED_IPS.items() if unban and unban <= t]
            for ip in to_unblock:
                del BLOCKED_IPS[ip]
                logging.info(f"到期自動解封 IP: {ip}")

            # 清理非常舊的嘗試記錄（例如 > 2 * TIME_WINDOW）
            cutoff = t - (2 * TIME_WINDOW)
            for ip, dq in list(CONN_ATTEMPTS.items()):
                while dq and dq[0] < cutoff:
                    dq.popleft()
                if not dq:
                    del CONN_ATTEMPTS[ip]

# ===== 封包過濾邏輯 =====
def packet_filter(pkt):
    if not pkt.haslayer(IP):
        return None

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    # 避免處理本機自己送出的封包，減少迴圈
    if src_ip == LOCAL_IP:
        return None

    with state_lock:
        # 檢查是否已被封鎖
        if src_ip in BLOCKED_IPS:
            return None

        # 如果 not ALLOW_ALL 且來源 IP 未在允許清單，阻擋
        if ALLOWED_IPS and src_ip not in ALLOWED_IPS:
            logging.warning(f"阻擋未授權來源 IP: {src_ip}")
            return None

    protocol = None
    src_port = None
    dst_port = None

    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            protocol = "TCP"
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = "UDP"

        # 阻擋特定目標 port
        with state_lock:
            if dst_port in BLOCKED_PORTS:
                logging.warning(f"阻擋目標端口 {dst_port} 的封包 (來自 {src_ip})")
                # 記錄嘗試（可能是探測/掃描）
                record_attempt_and_maybe_block(src_ip)
                return None

        # 新連線追蹤 & 嘗試記錄
        conn_id = (src_ip, dst_ip, src_port, dst_port, protocol)
        with state_lock:
            if conn_id not in TRACKED_CONNECTIONS:
                TRACKED_CONNECTIONS[conn_id] = now()
        # 記錄嘗試（不論是否已追蹤）
        record_attempt_and_maybe_block(src_ip)
        return pkt

    # ICMP 處理（例如 ping）
    if pkt.haslayer(ICMP):
        protocol = "ICMP"
        track_connection(src_ip, dst_ip, None, None, protocol)
        # 記錄嘗試（ICMP 也視為一種探測）
        record_attempt_and_maybe_block(src_ip)
        return pkt

    return None

# ===== 封包處理函數 =====
def process_packet(pkt):
    allowed = packet_filter(pkt)
    if allowed:
        logging.info(f"允許封包: {pkt.summary()}")
    else:
        logging.info(f"丟棄封包: {pkt.summary()}")

# ===== 啟動嗅探 =====
def start_firewall():
    print("🔥 防火牆啟動中... 按 Ctrl+C 停止")
    sniff(filter="ip", prn=process_packet, store=0)  # 只嗅 IP

# ===== CLI 管理 =====
def firewall_cli():
    global AUTO_BLOCK_ENABLED, ATTEMPT_THRESHOLD, TIME_WINDOW, BLOCK_DURATION
    while True:
        print("\n=== 防火牆命令 ===")
        print("1. 添加允許的 IP")
        print("2. 移除允許的 IP")
        print("3. 添加阻止的端口")
        print("4. 移除阻止的端口")
        print("5. 顯示當前規則與狀態")
        print("6. 切換自動封鎖 (目前: {})".format("啟用" if AUTO_BLOCK_ENABLED else "停用"))
        print("7. 設定自動封鎖參數 (threshold / time_window / block_duration)")
        print("8. 手動解封 IP")
        print("9. 退出")
        choice = input("請輸入選項: ").strip()

        if choice == "1":
            ip = input("輸入 IP: ").strip()
            add_allowed_ip(ip)
        elif choice == "2":
            ip = input("輸入 IP: ").strip()
            remove_allowed_ip(ip)
        elif choice == "3":
            port = int(input("輸入 port: ").strip())
            add_blocked_port(port)
        elif choice == "4":
            port = int(input("輸入 port: ").strip())
            remove_blocked_port(port)
        elif choice == "5":
            with state_lock:
                print("本機 IP:", LOCAL_IP)
                print("允許 IP:", ALLOWED_IPS if ALLOWED_IPS else "（空，代表所有來源允許）")
                print("阻擋 port:", BLOCKED_PORTS)
                print("被封鎖 IP:", {ip: ('永久' if unban is None else time.ctime(unban)) for ip, unban in BLOCKED_IPS.items()})
                print("追蹤連線筆數:", len(TRACKED_CONNECTIONS))
                print("嘗試記錄筆數:", {ip: len(dq) for ip, dq in CONN_ATTEMPTS.items()})
                print("自動封鎖:", AUTO_BLOCK_ENABLED)
                print(f"threshold={ATTEMPT_THRESHOLD}, time_window={TIME_WINDOW}s, block_duration={BLOCK_DURATION}s")
        elif choice == "6":
            with state_lock:
                AUTO_BLOCK_ENABLED = not AUTO_BLOCK_ENABLED
            logging.info(f"自動封鎖已{'啟用' if AUTO_BLOCK_ENABLED else '停用'}")
        elif choice == "7":
            thr = input(f"輸入 threshold（目前 {ATTEMPT_THRESHOLD}）: ").strip()
            tw = input(f"輸入 time_window 秒（目前 {TIME_WINDOW}）: ").strip()
            bd = input(f"輸入 block_duration 秒（0 表示永久，目前 {BLOCK_DURATION}）: ").strip()
            try:
                with state_lock:
                    ATTEMPT_THRESHOLD = int(thr) if thr else ATTEMPT_THRESHOLD
                    TIME_WINDOW = float(tw) if tw else TIME_WINDOW
                    BLOCK_DURATION = float(bd) if bd else BLOCK_DURATION
                logging.info(f"更新自動封鎖參數: threshold={ATTEMPT_THRESHOLD}, time_window={TIME_WINDOW}, block_duration={BLOCK_DURATION}")
            except ValueError:
                print("輸入格式錯誤，請輸入數字。")
        elif choice == "8":
            ip = input("輸入要解封的 IP: ").strip()
            unblock_ip(ip)
        elif choice == "9":
            print("退出")
            os._exit(0)
        else:
            print("無效選項")

# ===== 主程序 =====
if __name__ == "__main__":
    # 啟動背景清理執行緒
    threading.Thread(target=cleanup_blocked_ips_loop, daemon=True).start()
    # 啟動嗅探執行緒（daemon，讓 CLI 可控制程序存活）
    threading.Thread(target=start_firewall, daemon=True).start()
    # 啟動 CLI（主線程）
    firewall_cli()