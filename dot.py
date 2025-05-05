import matplotlib.pyplot as plt
import pyshark
from collections import defaultdict
import time
import threading

def analyze_pcap(pcap_file):
    # 每 1 秒為一個區間，紀錄來源 IP 與其目標 IP
    windows = defaultdict(lambda: defaultdict(set))
    
    cap = pyshark.FileCapture(pcap_file, display_filter="ip")
    for pkt in cap:
        try:
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            t = int(float(pkt.sniff_time.timestamp()))
            win_index = t // 10  # 10 秒統計一次
            windows[win_index][src_ip].add(dst_ip)
        except AttributeError:
            continue
    
    cap.close()
    
    # 準備繪圖資料：x 軸(每個 1 秒區間)，y 軸(目標 IP 數量)
    time_points = sorted(windows.keys())
    data_per_ip = defaultdict(list)
    
    for w in time_points:
        for ip in windows[w]:
            count_dst = len(windows[w][ip])
            data_per_ip[ip].append((w, count_dst))  # x 軸保持秒數
    
    # 繪圖：針對每個 IP 生成散點圖
    plt.figure(figsize=(10, 6))
    for ip, data in data_per_ip.items():
        x_vals = [d[0] for d in data]
        y_vals = [d[1] for d in data]
        plt.scatter(x_vals, y_vals, s=10, alpha=0.5)
        
    
    max_count = max(y for ip_data in data_per_ip.values() for _, y in ip_data)
    y_ticks = list(range(1000, (max_count // 1000 + 1) * 1000 + 1, 1000))
    plt.yticks(y_ticks)

    plt.axhline(y=2000, color='r', linestyle='--', label='Threshold') #Threshold畫線
    plt.xlabel('Time (seconds)')
    plt.ylabel('Distinct Destination IPs')
    plt.title('Distinct Destination IPs per 10s Window (date)')
    plt.show()

def print_status():
    while True:
        print("程式正在執行中...")
        time.sleep(60)  # 每 60 秒輸出一次

if __name__ == "__main__":
    pcap_file = '輸入檔案路徑'
    
    # 啟動 print_status 執行緒
    status_thread = threading.Thread(target=print_status)
    status_thread.daemon = True
    status_thread.start()
    
    # 在另一個執行緒中執行 analyze_pcap
    analyze_thread = threading.Thread(target=analyze_pcap, args=(pcap_file,))
    analyze_thread.start()
    
    # 等待 analyze_pcap 執行緒完成
    analyze_thread.join()