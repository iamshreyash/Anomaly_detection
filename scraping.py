import csv
import time
import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw, Ether

def packet_to_row(pkt):
    timestamp = pkt.time
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ''
    dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else ''
    src_ip = pkt[IP].src if pkt.haslayer(IP) else ''
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else ''
    proto = pkt[IP].proto if pkt.haslayer(IP) else ''
    ttl = pkt[IP].ttl if pkt.haslayer(IP) else ''
    total_len = pkt[IP].len if pkt.haslayer(IP) else len(pkt)
    src_port = pkt.sport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else ''
    dst_port = pkt.dport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else ''
    tcp_flags = pkt[TCP].flags if pkt.haslayer(TCP) else ''
    window = pkt[TCP].window if pkt.haslayer(TCP) else ''
    payload_size = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0

    return [
        timestamp, src_mac, dst_mac, src_ip, dst_ip, proto, ttl,
        total_len, src_port, dst_port, tcp_flags, window, payload_size
    ]

def log_message(message):
    with open("log.txt", "a") as log_file:
        log_file.write(f"{datetime.datetime.now()}: {message}\n")

def capture_packets(interface="Wi-Fi", total_duration_hrs=6, chunk_minutes=30):
    total_seconds = total_duration_hrs * 60 * 60
    chunk_seconds = chunk_minutes * 60
    end_time = time.time() + total_seconds
    file_counter =  1

    print(f"Starting packet capture on interface '{interface}' for {total_duration_hrs} hours.")
    
    while time.time() < end_time:
        filename = f"capture_{file_counter:03d}.csv"
        start_time = time.time()
        packets = sniff(timeout=chunk_seconds, iface=interface)

        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                'timestamp', 'src_mac', 'dst_mac', 'src_ip', 'dst_ip', 'protocol', 'ttl',
                'total_length', 'src_port', 'dst_port', 'tcp_flags', 'window', 'payload_size'
            ])
            for pkt in packets:
                if pkt.haslayer(IP):
                    writer.writerow(packet_to_row(pkt))
        
        log_message(f"Saved {filename} successfully at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[✓] {filename} written successfully.")

        file_counter += 1

    print("Capture complete.")

if __name__ == "__main__":
    capture_packets()
