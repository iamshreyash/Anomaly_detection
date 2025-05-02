import tkinter as tk
from tkinter import ttk, scrolledtext
import time
import pickle
import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, Raw, Ether
from sklearn.preprocessing import StandardScaler
import threading
from queue import Queue
from datetime import datetime

# Load models and preprocessing assets
isolation_forest = joblib.load('artifacts\\isolation_forest_model.pkl')
scaler = joblib.load('artifacts\\scaler.pkl')
with open('artifacts\\dummy_columns.pkl', 'rb') as f:
    dummy_columns = pickle.load(f)

numerical_features = ['ttl', 'total_length', 'window', 'payload_size', 'time_diff']
categorical_features = ['protocol', 'tcp_flags']

# Initialize previous timestamp for time_diff calculation
last_timestamp = None

# Queue for passing anomaly data to GUI
anomaly_queue = Queue()

def packet_to_features(pkt):
    global last_timestamp
    try:
        timestamp = pkt.time
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ''
        dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else ''
        src_ip = pkt[IP].src if pkt.haslayer(IP) else ''
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else ''
        proto = pkt[IP].proto if pkt.haslayer(IP) else ''
        ttl = pkt[IP].ttl if pkt.haslayer(IP) else ''
        total_len = pkt[IP].len if pkt.haslayer(IP) else len(pkt)
        src_port = pkt.sport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else 0
        dst_port = pkt.dport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else 0
        tcp_flags = pkt[TCP].flags if pkt.haslayer(TCP) else 'NONE'
        window = pkt[TCP].window if pkt.haslayer(TCP) else 0
        payload_size = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
        
        # Calculate time_diff
        current_time = pd.to_datetime(timestamp, unit='s', errors='coerce')
        if last_timestamp is None:
            time_diff = 0
        else:
            time_diff = (current_time - last_timestamp).total_seconds()
        last_timestamp = current_time

        # Build feature dictionary
        features = {
            'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'ttl': int(ttl) if ttl != '' else 0,
            'total_length': int(total_len),
            'window': int(window),
            'payload_size': int(payload_size),
            'time_diff': time_diff,
            'protocol': proto,
            'tcp_flags': str(tcp_flags) if tcp_flags != '' else 'NONE',
            'src_port': src_port,
            'dst_port': dst_port,
            'src_mac': src_mac,
            'dst_mac': dst_mac
        }
        return features
    except Exception as e:
        print(f"Error processing packet: {e}")
        return None

def preprocess_features(packet_features):
    numerical_features = ['ttl', 'total_length', 'window', 'payload_size', 'time_diff']
    categorical_features = ['tcp_flags', 'protocol']

    # Process numerical features
    df_num = pd.DataFrame([{k: packet_features[k] for k in numerical_features}])
    df_num_scaled = scaler.transform(df_num)
    df_num_scaled = pd.DataFrame(df_num_scaled, columns=numerical_features)

    # Process categorical features
    df_cat_raw = {
        'protocol': f"protocol_{packet_features['protocol']}",
        'tcp_flags': packet_features['tcp_flags']
    }
    df_cat = pd.DataFrame([df_cat_raw])
    df_cat = pd.get_dummies(df_cat)

    # Align with training dummy columns
    for col in dummy_columns:
        if col not in df_cat.columns:
            df_cat[col] = 0
    df_cat = df_cat[dummy_columns]

    # Combine numerical and categorical
    df_processed = pd.concat([df_num_scaled, df_cat], axis=1)
    df_processed.rename(columns={'protocol_6': 'protocol'}, inplace=True)
    return df_processed

def predict_packet(pkt):
    features = packet_to_features(pkt)
    if features is None:
        return

    X = preprocess_features(features)
    prediction = isolation_forest.predict(X)

    if prediction[0] == -1:
        print(f"______________[!] Anomaly Detected at______ {features['timestamp']}")
        anomaly_queue.put(features)

class AnomalyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Real-Time Network Anomaly Detection")
        self.root.geometry("1000x600")
        self.anomaly_count = 0

        # Main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Left frame for anomaly list and count
        self.left_frame = ttk.Frame(self.main_frame)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)

        # Anomaly count dashboard
        self.count_label = ttk.Label(self.left_frame, text="Anomalies Detected: 0", font=("Arial", 14, "bold"))
        self.count_label.pack(pady=10)

        # Anomaly list
        self.anomaly_listbox = tk.Listbox(self.left_frame, width=30, height=25)
        self.anomaly_listbox.pack(fill=tk.Y, expand=True)
        self.anomaly_listbox.bind("<<ListboxSelect>>", self.display_features)

        # Right frame for feature details
        self.right_frame = ttk.Frame(self.main_frame)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

        # Feature display
        self.feature_text = scrolledtext.ScrolledText(self.right_frame, wrap=tk.WORD, width=60, height=25)
        self.feature_text.pack(fill=tk.BOTH, expand=True)
        self.feature_text.config(state='disabled')

        # Stored anomalies for feature display
        self.anomalies = []

        # Start checking for new anomalies
        self.check_queue()

    def check_queue(self):
        while not anomaly_queue.empty():
            anomaly = anomaly_queue.get()
            self.anomaly_count += 1
            self.count_label.config(text=f"Anomalies Detected: {self.anomaly_count}")
            timestamp = anomaly['timestamp']
            self.anomaly_listbox.insert(tk.END, f"Anomaly at {timestamp}")
            self.anomalies.append(anomaly)
        self.root.after(100, self.check_queue)

    def display_features(self, event):
        selection = self.anomaly_listbox.curselection()
        if not selection:
            return
        index = selection[0]
        anomaly = self.anomalies[index]
        feature_str = "\n".join([f"{key}: {value}" for key, value in anomaly.items()])
        self.feature_text.config(state='normal')
        self.feature_text.delete(1.0, tk.END)
        self.feature_text.insert(tk.END, feature_str)
        self.feature_text.config(state='disabled')

def start_sniffing(interface="Wi-Fi"):
    print(f"Starting real-time packet sniffing on {interface}...")
    sniff(prn=predict_packet, iface=interface, store=0)

def run_sniffing():
    sniffing_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffing_thread.start()

if __name__ == "__main__":
    root = tk.Tk()
    app = AnomalyGUI(root)
    # Start sniffing in a separate thread
    threading.Thread(target=run_sniffing, daemon=True).start()
    root.mainloop()