from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP
import threading

app = Flask(__name__)
socketio = SocketIO(app)

capture_thread = None
stop_sniffing = False
captured_packets = []

def process_packet(packet):
    if IP in packet:
        packet_info = {
            "ip_src": packet[IP].src,
            "ip_dst": packet[IP].dst,
            "protocol": "IP"
        }
        if TCP in packet:
            packet_info["protocol"] = "TCP"
            packet_info["src_port"] = packet[TCP].sport
            packet_info["dst_port"] = packet[TCP].dport
        elif UDP in packet:
            packet_info["protocol"] = "UDP"
            packet_info["src_port"] = packet[UDP].sport
            packet_info["dst_port"] = packet[UDP].dport
        captured_packets.append(packet_info)
        socketio.emit('new_packet', packet_info)

def sniff_packets():
    global stop_sniffing
    stop_sniffing = False
    sniff(filter="ip", prn=process_packet, stop_filter=lambda x: stop_sniffing, iface="en0", promisc=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start')
def start_capture():
    global capture_thread
    if capture_thread and capture_thread.is_alive():
        return jsonify({"status": "Capture already running"})
    capture_thread = threading.Thread(target=sniff_packets)
    capture_thread.start()
    return jsonify({"status": "Capture started"})

@app.route('/stop')
def stop_capture():
    global stop_sniffing
    stop_sniffing = True
    if capture_thread:
        capture_thread.join()
    return jsonify({"status": "Capture stopped"})

@app.route('/search', methods=['GET'])
def search_packets():
    ip = request.args.get('ip')
    port = request.args.get('port')
    protocol = request.args.get('protocol')

    filtered_packets = captured_packets

    if ip:
        filtered_packets = [p for p in filtered_packets if p["ip_src"] == ip or p["ip_dst"] == ip]
    
    if port:
        filtered_packets = [p for p in filtered_packets if str(p.get("src_port")) == port or str(p.get("dst_port")) == port]

    if protocol:
        filtered_packets = [p for p in filtered_packets if p["protocol"] == protocol]

    return jsonify(filtered_packets)

if __name__ == '__main__':
    socketio.run(app, debug=True)
