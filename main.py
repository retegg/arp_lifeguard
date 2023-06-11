from scapy.all import Ether, ARP, srp, sniff, send
import json
from flask import Flask, render_template
import threading

hacked = False
hack_mac = ""
sniff_thread = None  # Global variable to hold the sniffing thread

with open('config.json', 'r') as f:
    config = json.load(f)

def get_mac():
    global hacked
    if hacked:
        global hack_mac
        print("hacked")
        return hack_mac
    else:
        ip = "192.168.1.1"
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
        result = srp(packet, timeout=5, verbose=False)
        response_packets, _ = result
        for _, packet in response_packets:
            arp_response = packet[ARP]
            print(arp_response.hwsrc)
            return arp_response.hwsrc
        

def get_devices_on_network():
    ip_range = "192.168.1.0/24"
    # Create an ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

    # Send the packet and capture the responses
    result = srp(arp_request, timeout=3,  verbose=False)[0]

    # Process the responses
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices
def arp_spoof_check(packet):
    global hacked
    global hack_mac
    if packet[ARP].op == 2:  # Filter ARP response packets
        mac_address = packet[ARP].hwsrc  # Extract MAC address from ARP response
        ip_address = packet[ARP].psrc  # Extract IP address from ARP response
        print(f"MAC: {mac_address} - IP: {ip_address}")
        if ip_address == "192.168.1.1" and mac_address != config.get('mac'):
            hacked = True
            hack_mac = mac_address
            print(hack_mac)
        elif ip_address == "192.168.1.1" and mac_address == config.get('mac'):
            hacked = False
def Re_arp():
    global config
    arp = ARP(op=2, hwsrc=config.get('mac'), psrc="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.1")
    print(int(config.get('arp_time')))
    for _ in range(int(config.get('arp_time'))):
        send(arp)
def start_sniffing():
    sniff(filter='arp', prn=arp_spoof_check, store=0)
app = Flask(__name__)
@app.route('/rearp')
def rearp():
    Re_arp()
    return "ok"
@app.route('/devices')
def Devices():
    return json.dumps(get_devices_on_network())

@app.route('/rm')
def rm():
    return config.get('mac')

@app.route('/checker')
def checker():
    global sniff_thread
    if not sniff_thread or not sniff_thread.is_alive():
        sniff_thread = threading.Thread(target=start_sniffing)
        sniff_thread.start()
    return str(hacked)

@app.route('/mac')
def mac():
    return get_mac()

@app.route("/")
def home():
    return render_template("index.html")

if __name__ == "__main__":
    app.run("0.0.0.0", 80)
