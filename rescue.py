from scapy.all import *
import struct
import threading
import time

survivors = {}
survivors_lock = threading.Lock()

def packet_handler(pkt):
    if not pkt.haslayer(Dot11):
        return
    if not pkt.haslayer(Raw):
        return

    packet_bytes = bytes(pkt)
    if not b'RESCUEME' in packet_bytes:
        return
    
    pos = packet_bytes.find(b"RESCUEME")
        
    # Extract survivor ID (4 bytes after RESCUEME)
    # figure out how this works 
    if pos + 12 <= len(packet_bytes):
        survivor_id = struct.unpack("!I", packet_bytes[pos+8:pos+12])[0]
        print(f"  Survivor ID: {survivor_id}")
        
        # Get RSSI
        rssi = None
        if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'dBm_AntSignal'):
            rssi = pkt[RadioTap].dBm_AntSignal
        print(f"  RSSI: {rssi} dBm")
    else:
        print("broken")
    '''
    print("got valid packet")
    survivor_id = struct.unpack("!I", payload[8:12])[0]
    
    rssi = None
    if pkt.haslayer(RadioTap):
        if hasattr(packet[RadioTap], 'dBm_AntSignal'):
            rssi = packet[RadioTap].dBm_AntSignal
            print(rssi)
    
    '''

def sniffer_thread(interface):
    print(f"Sniffer started on {interface}")
    sniff(iface=interface, prn=packet_handler, store=0)

def main():
    interface = "wlan0"
    sniffer = threading.Thread(target=sniffer_thread, args=(interface,), daemon=True)
    sniffer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopped")

if __name__ == "__main__":
    main()