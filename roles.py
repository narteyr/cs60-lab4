
import time
from scapy.all import *
from send_beacon import send_beacon

found_beacon = False


def detect_beacon_frame(pkt):
    global found_beacon
    beacon_msg = 'ready to begin'
    if not pkt.haslayer(Dot11) or not pkt.haslayer(Raw):
        return
    
    packet_bytes = bytes(pkt)
    if beacon_msg.encode() in packet_bytes:
        print("[+] Beacon detected")
        found_beacon = True
        return

    pos = packet_bytes.find(beacon_msg.encode())
    if pos:
        return True
    

def stop_filter(pkt):
    return found_beacon

def find_my_role():
    #we set a timer for 5s to listen for packet
    #if we do not receive beacon frame with that message, then we set ourselves as initiators
    #and start sending message.
    global found_beacon
    found_beacon = False
    duration = 5
    start_time = time.time()
    interface = "wlan0"

    print("Listening for beacon")
    sniff(
        iface=interface, 
        prn=detect_beacon_frame, 
        store=0, 
        timeout=duration, 
        stop_filter=stop_filter)

    print("Done after 5 seconds")

    if found_beacon:
        print("found beacon")
    else:
        print("beacon not found")
        send_beacon(beacon_message=b"ready to begin")


if __name__ == "__main__":
    find_my_role()

