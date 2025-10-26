from scapy.all import *
import time 
import uuid 
import threading
import struct
import statistics

READY_FRAME = b"READY"
ACK_FRAME = b"ACK"

# data is sent by initiator, reply sent by respondent
DATA_FRAME = b"DATA"
REPLY_FRAME = b"REPLY"
NUM_FRAMES = 300

def send_frame(payload, interface="wlan0"):
    """ Helper function to send frames """
    mac = uuid.getnode()
    mac_bytes = mac.to_bytes(6, 'big')
    mac_string = ':'.join(f'{b:02x}' for b in mac_bytes)

    frame = (RadioTap() /
             Dot11(type=2,
                   subtype=0,
                   addr1="ff:ff:ff:ff:ff:ff",
                   addr2=mac_string,
                   addr3="ff:ff:ff:ff:ff:ff") /
             Raw(load=payload))

    sendp(frame, iface=interface, verbose=False)

def determine_role(interface="wlan0"):
    """ Listens for ready frames
        If received, this host is the initiator
        Otherwise, this host is the receiver
    """
    found_initiator = False
    def check_ready(pkt):
        nonlocal found_initiator
        packet_bytes = bytes(pkt)
        if READY_FRAME in packet_bytes:
            print("Detected Ready Frame from another device")
            found_initiator = True

    sniff(iface=interface, prn=check_ready, timeout=3, store=0) # Wait 3 seconds
    if found_initiator:
        print("This device is the responder")
        send_ack(interface)
        return "responder"
    else:
        print("This device is the initiator")
        return "initiator"

def send_ack(interface="wlan0"):
    """ Send ack frames to initiator """
    print("Sending ACK frames to initiator...")
    for i in range(5):
        send_frame(ACK_FRAME, interface)
        time.sleep(0.2)

def wait_for_responder(interface="wlan0", timeout=5):
    """ Listens for ACK frames from the responder """
    start_time = time.time()

    heard_responder = False
    def check_ack(pkt):
        nonlocal heard_responder
        packet_bytes = bytes(pkt)
        if ACK_FRAME in packet_bytes:
            print("Detected ACK frame from responder")
            heard_responder = True

    # send ready frames until timeout or we have a responder 
    while time.time() - start_time < timeout and not heard_responder:
        send_frame(READY_FRAME, interface)
        sniff(iface=interface, prn=check_ack, timeout=0.5, store=0)

    if heard_responder:
        print("Responder found")
        return True
    else:
        print("Could not find a responder")
        return False

def send_data_frame(index, interface="wlan0"):
    """ Called by initiator to send frames """
    payload = DATA_FRAME + struct.pack("!I", index)
    send_frame(payload, interface)

def send_response_frame(index, interface="wlan0"):
    """ Called by responder to send frames back """
    payload = REPLY_FRAME + struct.pack("!I", index)
    send_frame(payload, interface)

def listen_for_replies(interface, rssi_data):
    num_received = 0
    def handle_reply(pkt):
        nonlocal num_received
        packet_bytes = bytes(pkt)

        if REPLY_FRAME in packet_bytes:
            pos = packet_bytes.find(REPLY_FRAME)

            if pos + len(REPLY_FRAME) + 4 <= len(packet_bytes):
                index_bytes = packet_bytes[pos+len(REPLY_FRAME):pos+len(REPLY_FRAME)+4]
                index = struct.unpack("!I", index_bytes)[0]

                rssi = None
                if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                    rssi = pkt[RadioTap].dBm_AntSignal

                if rssi is not None:
                    rssi_data[index] = rssi
                    num_received += 1
                    if num_received % 50 == 0:
                        print(f"Initiator has received {num_received}/{NUM_FRAMES} frames")
    
    sniff(iface=interface, prn=handle_reply, timeout=30, store=0)

def start_initiator(interface="wlan0"):
    """ Starts initiator exchange """
    print("Initiator starting in 3 seconds, start waving hand now...")
    time.sleep(3)

    rssi_data = {}

    # Listen to replies while sending in the background
    listener_thread = threading.Thread(target=listen_for_replies, args=(interface, rssi_data), daemon=True)
    listener_thread.start()

    for i in range(NUM_FRAMES):
        send_data_frame(i, interface)
        time.sleep(0.02)
        if (i+1 % 50 == 0):
            print(f"Sent {i+1}/{NUM_FRAMES}")
    
    print("Initiator has finished sending all frames")
    
    # make sure we wait for replies to finish
    time.sleep(2)
    return rssi_data

def start_responder(interface="wlan0"):
    """ Responder listens for data frames, measures the RSSI, and responds """
    print("Responder starting in 3 seconds, start waving hand now...")
    time.sleep(3)

    rssi_data = {}
    num_received = 0

    def handle_data_frame(pkt):
        nonlocal num_received
        packet_bytes = bytes(pkt)

        if DATA_FRAME in packet_bytes:
            pos = packet_bytes.find(DATA_FRAME)
            if pos + len(DATA_FRAME) + 4 <= len(packet_bytes):
                index_bytes = packet_bytes[pos+len(DATA_FRAME):pos+len(DATA_FRAME)+4]
                index = struct.unpack("!I", index_bytes)[0]

                rssi = None
                if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                    rssi = pkt[RadioTap].dBm_AntSignal

                if rssi is not None and index < NUM_FRAMES:
                    rssi_data[index] = rssi
                    num_received += 1

                    # reply with response frame
                    send_response_frame(index, interface)
                    if num_received % 50 == 0:
                        print(f"Responder has received {num_received}/{NUM_FRAMES} frames")

    sniff(iface=interface, prn=handle_data_frame, timeout=30, store=0)
    return rssi_data

def calculate_bits(rssi_data, z=1.5):  
    """ Determines sequence of bits based on RSSI Data """
    
    if len(rssi_data) < 0:
        print("Not enough bits to generate a key.")
        return {}

    rssi_values = list(rssi_data.values())

    mean_rssi = statistics.mean(rssi_values)
    std_rssi = statistics.stdev(rssi_values)

    # calcualte bounds
    high = mean_rssi + std_rssi * z
    low = mean_rssi - std_rssi * z

    key_bits = {}  
    for index, rssi in rssi_data.items():
        if rssi > high:
            key_bits[index] = 1
        elif rssi < low:
            key_bits[index] = 0

    return key_bits

def main():
    interface = "wlan0"

    print("Determining role...")
    role = determine_role(interface)
    rssi_data = {}
    if role == "initiator":
        print("ROLE: Initiator")
        print("\nWaiting for Responder...")
        if wait_for_responder(interface):
            print("Responder has connected")
            rssi_data = start_initiator(interface)
        else:
            print("No responder found")
    elif role == "responder":
        print("ROLE: Responder")
        print("Connected to Initaitor")
        rssi_data = start_responder(interface)

    print("RESULTS:")
    print('-'*50)
    print(f"Total number of RSSI Measurements: {len(rssi_data)}")

    # calcualte key bits
    if len(rssi_data) > 0:
        key_bits = calculate_bits(rssi_data, z=1.5)

if __name__ == "__main__":
    main()

        
    


    





    
