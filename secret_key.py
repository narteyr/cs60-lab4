from scapy.all import *
import time 
import uuid 
import threading
import struct
import statistics

READY_FRAME = b"READY"
ACK_FRAME = b"ACK"
INDICES_FRAME = b"INDICES"
KEY_HASH_FRAME = b"KEY_HASH"
KEY_VERIFY_FRAME = b"KEY_VERIFY"

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

    sniff(iface=interface, prn=check_ready, timeout=3, store=0) # Wait 5 seconds
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

def wait_for_responder(interface="wlan0", timeout=10):
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
        if ((i+1) % 50 == 0):
            print(f"Sent {i+1}/{NUM_FRAMES}")
    
    print("Initiator has finished sending all frames")
    
    # make sure we wait for replies to finish
    time.sleep(2)
    return rssi_data


def filter_common_bits(indices, bits):
    """
    purpose: to filter out bits with index similar to indices
    """

def listen_for_indices(pkt):
    """
    purpose: sniffs packets and extracts index arrays from Raw payload
    Expected payload encoding: 4-bytes unsigned integers (big-endian)
    """
    if not pkt.haslayer(RadioTap) or not pkt.haslayer(Raw):
        return

    payload = bytes(pkt[Raw].load)
    payload_len = len(payload)

    if payload_len % 4 != 0:
        print(f"[-] invalid payload length ({payload_len})")
        return

    num_indices = payload_len // 4
    indices = list(struct.unpack(f"!{num_indices}I", payload))
    print(f"[+] Received indices: {indices}")
    
def send_indices_frames(key_bits, interface="wlan0"):
    """
    Sends indices to other device
    """
    indices = sorted(key_bits.keys())

    if not indices:
        print("No indices to send")
        return

    print(f"Sending {len(indices)} indices...")
    payload = INDICES_FRAME + struct.pack(f"!{len(indices)}I", *indices)

    # send multiple times just in case
    for i in range(5):
        send_frame(payload, interface)
        time.sleep(0.1)

    print("Sent indices 5 times to other device")

def receive_indices(interface="wlan0", timeout=10):
    """ Receive indices from other device """

    print("Listening for indices...")
    received_indices = set()
    def listen_for_indices(pkt):
        nonlocal received_indices
        if not pkt.haslayer(Raw):
            return

        payload = bytes(pkt[Raw].load)

        if INDICES_FRAME not in payload:
            return
        
        pos = payload.find(INDICES_FRAME)
        indices_data = payload[pos + len(INDICES_FRAME):]

        # check that this is valid length (each index should be 4 bytes)
        if len(indices_data) % 4 != 0:
            print(f"Invalid indices data length: {len(indices_data)}")
            return

        num_indices = len(indices_data) // 4
        if num_indices > 0:
            try:
                indices = struct.unpack(f"!{num_indices}I", indices_data)
                received_indices = set(indices)
                print(f"Received {len(indices)} indices")
            except struct.error as e:
                print(f"Error unpacking indices: {e}")
        
    sniff(iface=interface, prn=listen_for_indices, timeout=timeout, store=0)

    if received_indices:
        print(f"Successfully received {len(receive_indices)} indices.")
        return received_indices
    else:
        print("Failed to receive indices")
        return set()

def exchange_indices(key_bits, interface="wlan0"):
    """ Sends indices to other device and determines indices in common """
    my_indices = set(key_bits.keys())
    send_indices_frames(key_bits, interface)
    time.sleep(0.5)
    
    other_indices = receive_indices(interface, 10)

    if not other_indices:
        print("Failed to receive indices from other device.")
        return set()
    
    common_indices = my_indices & other_indices
    print(f"Number of indices in common: {len(common_indices)}")

    return common_indices

def build_key(key_bits, common_indices):
    """ Takes common indices and builds a final key """
    if not common_indices:
        print("Cannot build a key with no indices in common...")
        return

    # sort for consistency
    sorted_indices = sorted(common_indices)
    key = ''.join(str[key_bits[idx]] for idx in sorted_indices)

    return key

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
    
    if len(rssi_data) == 0:
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

def send_key_hash(key_string, interface="wlan0"):
    """ Used by initiator to send hash of key to responder """

    key_hash = hashlib.sha256(key_string.encode()).hexdigest()
    payload = KEY_HASH_FRAME + key_hash.encode()

    # send multiple times
    for i in range(5):
        send_frame(payload, interface)
        time.sleep(1)

    print("Sent key hash to responder")

    return key_hash

def verify_key(key_string, interface="wlan0", timeout=10):
    """ Responder function to verify key matches """
    
    responder_key_hash = hashlib.sha256(key_string.encode()).hexdigest()
    initiator_key_hash = None

    def listen_for_hash(pkt):
        nonlocal initiator_key_hash

        if not pkt.haslayer(Raw):
            return
        
        payload = bytes(pkt[Raw].load)
        
        if not KEY_HASHFRAME in payload:
            return

        pos = payload.find(KEY_HASH_FRAME)
        # initiator key hash data
        data = payload[pos+len(KEY_HASH_FRAME):]

        # SHA 256 is 64 characters
        if len(data) >= 64:
            key_hash = data[:64].decode('ascii', errors='ignore')
            initiator_key_hash = key_hash
            print("Received key hash from initaitor")
    
    print("Listening for initiator's commitment...")
    sniff(iface=interface, prn=listen_for_hash, timeout=timeout, store=0)

    if not initiator_key_hash:
        print("Failed to receive initiator's key.")
        return False

    if initiator_key_hash == responder_key_hash:
        print("Success! Initiator and Responder keys match!")
        send_key_verification(True, interface)
        return True
    else:
        print("Error: Keys do not match.")
        send_key_verification(False, interface)
        return False

def send_key_verification(success, interface="wlan0"):
    """ Responder sends result of key comparison back to initiator """
    if success: 
        payload = KEY_VERIFY_FRAME + b"SUCCESS"
    else:
        payload = KEY_VERIFY_FRAME + b"FAILURE"

    for i in range(3):
        send_frame(payload, interface)
        time.sleep(0.1)

def wait_for_verification(interface="wlan0", timeout=10):
    """ Initiator waits for key verification result from responder """

    print("Waiting for key verification from responder...")
    match = False

    def listen_for_verify(pkt):
        nonlocal match 

        if not pkt.haslayer(Raw):
            return

        payload = bytes(pkt[Raw].load)
        if KEY_VERIFY_FRAME not in payload:
            return

        if b"SUCCESS" in payload:
            match = True
            print("Responder confirmed that keys match!")
        elif b"FAILURE" in payload:
            match = False
            print("Responder confirmed that keys do not match")

    sniff(iface=interface, prn=listen_for_verify, timeout=timeout, store=0)

    return match

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

    # calculate key bits using mean + std
    key_bits = calculate_bits(rssi_data, z=1.5)

    if len(key_bits) == 0:
        print("No key bits were generated")
        return

    # determine set of common indices
    common_indices = exchange_indices(key_bits, interface)
    
    if len(common_indices) == 0:
        print("Not able to generate a key because there were no indices in common...")
        return
    
    # use common indices to build string
    key = build_key(key_bits, common_indices)
    
    if len(key) == 0:
        print("Key is empty...")
        return

    # verify keys match
    time.sleep(1)

    if role == "initiator":
        send_key_hash(key, interface)
        result = wait_for_verification(interface, 10)
        if result:
            print("Key exchange was successful!")
        else:
            print("Key exchange was unsuccessful...")
    else:
        match = verify_key(key, interface, timeout=10)
        if match:
            print("Key exchange was successful!")
        else:
            print("Key exchange was unsuccessful...")

if __name__ == "__main__":
    main()

        
    


    





    
