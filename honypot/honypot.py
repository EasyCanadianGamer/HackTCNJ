import multiprocessing
import socket
import logging
import subprocess
import re
import time
import os
from scapy.all import sniff, ARP

# Configure logging
logging.basicConfig(filename="honeypot.log", level=logging.INFO, 
                    format="%(asctime)s - %(message)s")

def get_mac_address(ip):
    """Get MAC address from ARP cache."""
    try:
        output = subprocess.check_output(["arp", "-n", ip]).decode()
        match = re.search(r"at ([0-9a-f:]{17})", output)
        return match.group(1) if match else "unknown"
    except Exception as e:
        logging.error(f"Error getting MAC for {ip}: {e}")
        return "unknown"

def build_ssh_packet(message_type, message):
    """Construct protocol-compliant SSH packets with proper padding."""
    # SSH packet structure:
    # [4-byte packet length][1-byte padding length][payload][random padding]
    payload = bytes([message_type]) + message
    payload_length = len(payload)
    
    # Calculate padding to meet 8-byte block alignment
    block_size = 8
    extra = (payload_length + 5) % block_size  # 5 = 4(len) + 1(pad_len)
    padding_length = (block_size - extra) % block_size
    if padding_length < 4:
        padding_length += block_size  # Minimum 4 bytes of padding per RFC
    
    # Generate random padding
    padding = os.urandom(padding_length)
    
    # Build full packet
    packet_length = len(payload) + padding_length + 1  # +1 for pad_len byte
    return (
        packet_length.to_bytes(4, byteorder="big") +
        bytes([padding_length]) +
        payload +
        padding
    )

def ssh_honeypot(banned_macs):
    HOST, PORT = "0.0.0.0", 22
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"[*] Honeypot listening on port {PORT}...")

    # Protocol messages
    SSH_BANNER = b"SSH-2.0-OpenSSH_8.1p1 Debian-1ubuntu1.1\r\n"
    WARNING = b"\r\n[WARNING] Unauthorized access detected!\r\n"
    BANNED_MSG = b"\r\n[ALERT] Your MAC has been banned.\r\n"

    while True:
        conn, addr = server_socket.accept()
        ip, mac = addr[0], get_mac_address(addr[0])
        
        print(f"[!] Connection from {ip} ({mac})")
        logging.info(f"Connection attempt: {ip} ({mac})")

        try:
            # 1. Send SSH banner (outside normal packet structure)
            conn.sendall(SSH_BANNER)

            # 2. Send warning as SSH_MSG_USERAUTH_BANNER (type 53)
            warning_packet = build_ssh_packet(
                53,  # SSH_MSG_USERAUTH_BANNER
                WARNING
            )
            conn.sendall(warning_packet)

            # 3. Wait 2 seconds while handling client input
            start_time = time.time()
            while time.time() - start_time < 2:
                try:
                    _ = conn.recv(1024)  # Drain input buffer
                except (BlockingIOError, ConnectionResetError):
                    pass
                time.sleep(0.1)

            # 4. Ban MAC
            if mac not in banned_macs:
                banned_macs[mac] = ip
                with open("banned_macs.log", "a") as f:
                    f.write(f"{ip} - {mac}\n")
                print(f"[!] Banned {mac} ({ip})")
                logging.info(f"Banned {mac} ({ip})")

            # 5. Send disconnect message (type 1)
            disconnect_packet = build_ssh_packet(
                1,  # SSH_MSG_DISCONNECT
                BANNED_MSG
            )
            conn.sendall(disconnect_packet)
            time.sleep(0.5)
            
        except Exception as e:
            logging.error(f"Error handling {ip}: {e}")
        finally:
            conn.close()


def arp_monitor(banned_macs):
    """Monitor ARP traffic."""
    def process_packet(pkt):
        if pkt.haslayer(ARP) and pkt.op == 2:
            ip, mac = pkt.psrc, pkt.hwsrc
            log_msg = f"ARP from {ip} ({mac})"
            print(log_msg)
            logging.info(log_msg)
    
    print("[*] ARP monitor started")
    sniff(filter="arp", prn=process_packet, store=0)

if __name__ == "__main__":
    manager = multiprocessing.Manager()
    banned_macs = manager.dict()

    processes = [
        multiprocessing.Process(target=ssh_honeypot, args=(banned_macs,)),
        multiprocessing.Process(target=arp_monitor, args=(banned_macs,))
    ]

    for p in processes:
        p.start()
    for p in processes:
        p.join()