"""
seed.py  Gossip P2P Seed Node
================================
A seed node that bootstraps peer membership via consensus-based
registration and removal.  Communicates with other seeds and with
peers over TCP using a simple text-based protocol.

Usage:
    python seed.py <IP> <PORT>

Example:
    python seed.py 127.0.0.1 5001
"""

import sys
import os
import socket
import threading
import time
import csv
import json
import random
import hashlib
from datetime import datetime

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
PEER_LIST = set()                    # committed (ip, port) pairs
PEER_LIST_LOCK = threading.Lock()

# Pending registration proposals: key = (ip, port), value = set of seed (ip,port) that voted YES
PENDING_REG = {}
PENDING_REG_LOCK = threading.Lock()

# Pending deletion proposals: key = (ip, port), value = set of seed (ip,port) that voted YES
PENDING_DEL = {}
PENDING_DEL_LOCK = threading.Lock()

# Dead-node reports received from peers: key = (dead_ip, dead_port), value = set of reporter (ip,port)
DEAD_REPORTS = {}
DEAD_REPORTS_LOCK = threading.Lock()

SEED_LIST = []       # list of (ip, port) for ALL seeds (including self)
SELF_IP = ""
SELF_PORT = 0
QUORUM = 0           # floor(n/2) + 1

OUTPUT_FILE = "outputfile.txt"
OUTPUT_LOCK = threading.Lock()

# Degree hints for power-law: track how many neighbors each peer already has
PEER_DEGREE = {}   # (ip,port) -> int
PEER_DEGREE_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
def log(msg):
    """Log to both console and output file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [SEED {SELF_IP}:{SELF_PORT}] {msg}"
    print(line, flush=True)
    with OUTPUT_LOCK:
        with open(OUTPUT_FILE, "a") as f:
            f.write(line + "\n")


# ---------------------------------------------------------------------------
# Low-level TCP helpers
# ---------------------------------------------------------------------------
def send_message(ip, port, msg):
    """Send a single message to a TCP endpoint and return the reply (if any)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, int(port)))
        s.sendall((msg + "\n").encode())
        # Try to read a reply
        reply = ""
        try:
            data = s.recv(4096)
            if data:
                reply = data.decode().strip()
        except socket.timeout:
            pass
        s.close()
        return reply
    except Exception as e:
        return ""


def send_message_no_reply(ip, port, msg):
    """Fire-and-forget message."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, int(port)))
        s.sendall((msg + "\n").encode())
        s.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Consensus helpers
# ---------------------------------------------------------------------------
def other_seeds():
    """Return list of seed (ip, port) excluding self."""
    return [(ip, p) for ip, p in SEED_LIST if not (ip == SELF_IP and p == SELF_PORT)]


def broadcast_to_seeds(msg):
    """Send a message to every other seed node."""
    for ip, port in other_seeds():
        threading.Thread(target=send_message_no_reply, args=(ip, port, msg), daemon=True).start()


def check_registration_quorum(peer_key):
    """Check if we have quorum for a registration proposal and commit if so."""
    with PENDING_REG_LOCK:
        if peer_key not in PENDING_REG:
            return
        votes = len(PENDING_REG[peer_key])
        if votes >= QUORUM:
            # Commit
            with PEER_LIST_LOCK:
                PEER_LIST.add(peer_key)
            with PEER_DEGREE_LOCK:
                if peer_key not in PEER_DEGREE:
                    PEER_DEGREE[peer_key] = 0
            log(f"CONSENSUS REACHED: Peer {peer_key[0]}:{peer_key[1]} REGISTERED (votes={votes}/{len(SEED_LIST)})")
            del PENDING_REG[peer_key]


def check_deletion_quorum(peer_key):
    """Check if we have quorum for a deletion proposal and remove if so."""
    with PENDING_DEL_LOCK:
        if peer_key not in PENDING_DEL:
            return
        votes = len(PENDING_DEL[peer_key])
        if votes >= QUORUM:
            with PEER_LIST_LOCK:
                PEER_LIST.discard(peer_key)
            with PEER_DEGREE_LOCK:
                PEER_DEGREE.pop(peer_key, None)
            log(f"CONSENSUS REACHED: Peer {peer_key[0]}:{peer_key[1]} REMOVED (votes={votes}/{len(SEED_LIST)})")
            del PENDING_DEL[peer_key]


# ---------------------------------------------------------------------------
# Client handler
# ---------------------------------------------------------------------------
def handle_client(conn, addr):
    """Handle one incoming TCP connection."""
    try:
        data = conn.recv(4096).decode().strip()
        if not data:
            conn.close()
            return

        parts = data.split(":")

        # --- REGISTER:<peer_ip>:<peer_port> ---
        if parts[0] == "REGISTER" and len(parts) >= 3:
            peer_ip = parts[1]
            peer_port = int(parts[2])
            peer_key = (peer_ip, peer_port)
            log(f"Registration request from {peer_ip}:{peer_port}")

            # Self-vote YES
            with PENDING_REG_LOCK:
                if peer_key not in PENDING_REG:
                    PENDING_REG[peer_key] = set()
                PENDING_REG[peer_key].add((SELF_IP, SELF_PORT))

            # Propose to other seeds
            broadcast_to_seeds(f"PROPOSE_REG:{peer_ip}:{peer_port}:{SELF_IP}:{SELF_PORT}")

            # Brief wait for votes to arrive
            time.sleep(2)

            # Check quorum
            check_registration_quorum(peer_key)

            with PEER_LIST_LOCK:
                if peer_key in PEER_LIST:
                    conn.sendall(b"REG_OK\n")
                else:
                    conn.sendall(b"REG_FAIL\n")

        # --- PROPOSE_REG:<peer_ip>:<peer_port>:<proposer_ip>:<proposer_port> ---
        elif parts[0] == "PROPOSE_REG" and len(parts) >= 5:
            peer_ip = parts[1]
            peer_port = int(parts[2])
            proposer_ip = parts[3]
            proposer_port = int(parts[4])
            peer_key = (peer_ip, peer_port)

            log(f"Received registration proposal for {peer_ip}:{peer_port} from seed {proposer_ip}:{proposer_port}")

            # Vote YES (in a real system there could be checks here)
            with PENDING_REG_LOCK:
                if peer_key not in PENDING_REG:
                    PENDING_REG[peer_key] = set()
                PENDING_REG[peer_key].add((proposer_ip, proposer_port))
                PENDING_REG[peer_key].add((SELF_IP, SELF_PORT))

            # Send vote back to proposer
            send_message_no_reply(proposer_ip, proposer_port,
                                  f"VOTE_REG:{peer_ip}:{peer_port}:{SELF_IP}:{SELF_PORT}")

            # Also check locally
            check_registration_quorum(peer_key)

        # --- VOTE_REG:<peer_ip>:<peer_port>:<voter_ip>:<voter_port> ---
        elif parts[0] == "VOTE_REG" and len(parts) >= 5:
            peer_ip = parts[1]
            peer_port = int(parts[2])
            voter_ip = parts[3]
            voter_port = int(parts[4])
            peer_key = (peer_ip, peer_port)

            with PENDING_REG_LOCK:
                if peer_key not in PENDING_REG:
                    PENDING_REG[peer_key] = set()
                PENDING_REG[peer_key].add((voter_ip, voter_port))

            check_registration_quorum(peer_key)

        # --- GET_PEERS ---
        elif parts[0] == "GET_PEERS":
            with PEER_LIST_LOCK:
                peer_str = ",".join(f"{ip}:{p}" for ip, p in PEER_LIST)
            conn.sendall(f"PEER_LIST:{peer_str}\n".encode())

        # --- GET_DEGREES (custom: return degree hints for power-law) ---
        elif parts[0] == "GET_DEGREES":
            with PEER_DEGREE_LOCK:
                degree_str = ",".join(f"{ip}:{p}={d}" for (ip, p), d in PEER_DEGREE.items())
            conn.sendall(f"DEGREES:{degree_str}\n".encode())

        # --- UPDATE_DEGREE:<peer_ip>:<peer_port>:<degree> ---
        elif parts[0] == "UPDATE_DEGREE" and len(parts) >= 4:
            peer_ip = parts[1]
            peer_port = int(parts[2])
            degree = int(parts[3])
            with PEER_DEGREE_LOCK:
                PEER_DEGREE[(peer_ip, peer_port)] = degree
            conn.sendall(b"OK\n")

        # --- DEAD:<dead_ip>:<dead_port>:<ts>:<reporter_ip> ---
        elif parts[0] == "DEAD" and len(parts) >= 5:
            dead_ip = parts[1]
            dead_port = int(parts[2])
            ts = parts[3]
            reporter_ip = parts[4]
            dead_key = (dead_ip, dead_port)

            log(f"Dead-node report: {dead_ip}:{dead_port} reported by {reporter_ip} at {ts}")

            # Self-vote YES
            with PENDING_DEL_LOCK:
                if dead_key not in PENDING_DEL:
                    PENDING_DEL[dead_key] = set()
                PENDING_DEL[dead_key].add((SELF_IP, SELF_PORT))

            # Propose deletion to other seeds
            broadcast_to_seeds(f"PROPOSE_DEL:{dead_ip}:{dead_port}:{SELF_IP}:{SELF_PORT}")

            time.sleep(2)
            check_deletion_quorum(dead_key)

            conn.sendall(b"DEAD_ACK\n")

        # --- PROPOSE_DEL:<dead_ip>:<dead_port>:<proposer_ip>:<proposer_port> ---
        elif parts[0] == "PROPOSE_DEL" and len(parts) >= 5:
            dead_ip = parts[1]
            dead_port = int(parts[2])
            proposer_ip = parts[3]
            proposer_port = int(parts[4])
            dead_key = (dead_ip, dead_port)

            log(f"Received deletion proposal for {dead_ip}:{dead_port} from seed {proposer_ip}:{proposer_port}")

            with PENDING_DEL_LOCK:
                if dead_key not in PENDING_DEL:
                    PENDING_DEL[dead_key] = set()
                PENDING_DEL[dead_key].add((proposer_ip, proposer_port))
                PENDING_DEL[dead_key].add((SELF_IP, SELF_PORT))

            send_message_no_reply(proposer_ip, proposer_port,
                                  f"VOTE_DEL:{dead_ip}:{dead_port}:{SELF_IP}:{SELF_PORT}")

            check_deletion_quorum(dead_key)

        # --- VOTE_DEL:<dead_ip>:<dead_port>:<voter_ip>:<voter_port> ---
        elif parts[0] == "VOTE_DEL" and len(parts) >= 5:
            dead_ip = parts[1]
            dead_port = int(parts[2])
            voter_ip = parts[3]
            voter_port = int(parts[4])
            dead_key = (dead_ip, dead_port)

            with PENDING_DEL_LOCK:
                if dead_key not in PENDING_DEL:
                    PENDING_DEL[dead_key] = set()
                PENDING_DEL[dead_key].add((voter_ip, voter_port))

            check_deletion_quorum(dead_key)

        else:
            log(f"Unknown message from {addr}: {data}")

    except Exception as e:
        log(f"Error handling client {addr}: {e}")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global SELF_IP, SELF_PORT, QUORUM

    if len(sys.argv) != 3:
        print("Usage: python seed.py <IP> <PORT>")
        sys.exit(1)

    SELF_IP = sys.argv[1]
    SELF_PORT = int(sys.argv[2])

    # Read seed list from config.csv
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.csv")
    with open(config_path, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                ip = row[0].strip()
                port = int(row[1].strip())
                SEED_LIST.append((ip, port))

    n = len(SEED_LIST)
    QUORUM = (n // 2) + 1
    log(f"Starting seed node. Total seeds={n}, Quorum={QUORUM}")
    log(f"Seed list: {SEED_LIST}")

    # Start TCP server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((SELF_IP, SELF_PORT))
    server.listen(50)
    log(f"Listening on {SELF_IP}:{SELF_PORT}")

    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        log("Shutting down seed node.")
        server.close()


if __name__ == "__main__":
    main()
