"""
peer.py  Gossip P2P Peer Node
================================
A peer that registers with seed nodes via consensus, selects neighbors
using preferential attachment (power-law), disseminates gossip messages,
and performs consensus-based liveness detection.

Usage:
    python peer.py <IP> <PORT>

Example:
    python peer.py 127.0.0.1 6001
"""

import sys
import os
import socket
import threading
import time
import csv
import random
import hashlib
import math
from datetime import datetime

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
SELF_IP = ""
SELF_PORT = 0

SEED_LIST = []              # all seeds from config.csv
CONNECTED_SEEDS = []        # seeds we successfully registered with

NEIGHBORS = set()           # (ip, port) of connected neighbors
NEIGHBORS_LOCK = threading.Lock()

NEIGHBOR_CONNS = {}         # (ip, port) -> socket (persistent TCP)
NEIGHBOR_CONNS_LOCK = threading.Lock()

MESSAGE_LIST = {}           # hash -> (message, timestamp, sender_ip)
MESSAGE_LIST_LOCK = threading.Lock()

MSG_COUNTER = 0             # gossip message counter
MSG_LOCK = threading.Lock()
MAX_MESSAGES = 10

# Liveness tracking
PING_MISS = {}              # (ip, port) -> consecutive missed pings
PING_MISS_LOCK = threading.Lock()
MISS_THRESHOLD = 3          # after 3 misses, start suspicion

SUSPECTED = {}              # (ip, port) -> set of (voter_ip, voter_port) who agree
SUSPECTED_LOCK = threading.Lock()

REPORTED_DEAD = set()       # already reported as dead
REPORTED_DEAD_LOCK = threading.Lock()

OUTPUT_FILE = "outputfile.txt"
OUTPUT_LOCK = threading.Lock()

RUNNING = True
LISTEN_SOCKET = None

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
def log(msg):
    """Log to both console and output file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [PEER {SELF_IP}:{SELF_PORT}] {msg}"
    print(line, flush=True)
    with OUTPUT_LOCK:
        with open(OUTPUT_FILE, "a") as f:
            f.write(line + "\n")


# ---------------------------------------------------------------------------
# Low-level TCP helpers
# ---------------------------------------------------------------------------
def send_message(ip, port, msg):
    """Send a message and return the reply."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, int(port)))
        s.sendall((msg + "\n").encode())
        reply = ""
        try:
            data = s.recv(4096)
            if data:
                reply = data.decode().strip()
        except socket.timeout:
            pass
        s.close()
        return reply
    except Exception:
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
# Registration with seed nodes
# ---------------------------------------------------------------------------
def register_with_seeds():
    """Register with at least floor(n/2)+1 seed nodes."""
    global CONNECTED_SEEDS

    n = len(SEED_LIST)
    quorum = (n // 2) + 1
    random.shuffle(SEED_LIST)

    log(f"Attempting registration with {quorum} out of {n} seeds...")

    registered = []
    for ip, port in SEED_LIST:
        if len(registered) >= quorum:
            break
        reply = send_message(ip, port, f"REGISTER:{SELF_IP}:{SELF_PORT}")
        if reply and reply.startswith("REG_OK"):
            log(f"  Registered with seed {ip}:{port}")
            registered.append((ip, port))
        else:
            log(f"  Registration with seed {ip}:{port} failed (reply={reply})")

    if len(registered) < quorum:
        log(f"WARNING: Only registered with {len(registered)}/{quorum} seeds. Retrying in 3s...")
        time.sleep(3)
        # Retry with remaining seeds
        for ip, port in SEED_LIST:
            if (ip, port) in registered:
                continue
            if len(registered) >= quorum:
                break
            reply = send_message(ip, port, f"REGISTER:{SELF_IP}:{SELF_PORT}")
            if reply and reply.startswith("REG_OK"):
                log(f"  Registered with seed {ip}:{port}")
                registered.append((ip, port))

    CONNECTED_SEEDS = registered
    log(f"Registration complete. Connected to {len(registered)} seeds.")
    return len(registered) >= quorum


# ---------------------------------------------------------------------------
# Peer discovery + power-law neighbor selection
# ---------------------------------------------------------------------------
def discover_peers():
    """Get peer lists from connected seeds, compute union, select neighbors."""
    all_peers = set()
    for ip, port in CONNECTED_SEEDS:
        reply = send_message(ip, port, "GET_PEERS")
        if reply and reply.startswith("PEER_LIST:"):
            peer_data = reply[len("PEER_LIST:"):]
            if peer_data:
                for entry in peer_data.split(","):
                    entry = entry.strip()
                    if ":" in entry:
                        parts = entry.split(":")
                        pip, pport = parts[0], int(parts[1])
                        if not (pip == SELF_IP and pport == SELF_PORT):
                            all_peers.add((pip, pport))
            log(f"  Peer list from seed {ip}:{port}: {peer_data}")

    log(f"Union of peer lists: {all_peers}")
    return all_peers


def select_neighbors_power_law(candidates):
    """
    Select neighbors using preferential attachment to produce a power-law
    degree distribution.  Peers with lower current degree get higher weight.
    """
    if not candidates:
        return set()

    # Get degree hints from a seed
    degrees = {}
    for ip, port in CONNECTED_SEEDS:
        reply = send_message(ip, port, "GET_DEGREES")
        if reply and reply.startswith("DEGREES:"):
            deg_data = reply[len("DEGREES:"):]
            if deg_data:
                for entry in deg_data.split(","):
                    entry = entry.strip()
                    if "=" in entry:
                        addr_part, d = entry.rsplit("=", 1)
                        parts = addr_part.split(":")
                        if len(parts) >= 2:
                            degrees[(parts[0], int(parts[1]))] = int(d)
            break

    # Assign weights: new nodes (degree 0) get highest weight -> preferential attachment
    # Using inverse of (degree + 1) to avoid zero
    weights = []
    cand_list = list(candidates)
    for c in cand_list:
        d = degrees.get(c, 0)
        weights.append(1.0 / (d + 1))

    # Normalize
    total = sum(weights)
    if total > 0:
        weights = [w / total for w in weights]
    else:
        weights = [1.0 / len(cand_list)] * len(cand_list)

    # Select min(len(candidates), target) neighbors
    # Target degree: at least 1, at most len(candidates)
    # For a small network, connect to all; for larger, sample
    target = min(len(cand_list), max(1, int(math.log2(len(cand_list) + 1)) + 1))

    selected = set()
    remaining = list(range(len(cand_list)))
    rem_weights = list(weights)

    for _ in range(target):
        if not remaining:
            break
        total_w = sum(rem_weights)
        if total_w <= 0:
            break
        probs = [w / total_w for w in rem_weights]
        chosen_idx = random.choices(range(len(remaining)), weights=probs, k=1)[0]
        selected.add(cand_list[remaining[chosen_idx]])
        remaining.pop(chosen_idx)
        rem_weights.pop(chosen_idx)

    return selected


def connect_to_neighbors(neighbor_set):
    """Establish persistent TCP connections to neighbors."""
    for ip, port in neighbor_set:
        with NEIGHBORS_LOCK:
            NEIGHBORS.add((ip, port))
        with PING_MISS_LOCK:
            PING_MISS[(ip, port)] = 0

    # Update degree at seeds
    degree = len(neighbor_set)
    for sip, sport in CONNECTED_SEEDS:
        send_message(sip, sport, f"UPDATE_DEGREE:{SELF_IP}:{SELF_PORT}:{degree}")

    log(f"Connected to {len(neighbor_set)} neighbors: {neighbor_set}")
    log(f"Degree = {degree}")


# ---------------------------------------------------------------------------
# Gossip protocol
# ---------------------------------------------------------------------------
def gossip_generator():
    """Generate a gossip message every 5 seconds, up to MAX_MESSAGES."""
    global MSG_COUNTER
    time.sleep(2)  # wait for connections to settle

    while RUNNING:
        with MSG_LOCK:
            if MSG_COUNTER >= MAX_MESSAGES:
                break
            MSG_COUNTER += 1
            counter = MSG_COUNTER

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"{timestamp}:{SELF_IP}:{counter}"
        msg_hash = hashlib.sha256(message.encode()).hexdigest()

        with MESSAGE_LIST_LOCK:
            MESSAGE_LIST[msg_hash] = (message, timestamp, SELF_IP)

        log(f"Generated gossip #{counter}: {message}")

        # Forward to all neighbors
        with NEIGHBORS_LOCK:
            nbrs = list(NEIGHBORS)
        for ip, port in nbrs:
            send_message_no_reply(ip, port, f"GOSSIP:{message}")

        time.sleep(5)


def handle_gossip(message, sender_ip, sender_port):
    """Handle a received gossip message."""
    msg_hash = hashlib.sha256(message.encode()).hexdigest()

    with MESSAGE_LIST_LOCK:
        if msg_hash in MESSAGE_LIST:
            return  # duplicate, ignore
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        MESSAGE_LIST[msg_hash] = (message, timestamp, sender_ip)

    log(f"Received gossip from {sender_ip}:{sender_port}: {message}")

    # Forward to all neighbors except sender
    with NEIGHBORS_LOCK:
        nbrs = list(NEIGHBORS)
    for ip, port in nbrs:
        if ip == sender_ip and port == sender_port:
            continue
        send_message_no_reply(ip, port, f"GOSSIP:{message}")


# ---------------------------------------------------------------------------
# Liveness detection
# ---------------------------------------------------------------------------
def liveness_checker():
    """Periodically ping all neighbors."""
    time.sleep(5)  # let gossip start first

    while RUNNING:
        with NEIGHBORS_LOCK:
            nbrs = list(NEIGHBORS)

        for ip, port in nbrs:
            with REPORTED_DEAD_LOCK:
                if (ip, port) in REPORTED_DEAD:
                    continue

            reply = send_message(ip, port, "PING")
            if reply and reply.startswith("PONG"):
                with PING_MISS_LOCK:
                    PING_MISS[(ip, port)] = 0
            else:
                with PING_MISS_LOCK:
                    PING_MISS[(ip, port)] = PING_MISS.get((ip, port), 0) + 1
                    misses = PING_MISS[(ip, port)]

                if misses >= MISS_THRESHOLD:
                    initiate_suspicion(ip, port)

        time.sleep(5)


def initiate_suspicion(target_ip, target_port):
    """Start a suspicion phase for a potentially dead neighbor."""
    target_key = (target_ip, target_port)

    with REPORTED_DEAD_LOCK:
        if target_key in REPORTED_DEAD:
            return

    with SUSPECTED_LOCK:
        if target_key not in SUSPECTED:
            SUSPECTED[target_key] = set()
        SUSPECTED[target_key].add((SELF_IP, SELF_PORT))

    log(f"Suspecting {target_ip}:{target_port} is dead. Querying neighbors...")

    # Ask all other neighbors to confirm
    with NEIGHBORS_LOCK:
        nbrs = list(NEIGHBORS)

    for ip, port in nbrs:
        if ip == target_ip and port == target_port:
            continue
        send_message_no_reply(ip, port, f"SUSPECT:{target_ip}:{target_port}:{SELF_IP}:{SELF_PORT}")

    # Wait briefly for responses
    time.sleep(3)

    # Check if majority of neighbors agree
    with SUSPECTED_LOCK:
        if target_key in SUSPECTED:
            votes = len(SUSPECTED[target_key])
        else:
            votes = 0

    with NEIGHBORS_LOCK:
        total_nbrs = len(NEIGHBORS)

    quorum = (total_nbrs // 2) + 1
    if votes >= quorum:
        with REPORTED_DEAD_LOCK:
            if target_key in REPORTED_DEAD:
                return
            REPORTED_DEAD.add(target_key)

        log(f"PEER CONSENSUS: {target_ip}:{target_port} confirmed dead (votes={votes}/{total_nbrs})")
        report_dead_to_seeds(target_ip, target_port)

        # Remove from neighbors
        with NEIGHBORS_LOCK:
            NEIGHBORS.discard(target_key)


def report_dead_to_seeds(dead_ip, dead_port):
    """Send dead-node report to all connected seeds."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"DEAD:{dead_ip}:{dead_port}:{timestamp}:{SELF_IP}"

    log(f"Reporting dead node {dead_ip}:{dead_port} to seeds")

    for ip, port in CONNECTED_SEEDS:
        send_message_no_reply(ip, port, msg)


# ---------------------------------------------------------------------------
# Incoming connection handler
# ---------------------------------------------------------------------------
def handle_incoming(conn, addr):
    """Handle incoming TCP connection from another peer or seed."""
    try:
        data = conn.recv(4096).decode().strip()
        if not data:
            conn.close()
            return

        parts = data.split(":")

        # --- PING ---
        if parts[0] == "PING":
            conn.sendall(b"PONG\n")

        # --- GOSSIP:<timestamp>:<IP>:<Msg#> ---
        elif parts[0] == "GOSSIP" and len(parts) >= 4:
            message = ":".join(parts[1:])  # reconstruct the full gossip message
            # Determine sender from address or message parts
            sender_ip = parts[2]
            try:
                sender_port = addr[1]
            except:
                sender_port = 0
            # Use the connecting address as sender
            handle_gossip(message, addr[0], addr[1])

        # --- SUSPECT:<target_ip>:<target_port>:<requester_ip>:<requester_port> ---
        elif parts[0] == "SUSPECT" and len(parts) >= 5:
            target_ip = parts[1]
            target_port = int(parts[2])
            requester_ip = parts[3]
            requester_port = int(parts[4])
            target_key = (target_ip, target_port)

            # Check if we can also confirm this target is dead
            with PING_MISS_LOCK:
                misses = PING_MISS.get(target_key, 0)

            if misses >= MISS_THRESHOLD:
                # We also think it's dead
                send_message_no_reply(requester_ip, requester_port,
                                      f"SUSPECT_ACK:{target_ip}:{target_port}:{SELF_IP}:{SELF_PORT}")
            else:
                # Do a quick ping to check
                reply = send_message(target_ip, target_port, "PING")
                if not reply or not reply.startswith("PONG"):
                    send_message_no_reply(requester_ip, requester_port,
                                          f"SUSPECT_ACK:{target_ip}:{target_port}:{SELF_IP}:{SELF_PORT}")

        # --- SUSPECT_ACK:<target_ip>:<target_port>:<voter_ip>:<voter_port> ---
        elif parts[0] == "SUSPECT_ACK" and len(parts) >= 5:
            target_ip = parts[1]
            target_port = int(parts[2])
            voter_ip = parts[3]
            voter_port = int(parts[4])
            target_key = (target_ip, target_port)

            with SUSPECTED_LOCK:
                if target_key not in SUSPECTED:
                    SUSPECTED[target_key] = set()
                SUSPECTED[target_key].add((voter_ip, voter_port))

        else:
            pass  # ignore unknown messages

    except Exception as e:
        pass
    finally:
        conn.close()


def listener_thread():
    """Listen for incoming connections."""
    global LISTEN_SOCKET
    LISTEN_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    LISTEN_SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    LISTEN_SOCKET.bind((SELF_IP, SELF_PORT))
    LISTEN_SOCKET.listen(50)
    LISTEN_SOCKET.settimeout(2)

    while RUNNING:
        try:
            conn, addr = LISTEN_SOCKET.accept()
            threading.Thread(target=handle_incoming, args=(conn, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception:
            break


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global SELF_IP, SELF_PORT, RUNNING

    if len(sys.argv) != 3:
        print("Usage: python peer.py <IP> <PORT>")
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

    log(f"Starting peer node. Seed list: {SEED_LIST}")

    # Start listener first so seeds/peers can reach us
    t_listen = threading.Thread(target=listener_thread, daemon=True)
    t_listen.start()
    time.sleep(1)

    # Register with seeds
    if not register_with_seeds():
        log("FATAL: Could not register with a quorum of seeds. Exiting.")
        RUNNING = False
        sys.exit(1)

    # Discover peers and select neighbors
    candidates = discover_peers()
    if candidates:
        neighbors = select_neighbors_power_law(candidates)
        connect_to_neighbors(neighbors)
    else:
        log("No other peers found yet. Will operate as the first peer.")

    # Start gossip generator
    t_gossip = threading.Thread(target=gossip_generator, daemon=True)
    t_gossip.start()

    # Start liveness checker
    t_liveness = threading.Thread(target=liveness_checker, daemon=True)
    t_liveness.start()

    log("Peer fully operational.")

    try:
        while RUNNING:
            time.sleep(1)
    except KeyboardInterrupt:
        log("Shutting down peer node.")
        RUNNING = False
        if LISTEN_SOCKET:
            LISTEN_SOCKET.close()


if __name__ == "__main__":
    main()
