import socket
import json
import threading
import time
import os

# ===================== Configuration =====================
MY_IP = os.getenv("MY_IP", "127.0.0.1")
LOCAL_SUBNETS = os.getenv("LOCAL_SUBNETS", "").split(",") if os.getenv("LOCAL_SUBNETS") else []
NEIGHBORS = os.getenv("NEIGHBORS", "").split(",") if os.getenv("NEIGHBORS") else []
PORT = 5000
UPDATE_INTERVAL = 10

# ===================== Routing Table =====================
routing_table = {}

def init_routing_table():
    for subnet in LOCAL_SUBNETS:
        if subnet:
            # Store Dist, NextHop, Timestamp
            routing_table[subnet] = [0, "0.0.0.0", time.time()]

def update_kernel_route(subnet, next_hop, dist):
    if next_hop == "0.0.0.0":
        return
    if dist >= 16:
        # Route is dead, delete it to prevent black holes
        os.system(f"ip route del {subnet} via {next_hop} 2>/dev/null")
    else:
        cmd = f"ip route replace {subnet} via {next_hop}"
        os.system(cmd)

def apply_kernel_routes():
    for subnet, info in routing_table.items():
        dist = info[0]
        nh = info[1]
        update_kernel_route(subnet, nh, dist)

def broadcast_updates():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        time.sleep(UPDATE_INTERVAL)
        
        # --- Timeout Sweep ---
        changed = False
        current_time = time.time()
        for subnet, info in list(routing_table.items()):
            dist, nh, ts = info
            # If a route hasn't been updated by next hop in 3x interval, it is considered dead
            if nh != "0.0.0.0" and dist < 16 and (current_time - ts > UPDATE_INTERVAL * 3):
                routing_table[subnet][0] = 16
                changed = True
                print(f"*** ROUTE TIMEOUT: {subnet} via {nh} is dead (distance set to 16) ***")
                
        if changed:
            apply_kernel_routes()

        for neighbor in NEIGHBORS:
            if not neighbor:
                continue
            routes_to_send = []
            for subnet, info in routing_table.items():
                dist = info[0]
                nh = info[1]
                adv_dist = 16 if nh == neighbor else dist
                routes_to_send.append({"subnet": subnet, "distance": adv_dist})
            packet = {
                "router_id": MY_IP,
                "version": 1.0,
                "routes": routes_to_send
            }
            try:
                sock.sendto(json.dumps(packet).encode(), (neighbor, PORT))
            except Exception as e:
                print(f"Error sending to {neighbor}: {e}")

def listen_for_updates():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))
    print(f"Listening on port {PORT}...")
    while True:
        data, addr = sock.recvfrom(4096)
        neighbor_ip = addr[0]
        try:
            packet = json.loads(data.decode())
            threading.Thread(target=update_logic, args=(neighbor_ip, packet), daemon=True).start()
        except Exception as e:
            print(f"Error decoding packet from {neighbor_ip}: {e}")

def update_logic(neighbor_ip, packet):
    global routing_table
    changed = False
    if packet.get("version") != 1.0:
        return
    received_routes = packet.get("routes", [])
    for route in received_routes:
        subnet = route["subnet"]
        dist_from_neighbor = route["distance"]
        
        # We process distances >= 16 properly to deal with poisoned routes
        candidate_dist = min(dist_from_neighbor + 1, 16)
        
        if subnet not in routing_table:
            # We don't want to initially learn unreachable routes
            if candidate_dist < 16:
                routing_table[subnet] = [candidate_dist, neighbor_ip, time.time()]
                changed = True
        else:
            current_dist, current_nh, current_ts = routing_table[subnet]
            # If the neighbor is our next-hop, always update our distance to reflect theirs
            if current_nh == neighbor_ip:
                routing_table[subnet][2] = time.time() # Refresh the timestamp!
                if candidate_dist != current_dist:
                    routing_table[subnet][0] = candidate_dist
                    changed = True
            # Better route via a different neighbor
            elif candidate_dist < current_dist:
                routing_table[subnet] = [candidate_dist, neighbor_ip, time.time()]
                changed = True
                
    if changed:
        apply_kernel_routes()
        print("Routing table updated:")
        for s, info in routing_table.items():
            print(f"  {s} -> via {info[1]} (distance {info[0]})")

if __name__ == "__main__":
    init_routing_table()
    apply_kernel_routes()
    print("Initial routing table:")
    for s, info in routing_table.items():
        print(f"  {s} -> via {info[1]} (distance {info[0]})")
    threading.Thread(target=broadcast_updates, daemon=True).start()
    listen_for_updates()