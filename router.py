import socket
import json
import threading
import time
import os
import subprocess
import ipaddress


MY_IP = os.getenv("MY_IP", "127.0.0.1")
NEIGHBORS = [n for n in os.getenv("NEIGHBORS", "").split(",") if n]
NEIGHBOR_SET = set(NEIGHBORS)
PORT = 5000
UPDATE_INTERVAL = 3
ROUTE_TIMEOUT = UPDATE_INTERVAL * 4
INFINITY = 16


local_subnets = set()
neighbor_routes = {}
routing_table = {}

state_lock = threading.Lock()
triggered_update = threading.Event()


def discover_local_subnets():
    """Derive directly-connected subnets from interface addresses (stable even
    when the kernel routing table has been mutated by external tools)."""
    found = set()
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True, text=True
        )
        for raw in result.stdout.splitlines():
            line = raw.strip()
            if not line.startswith("inet "):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                iface = ipaddress.ip_interface(parts[1])
            except ValueError:
                continue
            net = str(iface.network)
            if net.startswith("127.") or net.startswith("169.254."):
                continue
            found.add(net)
    except Exception as e:
        print(f"Address scan error: {e}")
    return found


def refresh_local_subnets_locked():
    global local_subnets
    current = discover_local_subnets()
    if current != local_subnets:
        print(f"Interfaces changed: {sorted(local_subnets)} -> {sorted(current)}")
        local_subnets = current
        return True
    return False


def compute_routes_locked():
    now = time.time()
    table = {}
    for subnet in local_subnets:
        table[subnet] = (0, "0.0.0.0")
    for nh, adv in neighbor_routes.items():
        for subnet, (dist, ts) in adv.items():
            if now - ts > ROUTE_TIMEOUT:
                continue
            if dist >= INFINITY:
                continue
            candidate = dist + 1
            if candidate >= INFINITY:
                continue
            existing = table.get(subnet)
            if existing is None:
                table[subnet] = (candidate, nh)
                continue
            ex_dist, ex_nh = existing
            if ex_dist == 0:
                continue
            if candidate < ex_dist or (candidate == ex_dist and nh < ex_nh):
                table[subnet] = (candidate, nh)
    return table


def apply_kernel_diff_locked(old_table, new_table):
    for subnet in set(old_table) | set(new_table):
        old = old_table.get(subnet)
        new = new_table.get(subnet)
        if old == new:
            continue
        old_nh = old[1] if old else None
        new_nh = new[1] if new else None
        if old_nh and old_nh != "0.0.0.0" and old_nh != new_nh:
            os.system(f"ip route del {subnet} via {old_nh} 2>/dev/null")
        if new_nh and new_nh != "0.0.0.0":
            os.system(f"ip route replace {subnet} via {new_nh}")


def recompute_and_apply_locked():
    global routing_table
    new_table = compute_routes_locked()
    if new_table != routing_table:
        apply_kernel_diff_locked(routing_table, new_table)
        routing_table = new_table
        return True
    return False


def make_advertisement_locked(to_neighbor):
    """Split horizon with poison reverse."""
    out = []
    for subnet, (dist, nh) in routing_table.items():
        adv = INFINITY if nh == to_neighbor else dist
        out.append({"subnet": subnet, "distance": adv})
    return out


def expire_stale_neighbors_locked():
    now = time.time()
    for nh in list(neighbor_routes.keys()):
        adv = neighbor_routes[nh]
        for subnet in list(adv.keys()):
            if now - adv[subnet][1] > ROUTE_TIMEOUT:
                del adv[subnet]
        if not adv:
            del neighbor_routes[nh]


def send_cycle(sock):
    with state_lock:
        refresh_local_subnets_locked()
        expire_stale_neighbors_locked()
        changed = recompute_and_apply_locked()
        snapshots = {n: make_advertisement_locked(n) for n in NEIGHBORS}

    for neighbor, routes in snapshots.items():
        pkt = {"router_id": MY_IP, "version": 1.0, "routes": routes}
        try:
            sock.sendto(json.dumps(pkt).encode(), (neighbor, PORT))
        except Exception as e:
            print(f"Send error to {neighbor}: {e}")

    if changed:
        with state_lock:
            print("Routing table:")
            for s, (d, nh) in sorted(routing_table.items()):
                print(f"  {s} -> via {nh} (dist {d})")


def broadcast_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    req_pkt = json.dumps({
        "router_id": MY_IP, "version": 1.0, "request": True, "routes": []
    }).encode()
    for n in NEIGHBORS:
        try:
            sock.sendto(req_pkt, (n, PORT))
        except Exception:
            pass
    send_cycle(sock)
    while True:
        triggered_update.wait(timeout=UPDATE_INTERVAL)
        triggered_update.clear()
        send_cycle(sock)


def respond_to_request(neighbor_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with state_lock:
        routes = make_advertisement_locked(neighbor_ip)
    pkt = {"router_id": MY_IP, "version": 1.0, "routes": routes}
    try:
        sock.sendto(json.dumps(pkt).encode(), (neighbor_ip, PORT))
    except Exception as e:
        print(f"Respond error to {neighbor_ip}: {e}")
    sock.close()


def handle_packet(neighbor_ip, packet):
    # Critical: reject advertisements whose source IP isn't a configured
    # neighbor. Otherwise forwarded (transit) packets get cached with an
    # unreachable next hop and blackhole traffic through this router.
    if neighbor_ip not in NEIGHBOR_SET:
        return
    if packet.get("version") != 1.0:
        return
    if packet.get("request"):
        respond_to_request(neighbor_ip)
        return

    now = time.time()
    new_adv = {}
    for r in packet.get("routes") or []:
        subnet = r.get("subnet")
        dist = r.get("distance")
        if subnet is None or dist is None:
            continue
        try:
            new_adv[subnet] = (int(dist), now)
        except (TypeError, ValueError):
            continue

    with state_lock:
        neighbor_routes[neighbor_ip] = new_adv
        changed = recompute_and_apply_locked()

    if changed:
        triggered_update.set()


def listen_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))
    print(f"Listening on port {PORT}...")
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            packet = json.loads(data.decode())
            handle_packet(addr[0], packet)
        except Exception as e:
            print(f"Listen error: {e}")


if __name__ == "__main__":
    os.system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1")
    print(f"MY_IP={MY_IP} NEIGHBORS={NEIGHBORS}")
    time.sleep(2)
    with state_lock:
        refresh_local_subnets_locked()
        recompute_and_apply_locked()
    print(f"Local subnets: {sorted(local_subnets)}")
    print("Initial routing table:")
    for s, (d, nh) in sorted(routing_table.items()):
        print(f"  {s} -> via {nh} (dist {d})")

    threading.Thread(target=broadcast_loop, daemon=True).start()
    listen_loop()
