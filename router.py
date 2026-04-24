import socket
import json
import threading
import time
import os
import subprocess
import ipaddress


MY_IP     = os.getenv("MY_IP", "127.0.0.1")
NEIGHBORS = [n for n in os.getenv("NEIGHBORS", "").split(",") if n]
PORT      = 5000

UPDATE_INTERVAL = 3   # seconds between periodic broadcasts (3 s is better for
                      # larger topologies; keeps convergence well under 20 s)
TIMEOUT         = 15  # seconds of silence before a neighbour is declared dead
INFINITY        = 16  # RIP-style unreachable metric

routing_table      = {}
table_lock         = threading.Lock()

neighbor_last_seen = {}      # { neighbour_ip: last_heard_timestamp }
seen_lock          = threading.Lock()

broadcast_trigger = threading.Event()


def discover_local_subnets() -> dict:
    """
    Discover every directly-connected IPv4 subnet on this router.

    Shells out to ``ip addr show`` and parses each ``inet`` line to
    derive the CIDR network of the interface. Loopback (127.0.0.0/8)
    and link-local (169.254.0.0/16) ranges are ignored because they
    must never appear in a distance-vector advertisement.

    Returns:
        dict: Mapping ``{subnet_cidr: [distance, next_hop]}`` where
        the distance is ``0`` and next-hop is ``"0.0.0.0"`` to flag
        the entry as a locally-attached (DIRECT) route.
    """
    subnets = {}
    try:
        result = subprocess.run(
            ["ip", "addr", "show"], capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("inet "):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                iface   = ipaddress.ip_interface(parts[1])
                network = str(iface.network)
                # Skip loopback and link-local
                if network.startswith("127.") or network.startswith("169.254."):
                    continue
                subnets[network] = [0, "0.0.0.0"]
            except Exception:
                pass
    except Exception as exc:
        log_message(f"[ADDR] {exc}")
    return subnets



def log_message(msg: str):
    """
    Emit a single line to stdout, prefixed with this router's IP.

    ``flush=True`` guarantees the line appears immediately in the
    container log stream, which is essential when the evaluator tails
    the log to decide whether the network has converged.

    Args:
        msg: The free-form message to print.
    """
    print(f"[{MY_IP}] {msg}", flush=True)


def display_routing_table():
    """
    Pretty-print the current routing table under the ``table_lock``.

    Each row shows the destination subnet, the computed distance, and
    whether the route is ``DIRECT`` (locally attached) or reached
    ``via <next-hop>``. Entries whose distance has reached
    ``INFINITY`` are tagged ``[INFINITY]`` so the operator can see a
    route that is being poisoned before it is withdrawn.
    """
    log_message("--- Routing Table ---")
    with table_lock:
        if not routing_table:
            log_message("  (empty)")
        for subnet, (dist, nh) in sorted(routing_table.items()):
            tag = "DIRECT" if nh == "0.0.0.0" else f"via {nh}"
            inf = " [INFINITY]" if dist >= INFINITY else ""
            log_message(f"  {subnet:<20}  dist={dist:<4}  {tag}{inf}")
    log_message("---------------------")


def add_kernel_route(subnet: str, via: str):
    """
    Install (or overwrite) a route in the Linux kernel FIB.

    Uses ``ip route replace`` so the call is idempotent: a fresh route
    is created if none exists, and any previous entry for the same
    destination is atomically replaced.

    Args:
        subnet: Destination network in CIDR form (e.g. ``10.0.1.0/24``).
        via:    IPv4 address of the next-hop neighbour.
    """
    ret = os.system(f"ip route replace {subnet} via {via} 2>/dev/null")
    log_message(f"ip route replace {subnet} via {via}  (exit={ret})")


def delete_kernel_route(subnet: str, via: str = ""):
    """
    Remove a route from the Linux kernel FIB.

    If ``via`` is supplied, only the specific next-hop entry is
    removed – this matters when the same subnet has multiple
    candidate next-hops and we only want to purge the stale one.
    Otherwise every installed entry for ``subnet`` is deleted.

    Args:
        subnet: Destination network in CIDR form.
        via:    Optional next-hop IP to target a specific FIB entry.
    """
    if via:
        ret = os.system(f"ip route del {subnet} via {via} 2>/dev/null")
    else:
        ret = os.system(f"ip route del {subnet} 2>/dev/null")
    log_message(f"ip route del {subnet}  (exit={ret})")



def sync_directly_connected_routes() -> bool:
    """
    Reconcile the routing table with the current list of local subnets.

    This runs on every housekeeping tick to catch two situations:

    1. A new interface / subnet has appeared on the host – we must
       add it to the routing table so neighbours learn it.
    2. A subnet that is actually directly attached was mistakenly
       learned as a remote route earlier (possible during the first
       few seconds before interfaces came up). The stale remote route
       is deleted from the kernel and replaced with the DIRECT entry.

    Returns:
        bool: ``True`` if the routing table was modified (so the
        caller should trigger a broadcast), ``False`` otherwise.
    """
    direct  = discover_local_subnets()
    changed = False
    with table_lock:
        for subnet, entry in direct.items():
            current = routing_table.get(subnet)
            if current is None:
                log_message(f"New interface discovered: {subnet}")
                routing_table[subnet] = entry
                changed = True
            elif current[1] != "0.0.0.0":
                # We wrongly learned this subnet as a remote route before
                # we knew we had a direct interface on it.
                old_via = current[1]
                log_message(f"Fixing wrongly-learned direct subnet {subnet} "
                    f"(was via {old_via})")
                delete_kernel_route(subnet, via=old_via)
                routing_table[subnet] = entry
                changed = True
    return changed

def construct_update_packet(exclude_next_hop: str | None = None) -> bytes:
    """
    Build a JSON-encoded distance-vector advertisement.

    Applies two classic loop-prevention techniques:

    * **Split horizon** – a reachable route learned from ``X`` is
      *not* re-advertised back to ``X``.
    * **Route poisoning** – a route that has been marked unreachable
      (distance ``>= INFINITY``) is still advertised, but with a
      distance of ``INFINITY`` so neighbours drop it quickly.

    Args:
        exclude_next_hop: IP of the neighbour we are about to send
            this packet to. Routes learned via that neighbour are
            omitted (split horizon). ``None`` disables split horizon.

    Returns:
        bytes: UTF-8 encoded JSON ready to be handed to ``sendto``.
    """
    routes = []
    with table_lock:
        for subnet, (dist, nh) in routing_table.items():

            if dist < INFINITY:
                # Reachable route: apply split horizon
                if exclude_next_hop and nh == exclude_next_hop:
                    continue          # don't advertise back to who we learned from
                routes.append({"subnet": subnet, "distance": dist})

            else:
                if nh == "0.0.0.0":
                    continue          # direct routes can't be infinity; skip
                routes.append({"subnet": subnet, "distance": INFINITY})

    return json.dumps({
        "router_id": MY_IP,
        "version":   1.0,
        "routes":    routes,
    }).encode()


def send_periodic_updates():
    """
    Long-running thread that pushes advertisements to every neighbour.

    Every ``UPDATE_INTERVAL`` seconds (or immediately when
    ``broadcast_trigger`` is set by a triggered update), a custom
    packet is built for each neighbour – custom because split-horizon
    omits the routes learned from that specific neighbour. The
    ``broadcast_trigger`` event lets other threads request an
    out-of-cycle send (e.g. after a topology change) which is what
    gives the protocol its sub-second reaction time on failures.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        for neighbor_dst in NEIGHBORS:
            data = construct_update_packet(exclude_next_hop=neighbor_dst)
            try:
                sock.sendto(data, (neighbor_dst, PORT))
                log_message(f"TX → {neighbor_dst}")
            except Exception as exc:
                log_message(f"TX error → {neighbor_dst}: {exc}")

        broadcast_trigger.clear()
        broadcast_trigger.wait(timeout=UPDATE_INTERVAL)


def receive_neighbor_updates():
    """
    Long-running thread that receives advertisements from neighbours.

    Binds a UDP socket on ``0.0.0.0:PORT`` and blocks on ``recvfrom``.
    The source IP of the datagram is used as the authoritative
    next-hop (ignoring whatever ``router_id`` the neighbour self-
    reports, which defends against misconfiguration). On every valid
    packet it:

    1. Updates the liveness timestamp for the neighbour.
    2. Hands the route list to :func:`process_received_routes` to run
       the Bellman-Ford relaxation step.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))
    log_message(f"Listening on UDP :{PORT}")

    while True:
        try:
            data, addr  = sock.recvfrom(65535)
            neighbor_ip = addr[0]      # UDP source IP = correct next-hop

            packet = json.loads(data.decode())
            if packet.get("version") != 1.0:
                log_message(f"Ignored bad version from {neighbor_ip}")
                continue

            with seen_lock:
                neighbor_last_seen[neighbor_ip] = time.time()

            process_received_routes(neighbor_ip, packet.get("routes", []))

        except json.JSONDecodeError:
            log_message("Malformed JSON – ignoring")
        except Exception as exc:
            log_message(f"RX error: {exc}")



def process_received_routes(neighbor_ip: str, routes_from_neighbor: list):
    """
    Apply the Bellman-Ford update rule to a batch of received routes.

    For each advertised ``(subnet, distance)`` pair the new candidate
    distance is ``distance + 1`` (uniform link cost). The function
    then decides what to do with it:

    * **DIRECT routes are sacred** – we never let a remote
      advertisement overwrite a locally-attached subnet.
    * **Poison received** – if the neighbour advertises the route as
      unreachable *and* it was the one we currently use, the route is
      withdrawn from the kernel and marked ``INFINITY``.
    * **New destination** – installed straight away.
    * **Shorter path** – installed, replacing the old entry.
    * **Same next-hop, changed metric** – always follow the
      incumbent; if it just got worse it may indicate a downstream
      failure, so we update (and potentially withdraw) accordingly.

    Whenever the table changes a triggered update is scheduled via
    ``broadcast_trigger.set()`` so neighbours learn quickly.

    Args:
        neighbor_ip:          IP of the neighbour that sent the update.
        routes_from_neighbor: List of ``{"subnet", "distance"}`` dicts.
    """
    changed = False

    with table_lock:
        for route in routes_from_neighbor:
            subnet     = route.get("subnet")
            their_dist = route.get("distance")
            if subnet is None or their_dist is None:
                continue

            new_distance = their_dist + 1    # uniform link cost = 1
            current      = routing_table.get(subnet)

            if current is not None and current[1] == "0.0.0.0":
                continue

            if new_distance >= INFINITY:
                if current is not None and current[1] == neighbor_ip:
                    log_message(f"Withdrawal received for {subnet} from {neighbor_ip}")
                    routing_table[subnet] = [INFINITY, neighbor_ip]
                    delete_kernel_route(subnet)
                    changed = True

            elif current is None:
                routing_table[subnet] = [new_distance, neighbor_ip]
                add_kernel_route(subnet, neighbor_ip)
                changed = True

            elif new_distance < current[0]:
                routing_table[subnet] = [new_distance, neighbor_ip]
                add_kernel_route(subnet, neighbor_ip)
                changed = True

            elif current[1] == neighbor_ip and new_distance != current[0]:
                routing_table[subnet] = [new_distance, neighbor_ip]
                if new_distance < INFINITY:
                    add_kernel_route(subnet, neighbor_ip)
                else:
                    delete_kernel_route(subnet)
                changed = True

    if changed:
        display_routing_table()
        broadcast_trigger.set()     # triggered update: wake broadcast thread now


def monitor_neighbor_health():
    """
    Housekeeping thread – runs once per ``UPDATE_INTERVAL``.

    Two responsibilities:

    1. **Re-scan local interfaces** so freshly added subnets are
       advertised and stale remote entries for them are fixed.
    2. **Expire silent neighbours** – any neighbour that has not sent
       a packet for more than ``TIMEOUT`` seconds is declared dead;
       every route that used it as next-hop is poisoned and kicked
       out of the kernel FIB. A triggered update is then fired so the
       rest of the network converges without waiting for the next
       periodic broadcast.
    """
    while True:
        time.sleep(UPDATE_INTERVAL)

        # ── 1. Refresh directly-connected subnets ──────────────────────────
        if sync_directly_connected_routes():
            display_routing_table()
            broadcast_trigger.set()

        # ── 2. Expire silent neighbours ────────────────────────────────────
        now = time.time()
        with seen_lock:
            dead = [ip for ip, ts in neighbor_last_seen.items()
                    if now - ts > TIMEOUT]

        for dead_ip in dead:
            log_message(f"Neighbour {dead_ip} timed out – invalidating routes")
            changed = False
            with table_lock:
                for subnet, (dist, nh) in list(routing_table.items()):
                    if nh == dead_ip:
                        routing_table[subnet] = [INFINITY, dead_ip]
                        delete_kernel_route(subnet)
                        changed = True
            if changed:
                display_routing_table()
                broadcast_trigger.set()   # immediately tell neighbours the path is dead
            with seen_lock:
                neighbor_last_seen.pop(dead_ip, None)

if __name__ == "__main__":
    log_message(f"Router starting.  Neighbours: {NEIGHBORS}")
    
    time.sleep(2)




    routing_table = discover_local_subnets()

    
    log_message(f"Seeded direct subnets: {list(routing_table.keys())}")
    display_routing_table()

    threading.Thread(target=send_periodic_updates, daemon=True).start()
    threading.Thread(target=monitor_neighbor_health,   daemon=True).start()

    receive_neighbor_updates()
