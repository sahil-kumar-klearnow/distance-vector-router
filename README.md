# 🚀 Custom Distance Vector Router

## 📌 Overview
This project implements a **Distance-Vector Routing Protocol**  from scratch using Python.  
Each router runs inside a Docker container and dynamically discovers network topology using UDP communication.

The router uses the **Bellman-Ford algorithm** to calculate shortest paths and updates the Linux routing table in real time.

---

## 🎯 Features
- ✅ Distance Vector Routing (Bellman-Ford Algorithm)
- ✅ UDP-based communication between routers
- ✅ Dynamic routing table updates
- ✅ Split Horizon with Poisoned Reverse (loop prevention)
- ✅ Route timeout & failure detection
- ✅ Linux kernel routing table integration (`ip route`)
- ✅ Docker-based network simulation

---

## 🧠 Concepts Used
- Computer Networks (Routing Protocols)
- Bellman-Ford Algorithm
- Distance Vector Routing
- UDP Socket Programming
- Docker Networking
- Linux Networking Commands

---

## 🏗️ Project Structure
```text
.
├── router.py            # Main routing daemon
├── Dockerfile           # Docker image setup
├── docker-compose.yml   # (Optional) Multi-container setup
├── README.md            # Project documentation
```

---

## 🌐 Network Topology

This project simulates a **triangle topology**:

```text
       Router A
      /        \
  Net_AB      Net_AC
    /            \
Router B ---- Net_BC ---- Router C
```

- **Router A** → Net_AB & Net_AC  
- **Router B** → Net_AB & Net_BC  
- **Router C** → Net_BC & Net_AC  

---

## 📦 Packet Format (DV-JSON)

All routers exchange routing updates using the following JSON format:

```json
{
  "router_id": "10.0.1.1",
  "version": 1.0,
  "routes": [
    {
      "subnet": "10.0.1.0/24",
      "distance": 0
    }
  ]
}
```

---

## ⚙️ How It Works

### 1. Initialization
- Router adds directly connected subnets with distance = `0`
- Next hop = `0.0.0.0`

### 2. Broadcasting Updates
- Every 10 seconds, routers send routing tables to neighbors
- Uses **Split Horizon with Poisoned Reverse** to prevent infinite routing loops

### 3. Receiving Updates
- Routers listen on UDP port `5000`
- Incoming packets are processed asynchronously using threads

### 4. Route Calculation (Bellman-Ford)
- `New distance = neighbor distance + 1`
- Choose the shortest path
- Maximum distance = `16` (infinity bounds)

### 5. Failure Handling
- If no update is received for **30 seconds**, the route is marked unreachable
- Removed from the active routing kernel

### 6. Kernel Routing
Routes are physically applied to the OS using:
```bash
ip route replace <subnet> via <next_hop>
```

---

## 🐳 Docker Setup

### Step 1: Create Networks
```bash
docker network create --subnet=10.0.1.0/24 net_ab
docker network create --subnet=10.0.2.0/24 net_bc
docker network create --subnet=10.0.3.0/24 net_ac
```

### Step 2: Build Docker Image
```bash
docker build -t my-router .
```

### Automated Run using Docker Compose (Recommended)

Instead of running all the manual commands, you can instantly spin up the entire pre-configured triangular topology using the included `docker-compose.yml` file:
```bash
docker-compose up --build -d
```
To safely tear down the environment and free up resources when finished:
```bash
docker-compose down
```

---

### Alternative: Run Routers (Manual Example)

**Router A**
```bash
docker run -d --name router_a --privileged \
--network net_ab --ip 10.0.1.1 \
-e MY_IP=10.0.1.1 \
-e LOCAL_SUBNETS=10.0.1.0/24,10.0.3.0/24 \
-e NEIGHBORS=10.0.1.2,10.0.3.2 \
my-router

docker network connect net_ac router_a --ip 10.0.3.1
```

**Router B**
```bash
docker run -d --name router_b --privileged \
--network net_ab --ip 10.0.1.2 \
-e MY_IP=10.0.1.2 \
-e LOCAL_SUBNETS=10.0.1.0/24,10.0.2.0/24 \
-e NEIGHBORS=10.0.1.1,10.0.2.2 \
my-router

docker network connect net_bc router_b --ip 10.0.2.1
```

**Router C**
```bash
docker run -d --name router_c --privileged \
--network net_bc --ip 10.0.2.2 \
-e MY_IP=10.0.2.2 \
-e LOCAL_SUBNETS=10.0.2.0/24,10.0.3.0/24 \
-e NEIGHBORS=10.0.2.1,10.0.3.1 \
my-router

docker network connect net_ac router_c --ip 10.0.3.2
```

---

## 🧪 Testing

### ✅ Normal Operation
1. Routers exchange updates
2. Routing tables converge automatically to the shortest paths

### ❌ Failure Test
Stop Router C:
```bash
docker stop router_c
```
**Expected Result:**
1. Routes via C hit the 30-second timeout and become invalid
2. Router A successfully learns the alternate path to `10.0.2.0/24` via Router B

---

## 🔄 Routing Loop Prevention

This implementation vigorously prevents network loops using:
- 🔹 **Split Horizon with Poisoned Reverse** (Advertising bad paths back to the source)
- 🔹 **Maximum bounds** (Ceiling distance = 16)
- 🔹 **Route Timeout Mechanism** (Scanning stale routes every interval loop)

---

## 📊 Sample Routing Table Output

```text
*** ROUTE TIMEOUT: 10.0.2.0/24 via 10.0.3.2 is dead (distance set to 16) ***
Routing table updated:
  10.0.1.0/24 -> via 0.0.0.0 (distance 0)
  10.0.3.0/24 -> via 0.0.0.0 (distance 0)
  10.0.2.0/24 -> via 10.0.1.2 (distance 1)
```

---

## 🚧 Challenges Faced
- Overcoming asynchronous UDP staleness
- Mapping Bellman-Ford theories to practical packet updates
- Handling live Linux kernel tables dynamically inside isolated Docker containers
- Enforcing timeout loops without interrupting active broadcast threads

---

## 👨‍💻 Author
**Sahil Kumar**
