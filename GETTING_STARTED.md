# Getting Started with ONOS Learning Bridge

**Two-environment setup:** Develop in a dev container, test with Mininet in a VM.

---

## Prerequisites

- **Docker Desktop** (Windows/macOS) or **Docker Engine** (Linux)
- **VS Code** with **Dev Containers** extension
- **VirtualBox** (or VMware/Hyper-V) with a Mininet VM
- 4+ GB RAM for Docker

---

## Part 1: Dev Container (ONOS Development)

### Step 1: Open Dev Container

1. Open this folder in VS Code
2. Click **"Reopen in Container"** (or press `F1` → "Dev Containers: Reopen in Container")
3. Wait 5–10 minutes for first-time setup
   - ☕ Installs Java 11, ONOS 2.7.0, Maven

---

### Step 2: Build the Application

```bash
cd /workspaces/OpenFlow
./build.sh
```

Output: `target/learning-bridge-1.0-SNAPSHOT.jar`

**Rebuild after every code change.**

---

### Step 3: Start ONOS

```bash
cd /opt/onos
./bin/onos-service start
```

Verify it's running:
```bash
ps aux | grep karaf
```

Wait ~30-45 seconds for startup.

---

### Step 4: Open Onos CLI 

```bash
onos-cli
# Password: rocks
```

---

### Step 5: Install Your Bundle

In the ONOS CLI:

```text
onos> bundle:install -s file:/workspaces/OpenFlow/target/learning-bridge-1.0-SNAPSHOT.jar
onos> bundle:list | grep learning
```

**After code changes**, update instead of reinstalling:
```text
onos> bundle:list | grep learning       # note the ID (e.g., 200)
onos> bundle:update 200 file:/workspaces/OpenFlow/target/learning-bridge-1.0-SNAPSHOT.jar
```

---

### Step 6: Activate Core Apps (First Time Only)

```text
onos> app activate org.onosproject.openflow
onos> app activate org.onosproject.hostprovider
onos> app activate org.onosproject.lldpprovider
onos> app activate org.onosproject.fwd
```

These enable OpenFlow, host discovery, and forwarding.

---

### Step 7: Verify Port Forwarding

Check VS Code **Ports** panel (bottom toolbar):
- **6653** - ONOS OpenFlow (for Mininet VM)
- **8101** - ONOS CLI (SSH)
- **8181** - ONOS Web UI

Ports should auto-forward. Add manually if missing.

---

## Part 2: Mininet VM (Testing)

### Step 8: Set Up VM

**Option A:** Download [Official Mininet VM](http://mininet.org/download/) if you have X86 machine

**Option B:** Download the course VM with mininet from 
https://tele1.dee.fct.unl.pt/cgr. in the link shared in the laboratories page, 

**Network Config** (VirtualBox):
- **Bridged Adapter**: VM on LAN (use host's LAN IP, e.g., 192.168.1.100)
- **Host-Only Adapter**: VM isolated (use 192.168.56.1)

**Find your host IP:**
```bash
# On host machine
ip addr    # Linux/macOS
ipconfig   # Windows
```

Note the IP the VM can reach (LAN IP or Host-Only IP).

---

### Step 9: Test Connectivity

From the Mininet VM:

```bash
nc -vz <HOST_IP> 6653
# Example: nc -vz 192.168.1.100 6653
```

✅ If successful: Connection to 6653 port succeeded  
❌ If it fails:
- Check VS Code Ports panel shows 6653 forwarded
- Check host firewall settings
- Try Host-Only IP (192.168.56.1)

---

### Step 10: Start Mininet

From the VM:

```bash
sudo mn --topo tree,2 --mac --switch ovsk,protocols=OpenFlow13 --controller remote,ip=<HOST_IP>,port=6653
```

Replace `<HOST_IP>` with your actual IP (e.g., `192.168.1.100`).

You should get the `mininet>` prompt immediately.

**Other topologies:**
```bash
# Linear (2 switches, 2 hosts)
sudo mn --topo linear,2 --mac --switch ovsk,protocols=OpenFlow13 --controller remote,ip=<HOST_IP>,port=6653

# Tree (depth 2, fanout 2)
sudo mn --topo tree,depth=2,fanout=2 --mac --switch ovsk,protocols=OpenFlow13 --controller remote,ip=<HOST_IP>,port=6653
```

---

### Step 11: Test in Mininet

```bash
mininet> pingall

# Ping specific hosts
mininet> h1 ping h2

# HTTP server test
mininet> h1 python3 -m http.server 8000 &
mininet> h2 curl http://10.0.0.1:8000
mininet> h2 curl http://10.0.0.1:8000  # 2nd connection
mininet> h2 curl http://10.0.0.1:8000  # 3rd - should be blocked!
```

---

### Step 12: Monitor in ONOS

Back in the **dev container**:

```bash
onos-cli
```

Check the network:
```text
onos> devices     # See switches from VM
onos> ports       # Switch ports
onos> hosts       # Discovered hosts
onos> flows -n    # Flow rules
```

**View logs:**
```bash
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep LearningBridge
tail -f /tmp/tcp_connections.log
```

**Web UI** (optional):
- URL: http://localhost:8181/onos/ui
- Login: onos / rocks

---

## Development Workflow

After initial setup, repeat:

1. **Edit** code in dev container
2. **Build**: `./build.sh`
3. **Update** bundle in ONOS CLI: `bundle:update <ID> file:/...jar`
4. **Test** in Mininet VM
5. **Monitor** logs in dev container

---

## Quick Command Reference

### Dev Container
```bash
onos-cli                          # Access ONOS CLI
cd /opt/onos && ./bin/onos-service restart    # Restart ONOS
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep LearningBridge
```

### Mininet VM
```bash
sudo mn -c                        # Clean up Mininet
sudo mn --topo tree,2 --mac --switch ovsk,protocols=OpenFlow13 --controller remote,ip=<HOST_IP>,port=6653
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `no matching host key type found` | Create `onos-cli` wrapper (Step 4) |
| VM can't reach ONOS | Verify `nc -vz <HOST_IP> 6653`; check Ports panel |
| Mininet hangs "Starting switches" | ONOS not reachable; check IP and port |
| No devices in ONOS | Verify `protocols=OpenFlow13` in mn command |
| Mininet can't ping | Activate OpenFlow apps (Step 6) |
| Old code still running | Use `bundle:update <ID>` not reinstall |

---

## What's Next?

- 📖 [README.md](README.md) - Project overview
- 💻 [ONOS_DEVELOPMENT_GUIDE.md](ONOS_DEVELOPMENT_GUIDE.md) - Detailed guide
- 📋 [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Command cheat sheet

---

**Ready to develop?** Follow the steps above, then start coding! 🚀
