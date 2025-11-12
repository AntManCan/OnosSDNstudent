# ONOS Learning Bridge - Quick Reference Card

## 🚀 Quick Start

```bash
cd /workspaces/OnosSDN
./build.sh
```

## 📦 Build & Install

```bash
# Build (inside dev container)
cd /workspaces/OnosSDN
./build.sh

# Start ONOS (separate terminal)
cd /opt/onos && ./bin/onos-service start

# Open ONOS CLI (password: rocks)
onos-cli

# Install bundle
onos> bundle:install -s file:/workspaces/OnosSDN/target/learning-bridge-1.0-SNAPSHOT.jar
onos> bundle:list | grep learning

# Update bundle after code changes
onos> bundle:list | grep learning  # note the ID (e.g., 200)
onos> bundle:update 200 file:/workspaces/OnosSDN/target/learning-bridge-1.0-SNAPSHOT.jar
```

## 🎮 ONOS Controller

```bash
# Start/Stop/Restart
/opt/onos/bin/onos-service start
/opt/onos/bin/onos-service stop
/opt/onos/bin/onos-service restart

# Status
/opt/onos/bin/onos-service status
ps aux | grep karaf
```

## 💻 Access Points

| Interface | URL/Command | Credentials |
|-----------|-------------|-------------|
| Web GUI | http://localhost:8181/onos/ui | onos/rocks |
| CLI | `onos-cli` | password: rocks |
| REST API | http://localhost:8181/onos/v1/ | onos/rocks |

## 🔧 ONOS CLI Commands

```bash
# Application management
apps -s -a              # List active apps
app activate <name>     # Activate app
app deactivate <name>   # Deactivate app

# Network view
devices                 # List switches
hosts                   # List hosts
links                   # List links
flows                   # List flow rules
flows -n                # List flows (no core flows)

# Bundle management
bundle:list | grep learning  # Find bundle
bundle:update <ID> file:/workspaces/OnosSDN/target/learning-bridge-1.0-SNAPSHOT.jar

# Logs
log:display             # Show logs
log:set DEBUG org.onosproject.learningbridge  # Set log level
```

## 🌐 Mininet (in VM)

```bash
# Test connectivity to ONOS in dev container
nc -vz <HOST_IP> 6653

# Start Mininet with remote ONOS controller (using course script)
sudo ./start-mininet.py <HOST_IP>

# Alternative manual start
sudo mn --topo tree,2 --mac --switch ovsk,protocols=OpenFlow13 --controller remote,ip=<HOST_IP>,port=6653

# Clean up (in VM)
sudo mn -c

# In Mininet CLI (on VM)
pingall                 # Test connectivity
h1 ping h2              # Ping between hosts
xterm h1                # Open terminal for h1
dump                    # Show network info
exit                    # Exit Mininet
```

**Note**: Replace `<HOST_IP>` with your host's IP address as seen from the VM:
- NAT/Bridged network: Your host's LAN IP (e.g., `192.168.1.100`)
- Host-Only network: Typically `192.168.56.1`

## 📊 Testing (in Mininet VM)

### Test Connection Limiting (Recommended: xterm)

```bash
# Open three terminal windows for one host
mininet> xterm h1 h1 h1

# In h1's xterm windows:
# Terminal 1: ping 10.0.0.2  # Should work ✅
# Terminal 2: ping 10.0.0.3  # Should work ✅
# Terminal 3: ping 10.0.0.4  # Should be BLOCKED ❌ (limit: 2)

# Stop Terminal 1, wait ~30 seconds for flow timeout
# Terminal 3 should now work ✅ (connection slot freed)
```

### Test TCP Statistics

```bash
# Open xterm windows
mininet> xterm h1 h2

# In h2's terminal (server):
h2# iperf -s

# In h1's terminal (client):
h1# iperf -c 10.0.0.2 -t 10  # Send TCP traffic for 10 seconds

# After the flow expires (30 seconds), check logs in dev container:
tail /tmp/tcp_connections.log
# Should show: bytes transferred, packet count, duration
```

### Test with HTTP

```bash
# Start HTTP server on h1
mininet> h1 python3 -m http.server 8000 &

# Make requests from h2
mininet> h2 curl http://10.0.0.1:8000
```

## 📝 Logs & Statistics (in Dev Container)

```bash
# Application logs
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep LearningBridge

# All ONOS logs
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log

# Connection statistics
cat /tmp/tcp_connections.log
tail -f /tmp/tcp_connections.log  # follow live updates

# Monitor connection tracking
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep -E "(Connection ended|Active destinations)"
```

## ⚙️ Configuration

Edit `src/main/java/org/onosproject/learningbridge/LearningBridgeApp.java`:

```java
MAX_CONNECTIONS_PER_HOST = 2;     // Connection limit (applies to all traffic)
FLOW_TIMEOUT = 30;                // Flow rule timeout (seconds)
LOG_FILE_PATH = "/tmp/tcp_connections.log";  // TCP stats file
```

Rebuild and update bundle after changes.

## 🔍 Debugging

```bash
# Increase log level (in ONOS CLI)
onos> log:set DEBUG org.onosproject.learningbridge

# View specific logs
onos> log:display | grep LearningBridge

# Check application status
onos> apps -s | grep learning

# View flows
onos> flows -n

# Check which apps are active
onos> apps -s -a
```

## 🐛 Troubleshooting

| Problem | Solution |
|---------|----------|
| `no matching host key type found` | Create `onos-cli` wrapper (see GETTING_STARTED.md Step 4) |
| ONOS won't start | Check Java 11: `java -version` |
| Build fails | Check Maven: `mvn -version` |
| Switches don't connect | Activate OpenFlow: `app activate org.onosproject.openflow` |
| Can't access GUI | Check port 8181: `netstat -an \| grep 8181` |
| VM can't reach ONOS | Verify `nc -vz <HOST_IP> 6653` from VM; check port forwarding in VS Code Ports panel |
| Mininet hangs | ONOS not reachable; check controller IP and port |
| Mininet can't ping | Activate: openflow, hostprovider, lldpprovider; DEACTIVATE fwd |
| Broadcast packets blocked | Fixed - broadcast/multicast excluded from limits |
| Connection slots not freed | Fixed - cleanup works for all protocols (ICMP, TCP, UDP) |
| Old code still running | Use `bundle:update <ID>` not reinstall |

## 📋 Essential Files

| File | Purpose |
|------|---------|
| `LearningBridgeApp.java` | Main application code |
| `pom.xml` | Maven build config |
| `build.sh` | Build script (run after each change) |
| `GETTING_STARTED.md` | Complete setup guide |
| `ONOS_DEVELOPMENT_GUIDE.md` | Full documentation |
| `README.md` | Project overview |

## 🔗 Key Directories (Dev Container)

| Path | Contents |
|------|----------|
| `/opt/onos` | ONOS installation |
| `/workspaces/OnosSDN` | Project files |
| `/tmp/tcp_connections.log` | TCP statistics output |

**Note**: Mininet is NOT in the dev container. Use a separate VM.

## 🎯 Common Workflow

```bash
# 1. Edit code (in dev container)
vim /workspaces/OnosSDN/src/main/java/org/onosproject/learningbridge/LearningBridgeApp.java

# 2. Build (in dev container)
cd /workspaces/OnosSDN
./build.sh

# 3. Update bundle (in ONOS CLI in dev container)
onos-cli
onos> bundle:list | grep learning  # note bundle ID
onos> bundle:update <ID> file:/workspaces/OnosSDN/target/learning-bridge-1.0-SNAPSHOT.jar

# 4. Test (in Mininet VM)
sudo ./start-mininet.py <HOST_IP>
mininet> xterm h1 h1 h1
# Test connection limiting...

# 5. Monitor (in dev container)
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep LearningBridge
tail -f /tmp/tcp_connections.log
```

## 📱 Ports (Forwarded from Dev Container)

| Port | Service |
|------|---------|
| 6653 | OpenFlow (for Mininet VM) |
| 8101 | ONOS Karaf CLI (SSH) |
| 8181 | ONOS Web GUI |

## 📚 Documentation

- **GETTING_STARTED.md** - Start here! Complete setup walkthrough
- **README.md** - Project overview
- **ONOS_DEVELOPMENT_GUIDE.md** - In-depth development guide
- **QUICK_REFERENCE.md** - This card
- **CONNECTION_CLEANUP_FIX.md** - Technical doc on cleanup logic
- **TROUBLESHOOTING_FIX.md** - Technical doc on broadcast fix

## 🆘 Get Help

```bash
# ONOS CLI help
onos> help

# App-specific logs
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep LearningBridge

# Check bundle status
onos> bundle:list | grep learning

# Check flow rules
onos> flows -n
```

## 🎓 Key Concepts

### Connection Limiting
- Limits each host to MAX_CONNECTIONS_PER_HOST simultaneous **destinations**
- Applies to **ALL traffic types** (ICMP, TCP, UDP, etc.)
- **Excludes broadcast/multicast** (essential for ARP, DHCP)
- Dynamically frees slots when flows expire

### TCP Statistics
- Tracks TCP SYN packets to identify new connections
- Retrieves bytes/packets/duration from flow rules when they expire
- Logs to `/tmp/tcp_connections.log`

### Flow Lifecycle
1. Packet arrives → App installs flow rule (30s timeout)
2. Flow processes traffic for up to 30 seconds
3. Flow expires → FlowRuleListener detects removal
4. App checks if other flows exist between same hosts
5. If none, removes destination from active set (frees slot)

---

**Version**: 1.0 | **Updated**: Nov 2025 | **ONOS**: 2.7.0 | **Java**: 11
