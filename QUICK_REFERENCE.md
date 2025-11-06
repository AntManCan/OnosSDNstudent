# ONOS Learning Bridge - Quick Reference Card

## 🚀 Quick Start (Build Only)
```bash
cd /workspaces/OpenFlow
./build.sh
```

## 📦 Build & Install (Manual)
```bash
# Build (inside dev container)
cd /workspaces/OpenFlow
mvn clean package -DskipTests

# Start ONOS (separate terminal)
cd /opt/onos && ./bin/onos-service start

# Open ONOS CLI (user: onos, pass: rocks)
/opt/onos/bin/onos -l onos localhost

# Install your build (choose ONE)
# A) Reliable (offline): Karaf bundle install
onos> bundle:install -s file:/workspaces/OpenFlow/target/learning-bridge-1.0-SNAPSHOT.jar

# B) ONOS app subsystem
onos> app install /workspaces/OpenFlow/target/learning-bridge-1.0-SNAPSHOT.jar
onos> app activate org.onosproject.learningbridge
```

## 🎮 ONOS Controller
```bash
# Start/Stop/Restart
/opt/onos/bin/onos-service start
/opt/onos/bin/onos-service stop
/opt/onos/bin/onos-service restart

# Status
/opt/onos/bin/onos-service status
```

## 💻 Access Points
| Interface | URL/Command | Credentials |
|-----------|-------------|-------------|
| Web GUI | http://localhost:8181/onos/ui | onos/rocks |
| CLI | `/opt/onos/bin/onos -l onos localhost` | onos/rocks |
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

# Logs
log:display             # Show logs
log:set DEBUG <class>   # Set log level
```

## 🌐 Mininet (in VM)
```bash
# Test connectivity to ONOS in dev container
nc -vz <HOST_IP> 6653

# Start Mininet with remote ONOS controller
sudo mn --topo tree,2 --mac --switch ovsk,protocols=OpenFlow13 --controller remote,ip=<HOST_IP>,port=6653

# Common topologies
sudo mn --topo linear,2 --mac --switch ovsk,protocols=OpenFlow13 --controller remote,ip=<HOST_IP>,port=6653
sudo mn --topo tree,depth=2,fanout=2 --mac --switch ovsk,protocols=OpenFlow13 --controller remote,ip=<HOST_IP>,port=6653

# Clean up (in VM)
sudo mn -c

# In Mininet CLI (on VM)
pingall                 # Test connectivity
h1 ping h2              # Ping between hosts
dump                    # Show network info
exit                    # Exit Mininet
```

**Note**: Replace `<HOST_IP>` with your host's IP address as seen from the VM:
- Bridged network: Your host's LAN IP (e.g., `192.168.1.100`)
- Host-Only network: Typically `192.168.56.1`

## 📊 Testing (in Mininet VM)
```bash
# Start iperf servers on different hosts
mininet> h2 iperf -s -p 5001 &
mininet> h3 iperf -s -p 5002 &
mininet> h4 iperf -s -p 5003 &

# Create connections to test connection limits
mininet> h1 iperf -c 10.0.0.2 -p 5001 -t 60 &
mininet> h1 iperf -c 10.0.0.3 -p 5002 -t 60 &
# ... repeat to test limit (default: 2 concurrent connections per host)

# HTTP server test
mininet> h1 python3 -m http.server 8000 &
mininet> h2 curl http://10.0.0.1:8000
mininet> h2 curl http://10.0.0.1:8000  # repeat to hit limit
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
```

## 🛠️ Makefile Commands
```bash
make help       # Show all commands
make build      # Build application
make install    # (Optional) custom install target if provided
make start      # Start ONOS
make stop       # Stop ONOS
make test       # Start Mininet
make logs       # View logs
make stats      # View statistics
make cli        # Open ONOS CLI
make status     # Show status
make clean      # Clean build
```

## ⚙️ Configuration
Edit `LearningBridgeApp.java`:
```java
MAX_CONNECTIONS_PER_HOST = 5;     // Connection limit
FLOW_TIMEOUT = 30;                // Flow rule timeout (seconds)
LOG_FILE_PATH = "/tmp/tcp_connections.log";  // Stats file
```

## 🔍 Debugging
```bash
# Increase log level (in ONOS CLI)
log:set DEBUG org.onosproject.learningbridge

# View specific logs
log:display | grep LearningBridge

# Check application status
apps -s | grep learningbridge

# View flows
flows -s
```

## 🐛 Troubleshooting
| Problem | Solution |
|---------|----------|
| ONOS won't start | Check Java 11: `java -version` |
| Build fails | Check Maven: `mvn -version` |
| Switches don't connect | Activate OpenFlow: `app activate org.onosproject.openflow` |
| Can't access GUI | Check port 8181: `netstat -an \| grep 8181` |
| VM can't reach ONOS | Verify `nc -vz <HOST_IP> 6653` from VM; check port forwarding in VS Code |
| Mininet hangs | ONOS not reachable; check controller IP and port |
| Mininet issues | Clean: `sudo mn -c` (in VM) |

## 📋 Essential Files
| File | Purpose |
|------|---------|
| `LearningBridgeApp.java` | Main application code |
| `pom.xml` | Maven build config |
| `build.sh` | Build script (run after each change) |
| `test_topology.py` | Example Mininet topology (copy to VM if needed) |
| `GETTING_STARTED.md` | Complete setup guide |
| `ONOS_DEVELOPMENT_GUIDE.md` | Full documentation |
| `README.md` | Project overview |

## 🔗 Key Directories (Dev Container)
| Path | Contents |
|------|----------|
| `/opt/onos` | ONOS installation |
| `/workspaces/OpenFlow` | Project files |

**Note**: Mininet is NOT in the dev container. Use a separate VM.

## 🎯 Common Workflow
```bash
# 1. Edit code (in dev container)
vim /workspaces/OpenFlow/src/main/java/org/onosproject/learningbridge/LearningBridgeApp.java

# 2. Build (in dev container)
cd /workspaces/OpenFlow
./build.sh

# 3. Update bundle (in ONOS CLI in dev container)
onos-cli
onos> bundle:list | grep learning  # note bundle ID
onos> bundle:update <ID> file:/workspaces/OpenFlow/target/learning-bridge-1.0-SNAPSHOT.jar

# 4. Test (in Mininet VM)
sudo mn --topo tree,2 --mac --switch ovsk,protocols=OpenFlow13 --controller remote,ip=<HOST_IP>,port=6653

# 5. Monitor (in dev container)
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep LearningBridge
```

## 📱 Ports (Forwarded from Dev Container)
| Port | Service |
|------|---------|
| 6653 | OpenFlow (for Mininet VM) |
| 8101 | ONOS Karaf CLI (SSH) |
| 8181 | ONOS Web GUI |

## 📚 Documentation
- Full Guide: `DEVELOPMENT_GUIDE.md`
- Project Info: `README.md`
- Migration Notes: `MIGRATION_SUMMARY.md`
- This Card: `QUICK_REFERENCE.md`

## 🆘 Get Help
```bash
# ONOS CLI help
help

# App-specific logs
log:display | grep LearningBridge

# System status
make status
```

---
**Version**: 1.0 | **Updated**: Nov 2025 | **ONOS**: 2.7.0 | **Java**: 11
