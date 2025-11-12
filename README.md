# ONOS Learning Bridge with Connection Limiting

A Software-Defined Networking (SDN) application built on ONOS that implements an intelligent learning bridge with connection limiting and TCP statistics logging.

## Features

- 🔄 **MAC Address Learning**: Automatically learns MAC addresses and their associated switch ports
- 🚦 **Connection Limiting**: Enforces a maximum number of simultaneous connections per host (default: 2) for ALL traffic types
- 📊 **TCP Statistics Logging**: Tracks and logs packet count, byte count, and duration for TCP connections to `/tmp/tcp_connections.log`
- ⏱️ **Flow Management**: Automatic flow rule timeout (30 seconds default)
- 🔄 **Dynamic Connection Cleanup**: Automatically frees connection slots when flows expire

---

## Architecture

**Two-tier setup for reliable development and testing:**

- **Dev Container** (this workspace): Runs ONOS 2.7.0 + Java 11 + Maven for app development
- **Mininet VM** (separate VirtualBox VM): Runs Mininet with OVS 3.5.0 for realistic network testing
- **Connection**: The VM connects to ONOS via exposed ports (6653 OpenFlow, 8101 CLI, 8181 Web UI)

---

## Requirements (auto-installed in Dev Container)

- Java 11 LTS
- Maven 3.6+
- ONOS 2.7.0
- Works on x86_64 and ARM64

---
## Requirements (outside Machine VM Host or container)
- Mininet + Open vSwitch 3.5.0

## Quick Start

### 1. Open in Dev Container

1. Open this folder in VS Code
2. **Reopen in Container** when prompted
3. Wait for setup (~5-10 minutes first time)

### 2. Build the Application

\`\`\`bash
cd /workspaces/OnosSDN
./build.sh
\`\`\`

Output: \`target/learning-bridge-1.0-SNAPSHOT.jar\`

### 3. Start ONOS

\`\`\`bash
cd /opt/onos
./bin/onos-service start
\`\`\`

Wait ~30-45 seconds for ONOS to start.

### 4. Install the Bundle

Create the CLI wrapper (first time only):

\`\`\`bash
cat > /usr/local/bin/onos-cli << 'EOF'
#!/bin/bash
ssh -o "HostKeyAlgorithms=+ssh-rsa" \\
    -o "PubkeyAcceptedAlgorithms=+ssh-rsa" \\
    -o "StrictHostKeyChecking=no" \\
    -o "UserKnownHostsFile=/dev/null" \\
    -p 8101 onos@localhost "$@"
EOF
chmod +x /usr/local/bin/onos-cli
\`\`\`

Install the bundle:

\`\`\`bash
onos-cli
# Password: rocks
\`\`\`

\`\`\`text
onos> bundle:install -s file:/workspaces/OnosSDN/target/learning-bridge-1.0-SNAPSHOT.jar
onos> bundle:list | grep learning
\`\`\`

Activate core ONOS apps (first time only):

\`\`\`text
onos> app activate org.onosproject.openflow
onos> app activate org.onosproject.hostprovider
onos> app activate org.onosproject.lldpprovider
\`\`\`

**Note:** Do NOT activate \`org.onosproject.fwd\` - it conflicts with the learning bridge app.

### 5. Set Up Mininet VM

**Download:** Get the course VM with Mininet from https://tele1.dee.fct.unl.pt/cgr (link shared in the laboratories page)

**Network Config** (VirtualBox):
- Use **NAT Network** or **Bridged Adapter**: VM can reach HOST at its IP address

**Find your host IP:**
\`\`\`bash  
# On host machine
ip addr    # Linux/macOS
ipconfig   # Windows
\`\`\`

Note the IP the VM can reach (LAN IP or Host-Only IP).

### 6. Connect Mininet to ONOS

From the Mininet VM, test connectivity:

\`\`\`bash
nc -vz <HOST_IP> 6653
# Example: nc -vz 192.168.1.100 6653
\`\`\`

Get the \`start-mininet.py\` script from https://tele1.dee.fct.unl.pt/cgr_2025_2026/pages/laboratorios.html

Start Mininet:

\`\`\`bash
sudo ./start-mininet.py <HOST_IP>
\`\`\`

Replace \`<HOST_IP>\` with your actual IP (e.g., \`192.168.1.100\`).

### 7. Test in Mininet

\`\`\`bash
mininet> pingall

# Test connection limiting using xterm
mininet> xterm h1 h1 h1

# In h1's xterm windows:
# Terminal 1: ping 10.0.0.2  # Should work ✅
# Terminal 2: ping 10.0.0.3  # Should work ✅
# Terminal 3: ping 10.0.0.4  # Should be BLOCKED ❌

# Test TCP statistics
mininet> xterm h1 h2
# In h2's terminal:
h2# iperf -s
# In h1's terminal:
h1# iperf -c 10.0.0.2 -t 10
\`\`\`

### 8. Monitor Logs

From the dev container:

\`\`\`bash
# Application logs
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep LearningBridge

# Connection statistics
tail -f /tmp/tcp_connections.log

# Monitor connection tracking
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep -E "(Connection ended|Active destinations)"
\`\`\`

**Web UI** (optional):
- URL: http://localhost:8181/onos/ui
- Login: onos / rocks

---

## Development Workflow

After initial setup, repeat:

1. **Edit** code in dev container
2. **Build**: \`./build.sh\`
3. **Update** bundle in ONOS CLI: 
   \`\`\`text
   onos> bundle:list | grep learning  # note the bundle ID
   onos> bundle:update <ID> file:/workspaces/OnosSDN/target/learning-bridge-1.0-SNAPSHOT.jar
   \`\`\`
4. **Test** in Mininet VM
5. **Monitor** logs in dev container

---

## Configuration

Edit these constants in \`LearningBridgeApp.java\`:

\`\`\`java
private static final int MAX_CONNECTIONS_PER_HOST = 2;      // Max concurrent connections per host
private static final int FLOW_TIMEOUT = 30;                  // Flow timeout in seconds
private static final String LOG_FILE_PATH = "/tmp/tcp_connections.log";
\`\`\`

Rebuild and update the bundle after changes.

---

## Common ONOS CLI Commands

\`\`\`text
onos-cli                          # Open CLI (password: rocks)
apps -s -a                        # List active apps
devices                           # Show connected switches
ports                             # Show switch ports
hosts                             # Show discovered hosts
flows -n                          # Show flow rules
log:set DEBUG org.onosproject.learningbridge  # Enable debug logging
\`\`\`

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| \`no matching host key type found\` | Create the \`onos-cli\` wrapper script (see Step 4) |
| VM can't reach ONOS | Check VS Code Ports panel; verify \`nc -vz <HOST_IP> 6653\` from VM |
| Mininet hangs "Starting switches" | ONOS not reachable; check controller IP and ensure ONOS is running |
| No devices in ONOS | Verify \`protocols=OpenFlow13\` and correct controller IP |
| Bundle won't install | Use \`bundle:install -s file:/...jar\` method |
| Mininet can't ping | Activate OpenFlow apps in ONOS; ensure \`fwd\` app is NOT active |
| ONOS won't start | Check logs: \`tail -100 /opt/onos/apache-karaf-*/data/log/karaf.log\` |
| Old code still running | Update bundle with \`bundle:update <ID>\` instead of reinstalling |
| Broadcast packets blocked | Fixed in latest version - broadcast/multicast excluded from limits |
| Connection not freed after stopping ping | Fixed in latest version - cleanup works for all protocols |

---

## Project Structure

\`\`\`
/workspaces/OnosSDN/
├── pom.xml                                 # Maven build configuration
├── build.sh                                # Build script
├── src/
│   └── main/
│       ├── java/org/onosproject/learningbridge/
│       │   └── LearningBridgeApp.java     # Main application logic
│       └── resources/
│           └── app.xml                     # ONOS app descriptor
├── GETTING_STARTED.md                      # Detailed setup guide (START HERE)
├── ONOS_DEVELOPMENT_GUIDE.md               # Development reference
├── QUICK_REFERENCE.md                      # Command cheat sheet
├── CONNECTION_CLEANUP_FIX.md               # Technical doc on cleanup logic
├── TROUBLESHOOTING_FIX.md                  # Technical doc on broadcast fix
└── README.md                               # This file
\`\`\`

---

## Useful Links

- 📖 [GETTING_STARTED.md](GETTING_STARTED.md) - **START HERE** - Complete setup walkthrough
- 💻 [ONOS_DEVELOPMENT_GUIDE.md](ONOS_DEVELOPMENT_GUIDE.md) - In-depth development guide
- 📋 [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Command cheat sheet
- 🌐 [ONOS Documentation](https://wiki.onosproject.org/)
- 🔧 [Mininet Documentation](http://mininet.org/)

---

## How It Works

### Connection Limiting

- Tracks active destinations per source MAC address
- Limits each host to MAX_CONNECTIONS_PER_HOST simultaneous destinations
- Applies to **ALL traffic types** (ICMP, TCP, UDP, etc.)
- Broadcast and multicast traffic is **excluded** from limits (essential for ARP, DHCP, etc.)

### Dynamic Cleanup

- Monitors flow rule removals using \`FlowRuleListener\`
- When a flow expires or is removed, checks if any other flows exist between the same hosts
- If no flows remain, removes the destination from the active set
- This frees up connection slots dynamically

### TCP Statistics

- Tracks TCP SYN packets to identify new connections
- When TCP flow rules are removed, retrieves statistics from the flow entry:
  - Byte count
  - Packet count
  - Duration (calculated from timestamps)
- Logs statistics to \`/tmp/tcp_connections.log\`

---

## License

Educational use (CGR – FCT NOVA, 2024/2025)

---

**Ready to develop?** See [GETTING_STARTED.md](GETTING_STARTED.md) for the complete walkthrough! 🚀

*Last updated: November 2025*
