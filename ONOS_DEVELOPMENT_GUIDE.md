# ONOS Learning Bridge – Development Guide

## Overview

This guide explains how to develop, build, and test the ONOS Learning Bridge application in a two-environment setup:
- **Dev Container** (VS Code): ONOS controller + development tools
- **Mininet VM** (VirtualBox): Network simulation with OVS 3.5.0

---

## Your Workflow at a Glance

1. Open the project in the VS Code dev container
2. Update the app code under `src/main/java/org/onosproject/learningbridge/`
3. Run `./build.sh` to rebuild the app
4. Start ONOS, install the bundle, and activate helper apps
5. Use Mininet (in a separate VM) to generate traffic and validate behavior
6. Check ONOS logs and `/tmp/tcp_connections.log` to confirm the features you added

---

## Code Structure

### Main Files

| File | Purpose | Typical Edits |
|------|---------|---------------|
| `LearningBridgeApp.java` | Main application: packet processor, MAC learning, connection limiting, TCP tracking | Change logic in `LearningBridgeProcessor`, update limits/timeouts, add new behaviors |
| `pom.xml` | Maven build configuration (ONOS 2.7.0) | Only edit if you need new dependencies |
| `build.sh` | Build script | No changes needed |
| `app.xml` | ONOS app descriptor | Usually no changes needed |

### Key Classes and Methods

#### Main Component: `LearningBridgeApp`

```java
@Component(immediate = true)
public class LearningBridgeApp {
    // OSGi services injected by ONOS
    @Reference protected CoreService coreService;
    @Reference protected PacketService packetService;
    @Reference protected FlowRuleService flowRuleService;
    @Reference protected FlowObjectiveService flowObjectiveService;
    @Reference protected HostService hostService;
    @Reference protected TopologyService topologyService;
    @Reference protected DeviceService deviceService;
    
    // Configuration constants
    private static final int MAX_CONNECTIONS_PER_HOST = 2;
    private static final int FLOW_TIMEOUT = 30;  // seconds
    private static final String LOG_FILE_PATH = "/tmp/tcp_connections.log";
}
```

#### Inner Class: `LearningBridgeProcessor`

Handles packet-in events:

```java
private class LearningBridgeProcessor implements PacketProcessor {
    @Override
    public void process(PacketContext context) {
        // 1. Extract packet information
        // 2. Learn MAC address → port mapping
        // 3. Check connection limits (for unicast only)
        // 4. Install flow rules or flood
        // 5. Track TCP connections (if TCP)
    }
}
```

#### Inner Class: `InternalFlowListener`

Monitors flow rule removals:

```java
private class InternalFlowListener implements FlowRuleListener {
    @Override
    public void event(FlowRuleEvent event) {
        if (event.type() == FlowRuleEvent.Type.RULE_REMOVED) {
            // 1. Clean up destination tracking for ALL flows
            handleFlowRemoval(flowRule);
            
            // 2. Log TCP statistics if it was a TCP flow
            handleTcpFlowRemoval(flowRule);
        }
    }
}
```

### Important Data Structures

```java
// MAC learning table: DeviceId -> (MacAddress -> PortNumber)
private Map<DeviceId, Map<MacAddress, PortNumber>> macTables;

// Track active destinations per source: SourceMac -> Set of DestMacs
private Map<MacAddress, Set<MacAddress>> activeDestinations;

// TCP connection tracking: ConnectionKey -> ConnectionInfo
private Map<ConnectionKey, TcpConnectionInfo> tcpConnections;
```

---

## Configuration Constants

Edit these in `LearningBridgeApp.java` to tune behavior:

```java
// Maximum number of simultaneous connections per host
// Applies to ALL traffic types (ICMP, TCP, UDP, etc.)
private static final int MAX_CONNECTIONS_PER_HOST = 2;

// Flow rule timeout in seconds
private static final int FLOW_TIMEOUT = 30;

// TCP connection statistics log file
private static final String LOG_FILE_PATH = "/tmp/tcp_connections.log";

// Packet processing priority
private static final int PRIORITY = 2;
```

After editing, rebuild and update the bundle.

---

## Build & Deploy

### Build the Application

```bash
cd /workspaces/OnosSDN
./build.sh
```

Output: `target/learning-bridge-1.0-SNAPSHOT.jar`

### Start ONOS (if not running)

```bash
cd /opt/onos
./bin/onos-service start
```

Wait ~30-45 seconds for startup.

### Install the Bundle

**First time only:** Create the CLI wrapper:

```bash
cat > /usr/local/bin/onos-cli << 'EOF'
#!/bin/bash
ssh -o "HostKeyAlgorithms=+ssh-rsa" \
    -o "PubkeyAcceptedAlgorithms=+ssh-rsa" \
    -o "StrictHostKeyChecking=no" \
    -o "UserKnownHostsFile=/dev/null" \
    -p 8101 onos@localhost "$@"
EOF
chmod +x /usr/local/bin/onos-cli
```

**Install bundle:**

```bash
onos-cli
# Password: rocks
```

```text
onos> bundle:install -s file:/workspaces/OnosSDN/target/learning-bridge-1.0-SNAPSHOT.jar
onos> bundle:list | grep learning
```

**Activate required ONOS apps (first time only):**

```text
onos> app activate org.onosproject.openflow
onos> app activate org.onosproject.hostprovider
onos> app activate org.onosproject.lldpprovider
```

**Important:** Do NOT activate `org.onosproject.fwd` - it conflicts with the learning bridge.

### Update Bundle After Code Changes

**Recommended method (faster):**

```text
onos> bundle:list | grep learning       # note the ID (e.g., 200)
onos> bundle:update 200 file:/workspaces/OnosSDN/target/learning-bridge-1.0-SNAPSHOT.jar
```

---

## Testing with Mininet

### Set Up Mininet VM

1. **Download** the course VM from https://tele1.dee.fct.unl.pt/cgr
2. **Configure networking** (VirtualBox): Use NAT Network or Bridged Adapter
3. **Find your host IP** from the VM's perspective:
   - Bridged: Your host's LAN IP (e.g., `192.168.1.100`)
   - NAT: Your host IP as seen by the VM
4. **Test connectivity** from VM:
   ```bash
   nc -vz <HOST_IP> 6653
   ```

### Start Mininet

Get the `start-mininet.py` script from the course website, then:

```bash
sudo ./start-mininet.py <HOST_IP>
```

This script automatically:
- Creates a tree topology
- Configures switches for OpenFlow 1.3
- Applies OVS 3.5.0 compatibility fixes
- Connects to your ONOS controller

### Test Basic Connectivity

```bash
mininet> pingall
mininet> h1 ping h2
```

### Test Connection Limiting

**Recommended: Use xterm**

```bash
# Open three terminal windows for host h1
mininet> xterm h1 h1 h1

# In h1's xterm windows:
# Terminal 1: ping 10.0.0.2  # Should work ✅
# Terminal 2: ping 10.0.0.3  # Should work ✅
# Terminal 3: ping 10.0.0.4  # Should be BLOCKED ❌

# Stop Terminal 1 (Ctrl+C)
# Wait ~30 seconds for flow to expire

# Terminal 3 should now work ✅ (connection slot freed)
```

### Test TCP Statistics

```bash
# Open xterm windows
mininet> xterm h1 h2

# In h2's terminal (server):
h2# iperf -s

# In h1's terminal (client):
h1# iperf -c 10.0.0.2 -t 10

# After the flow expires (30 seconds), check logs in dev container:
tail /tmp/tcp_connections.log
```

---

## Monitoring & Debugging

### View Application Logs

```bash
# In dev container
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep LearningBridge

# Monitor connection tracking
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep -E "(Connection ended|Active destinations)"
```

### View TCP Statistics

```bash
cat /tmp/tcp_connections.log
tail -f /tmp/tcp_connections.log
```

### ONOS CLI Commands

```text
onos> devices                    # Show connected switches
onos> hosts                      # Show discovered hosts
onos> flows -n                   # Show flow rules (no core flows)
onos> apps -s -a                 # Show active apps
onos> bundle:list | grep learning # Show bundle status

# Enable debug logging
onos> log:set DEBUG org.onosproject.learningbridge

# View recent logs
onos> log:display | grep LearningBridge
```

---

## How It Works

### 1. MAC Address Learning

When a packet arrives:
1. Extract source MAC and input port
2. Store mapping: `macTables[deviceId][srcMac] = inPort`
3. Look up destination MAC in table
4. If found, install flow rule for that specific path
5. If not found, flood the packet

### 2. Connection Limiting

**Applies to ALL traffic types** (ICMP, TCP, UDP, etc.):

1. When a new packet arrives, extract source and destination MACs
2. **Skip if destination is broadcast/multicast** (essential for ARP, DHCP)
3. Check if destination is already in `activeDestinations[srcMac]`
4. If new destination and limit reached → drop packet
5. Otherwise, add destination to active set and forward

**Key insight:** Tracks destinations per source, not individual flows.

### 3. Dynamic Cleanup

**FlowRuleListener monitors flow removals:**

1. When a flow expires or is removed, `handleFlowRemoval()` is called
2. Extract source and destination MACs from the flow
3. Query all devices to check if any other flows exist between same hosts
4. If no flows remain → remove destination from `activeDestinations`
5. This frees a connection slot for new destinations

**Works for all protocols:** ICMP, TCP, UDP, etc.

### 4. TCP Statistics Logging

**Only for TCP flows:**

1. When TCP SYN packet arrives → track connection in `tcpConnections`
2. When TCP flow is removed → `handleTcpFlowRemoval()` is called
3. Retrieve statistics from `FlowEntry`:
   - `entry.bytes()` → total bytes transferred
   - `entry.packets()` → total packets
   - Calculate duration from timestamps
4. Log to `/tmp/tcp_connections.log`

**Format:**
```
2025-11-12 14:30:45 | TCP Connection | 00:00:00:00:00:01 -> 00:00:00:00:00:02 | 10.0.0.1:45678 -> 10.0.0.2:5001 | Duration: 10234ms | Bytes: 1048576 | Packets: 1024
```

---

## Common Development Tasks

### Add a New Feature

1. Edit `LearningBridgeApp.java`
2. Rebuild: `./build.sh`
3. Update bundle: `onos> bundle:update <ID> file:/workspaces/OnosSDN/target/learning-bridge-1.0-SNAPSHOT.jar`
4. Test in Mininet
5. Check logs

### Change Connection Limit

```java
private static final int MAX_CONNECTIONS_PER_HOST = 5;  // Change from 2 to 5
```

Rebuild and update bundle.

### Change Flow Timeout

```java
private static final int FLOW_TIMEOUT = 60;  // Change from 30 to 60 seconds
```

Rebuild and update bundle.

### Add Custom Logging

```java
log.info("Custom message: {}", someVariable);
log.debug("Debug info: {}", details);
log.warn("Warning: {}", issue);
log.error("Error: {}", problem);
```

Enable debug logging in ONOS CLI:
```text
onos> log:set DEBUG org.onosproject.learningbridge
```

---

## Troubleshooting

### Bundle Won't Install

**Solution:** Use file-based installation:
```text
onos> bundle:install -s file:/workspaces/OnosSDN/target/learning-bridge-1.0-SNAPSHOT.jar
```

### Old Code Still Running

**Solution:** Update bundle instead of reinstalling:
```text
onos> bundle:list | grep learning
onos> bundle:update <ID> file:/workspaces/OnosSDN/target/learning-bridge-1.0-SNAPSHOT.jar
```

### Switches Don't Connect

**Solution:** Activate OpenFlow apps:
```text
onos> app activate org.onosproject.openflow
onos> app activate org.onosproject.hostprovider
onos> app activate org.onosproject.lldpprovider
```

### Hosts Can't Ping

**Common causes:**
1. `fwd` app is active (conflicts with learning bridge)
   ```text
   onos> app deactivate org.onosproject.fwd
   ```
2. OpenFlow apps not activated (see above)
3. Broadcast packets being blocked (fixed in current version)

### Connection Slots Not Freed

**Fixed in current version.** The app now:
- Monitors ALL flow types (not just TCP)
- Removes destinations when flows expire
- Works for ICMP, TCP, UDP, etc.

---

## Best Practices

1. **Always update bundle** after code changes (don't uninstall/reinstall)
2. **Use xterm for testing** connection limiting (better than background processes)
3. **Monitor logs** while testing to see what's happening
4. **Clean Mininet** between tests: `sudo mn -c` (in VM)
5. **Check flow rules** to understand behavior: `onos> flows -n`
6. **Exclude broadcast/multicast** from connection limiting (essential for network operation)

---

## Advanced Topics

### Understanding OSGi Components

The app uses OSGi Service Component Runtime (SCR):
- `@Component(immediate = true)` → Start immediately when bundle activates
- `@Activate` → Method called when component starts
- `@Deactivate` → Method called when component stops
- `@Reference` → Inject ONOS services

### Flow Rule Priority

```java
private static final int PRIORITY = 2;
```

Higher priority = processed first. Our app uses priority 2 (above default forwarding).

### Packet Processing Pipeline

1. Packet arrives at switch
2. No matching flow rule → packet-in to controller
3. ONOS delivers to PacketProcessor (our app)
4. App processes packet, installs flow rule
5. Subsequent packets match flow rule → processed in switch (no controller involvement)
6. Flow expires after FLOW_TIMEOUT seconds → removed
7. FlowRuleListener detects removal → cleanup

---

## Summary Checklist

Development cycle:

- [ ] Edited `LearningBridgeApp.java` with your new logic
- [ ] Ran `./build.sh` (build succeeded)
- [ ] Updated bundle in ONOS with `bundle:update <ID>`
- [ ] Mininet VM connected to ONOS successfully
- [ ] Mininet traffic shows the expected behavior
- [ ] Logs or statistics confirm your feature works

---

## Further Reading

- [GETTING_STARTED.md](GETTING_STARTED.md) - Setup walkthrough
- [README.md](README.md) - Project overview
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Command cheat sheet
- [ONOS Documentation](https://wiki.onosproject.org/) - Official ONOS docs
- [Mininet Documentation](http://mininet.org/) - Mininet guides

---

*Last updated: November 2025*
