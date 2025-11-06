# ONOS Learning Bridge with Connection Limiting# ONOS Learning Bridge with Connection Limiting# ONOS Learning Bridge with Connection Limiting# 



A Software-Defined Networking (SDN) application for ONOS that implements MAC address learning, TCP connection limiting, and statistics logging.



## FeaturesA Software-Defined Networking (SDN) application built on ONOS that implements an intelligent learning bridge with TCP connection limiting and statistics logging.



- 🔄 **MAC Address Learning**: Automatically learns MAC addresses and their associated switch ports

- 🚦 **Connection Limiting**: Enforces a maximum number of simultaneous TCP connections per host (default: 2)

- 📊 **Statistics Logging**: Tracks and logs packet count and duration for each TCP connection to `/tmp/tcp_connections.log`## FeaturesA learning bridge application for ONOS SDN controller that limits TCP connections per host and logs connection statistics. A Software-Defined Networking (SDN) application built on ONOS that implements an intelligent learning bridge with connection limiting and TCP statistics logging.

- ⏱️ **Flow Management**: Automatic flow rule timeout (30 seconds default)



---

- MAC address learning (switch-port learning)

## Architecture

- Connection limiting: maximum concurrent TCP connections per host (default: 2)

**Two-tier setup for reliable development and testing:**

- TCP statistics logging to /tmp/tcp_connections.log## Features## Features

- **Dev Container** (this workspace): Runs ONOS 2.7.0 + Java 11 + Maven for app development

- **Mininet VM** (separate VirtualBox VM): Runs Mininet with OVS kernel support for realistic network testing- Flow rule management with 30-second timeout

- **Connection**: The VM connects to ONOS via exposed ports (6653 OpenFlow, 8101 CLI, 8181 Web UI)



---

## Requirements (auto-installed in Dev Container)

## Quick Start

- 🔄 **MAC Address Learning**: Automatically learns MAC addresses and their switch ports- 🔄 **MAC Address Learning**: Automatically learns MAC addresses and their associated switch ports

### 1. Open in Dev Container

- Java 11 LTS

1. Open this folder in VS Code

2. **Reopen in Container** when prompted- Maven 3.6+- 🚦 **Connection Limiting**: Limits simultaneous  connections per host (default: 2)- 🚦 **Connection Limiting**: Enforces a maximum number of simultaneous connections per host

3. Wait for setup (~5-10 minutes first time)

- ONOS 2.7.0

### 2. Build the Application

- Mininet + Open vSwitch- 📊 **Statistics Logging**: Records packet count and duration for each TCP connection- 📊 **Statistics Logging**: Tracks and logs packet count and duration for each TCP connection

```bash

cd /workspaces/OpenFlow- Works on x86_64 and ARM64

./build.sh# ONOS Learning Bridge (Student Edition)

```

Minimal ONOS application that implements a learning bridge with:

Output: `target/learning-bridge-1.0-SNAPSHOT.jar`* MAC address learning

* TCP connection limiting (default: 2 per host)

### 3. Start ONOS* Connection statistics logging to `/tmp/tcp_connections.log`



```bash## Why Simplified?

cd /opt/onosAutomation was removed to avoid controller startup edge cases. Students now build and deploy manually to understand each step of the SDN workflow.

./bin/onos-service start

```## Prerequisites (already baked into the dev container)

* Java 11

Wait ~30-45 seconds for ONOS to start.* Maven 3.x

* ONOS 2.7.0 at `/opt/onos`

### 4. Install the Bundle* Mininet + Open vSwitch



Create the CLI wrapper (first time only):## 1. Build

```bash

```bashcd /workspaces/OpenFlow

cat > /usr/local/bin/onos-cli << 'EOF'./build.sh          # or use: mvn clean package -DskipTests

#!/bin/bash```

ssh -o "HostKeyAlgorithms=+ssh-rsa" \Jar: `target/learning-bridge-1.0-SNAPSHOT.jar`

    -o "PubkeyAcceptedAlgorithms=+ssh-rsa" \

    -o "StrictHostKeyChecking=no" \## 2. Start ONOS

    -o "UserKnownHostsFile=/dev/null" \```bash

    -p 8101 onos@localhost "$@"cd /opt/onos

EOF./bin/onos-service start

chmod +x /usr/local/bin/onos-cli```

```

## 3. Install & Activate

Install the bundle:

Create CLI helper (one-time):

```bash```bash

onos-clicat > /usr/local/bin/onos-cli << 'EOF'

# Password: rocks#!/bin/bash

```ssh -o "HostKeyAlgorithms=+ssh-rsa" \

    -o "PubkeyAcceptedAlgorithms=+ssh-rsa" \

```text    -o "StrictHostKeyChecking=no" \

onos> bundle:install -s file:/workspaces/OpenFlow/target/learning-bridge-1.0-SNAPSHOT.jar    -o "UserKnownHostsFile=/dev/null" \

onos> bundle:list | grep learning    -p 8101 onos@localhost "$@"

```EOF

chmod +x /usr/local/bin/onos-cli

Activate core ONOS apps (first time only):```



```textThen install (choose method A, recommended):

onos> app activate org.onosproject.openflow```text

onos> app activate org.onosproject.hostproviderA) Karaf bundle (offline, recommended):

onos> app activate org.onosproject.lldpprovider   onos-cli                                 # password: rocks

onos> app activate org.onosproject.fwd   onos> bundle:install -s file:/workspaces/OpenFlow/target/learning-bridge-1.0-SNAPSHOT.jar

```   onos> bundle:list | grep learning



### 5. Set Up Mininet VMB) App subsystem:

   onos> app install /workspaces/OpenFlow/target/learning-bridge-1.0-SNAPSHOT.jar

**Option A**: Download the [official Mininet VM](http://mininet.org/download/)   onos> app activate org.onosproject.learningbridge

   (If it tries to reach remote registry, fall back to method A.)

**Option B**: Create your own Ubuntu VM and install Mininet:```



```bashActivate helper services (only once per fresh controller):

git clone https://github.com/mininet/mininet```text

cd mininetonos> app activate org.onosproject.openflow

sudo PYTHON=python3 util/install.sh -aonos> app activate org.onosproject.hostprovider

```onos> app activate org.onosproject.lldpprovider

onos> app activate org.onosproject.fwd

**Configure VM Networking** (VirtualBox):```

- Use **Bridged Adapter** (VM gets LAN IP) or **Host-Only Adapter** (typically 192.168.56.1)

## 4. Run Mininet

**Find your host IP** from the VM's perspective:```bash

- Bridged: Your host's LAN IP (e.g., `192.168.1.100`)cd /workspaces/OpenFlow

- Host-Only: Typically `192.168.56.1`sudo python3 test_topology.py    # auto-starts OVS if needed

```

**Test connectivity from the VM**:Example tests in Mininet CLI:

```bash

```bashmininet> pingall

nc -vz <HOST_IP> 6653mininet> h1 python3 -m http.server 8000 &

```mininet> h2 curl http://10.0.0.1:8000

```

### 6. Connect Mininet to ONOSStart more client connections to hit the limit.



From the Mininet VM:## 5. Observe

```bash

```bashtail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep LearningBridge

sudo mn --topo tree,2 --mac --switch ovsk,protocols=OpenFlow13 --controller remote,ip=<HOST_IP>,port=6653tail -f /tmp/tcp_connections.log

``````



Replace `<HOST_IP>` with your actual host IP.## Adjust Behaviour

Edit constants inside `src/main/java/org/onosproject/learningbridge/LearningBridgeApp.java`:

### 7. Test in Mininet```java

private static final int MAX_CONNECTIONS_PER_HOST = 2;

```bashprivate static final int FLOW_TIMEOUT = 30; // seconds

mininet> pingallprivate static final String LOG_FILE_PATH = "/tmp/tcp_connections.log";

mininet> h1 python3 -m http.server 8000 &```

mininet> h2 curl http://10.0.0.1:8000Rebuild and reinstall after changes.

mininet> h2 curl http://10.0.0.1:8000  # second connection

mininet> h2 curl http://10.0.0.1:8000  # third should be blocked## Common ONOS CLI Commands

``````text

onos-cli                # open CLI (password: rocks)

### 8. Monitor Logsapps -s -a              # list apps

flows                   # view flow rules

From the dev container:hosts                   # discovered hosts

devices                 # switches

```bashlog:set DEBUG org.onosproject.learningbridge

# Application logs```

tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep LearningBridge

## Troubleshooting

# Connection statistics| Issue | Fix |

tail -f /tmp/tcp_connections.log|-------|-----|

```| SSH "no matching host key" | Create onos-cli wrapper (see section 3) |

| `database connection failed` (OVS) | `sudo service openvswitch-switch start` |

---| `openvswitch module not found` | **Normal in Docker** - ignore, userspace OVS works |

| `Error setting resource limits` | **Normal in containers** - ignore, doesn't affect functionality |

## Development Workflow| App not visible | Use bundle:install method (A) |

| Mininet can't ping | Activate OpenFlow + hostprovider apps |

After the initial setup:| Log empty | Generate traffic (HTTP, ping, iperf) |

| Old logic running | Rebuild, reinstall (uninstall bundle if needed) |

1. **Edit code**: Modify `src/main/java/org/onosproject/learningbridge/LearningBridgeApp.java`

2. **Rebuild**: `./build.sh`## Project Layout

3. **Update bundle** (in ONOS CLI):```

   ```textworkspaces/OpenFlow

   onos> bundle:list | grep learning  # note the bundle ID├── pom.xml

   onos> bundle:update <ID> file:/workspaces/OpenFlow/target/learning-bridge-1.0-SNAPSHOT.jar├── build.sh                  # Build script (run after each code change)

   ```├── src/main/java/org/onosproject/learningbridge/LearningBridgeApp.java

4. **Test**: Generate traffic in Mininet VM├── src/main/resources/app.xml

5. **Observe**: Check logs and statistics├── test_topology.py

├── GETTING_STARTED.md        # Start here!

---├── ONOS_DEVELOPMENT_GUIDE.md

├── QUICK_REFERENCE.md

## Configuration└── README.md

```

Edit these constants in `LearningBridgeApp.java`:

## License / Course

```javaEducational use (CGR – FCT NOVA, 2024/2025).

private static final int MAX_CONNECTIONS_PER_HOST = 2;      // Max concurrent TCP connections

private static final int FLOW_TIMEOUT = 30;                  // Flow timeout in seconds## Next Steps

private static final String LOG_FILE_PATH = "/tmp/tcp_connections.log";Add new learning behaviours, metrics, or enforcement policies. Rebuild, redeploy, test. Iterate quickly.

```

---

Rebuild and update the bundle after changes.Updated: Nov 2025



---

## Common ONOS CLI Commands

```text
onos-cli                          # Open CLI (password: rocks)
apps -s -a                        # List active apps
devices                           # Show connected switches
ports                             # Show switch ports
hosts                             # Show discovered hosts
flows -n                          # Show flow rules
log:set DEBUG org.onosproject.learningbridge  # Enable debug logging
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `no matching host key type found` | Create the `onos-cli` wrapper script |
| VM can't reach ONOS | Check VS Code Ports panel; verify `nc -vz <HOST_IP> 6653` from VM |
| Mininet hangs "Starting switches" | ONOS not reachable; check controller IP and ensure ONOS is running |
| No devices in ONOS | Verify Mininet used `protocols=OpenFlow13` and correct controller IP |
| Bundle won't install | Use `bundle:install -s file:/...jar` method |
| Mininet can't ping | Activate OpenFlow apps in ONOS |
| ONOS won't start | Check logs: `tail -100 /opt/onos/apache-karaf-*/data/log/karaf.log` |
| Old code still running | Update bundle with `bundle:update <ID>` instead of reinstalling |

---

## Project Structure

```
/workspaces/OpenFlow/
├── pom.xml                                 # Maven build configuration
├── build.sh                                # Build script
├── src/
│   └── main/
│       ├── java/org/onosproject/learningbridge/
│       │   └── LearningBridgeApp.java     # Main application logic
│       └── resources/
│           └── app.xml                     # ONOS app descriptor
├── GETTING_STARTED.md                      # Detailed setup guide
├── ONOS_DEVELOPMENT_GUIDE.md               # Development reference
├── QUICK_REFERENCE.md                      # Command quick reference
└── README.md                               # This file
```

---

## Useful Links

- 📖 [GETTING_STARTED.md](GETTING_STARTED.md) - Complete setup walkthrough
- 💻 [ONOS_DEVELOPMENT_GUIDE.md](ONOS_DEVELOPMENT_GUIDE.md) - In-depth development guide
- 📋 [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Command cheat sheet
- 🌐 [ONOS Documentation](https://wiki.onosproject.org/)
- 🔧 [Mininet Documentation](http://mininet.org/)

---

## License

Educational use (CGR – FCT NOVA, 2024/2025)

---

**Ready to develop?** See [GETTING_STARTED.md](GETTING_STARTED.md) for the complete walkthrough! 🚀

*Last updated: November 2025*
