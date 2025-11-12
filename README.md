# ONOS Learning Bridge - Student Version 🎓

**A hands-on SDN programming assignment using ONOS**

This repository contains a starter template for students to learn Software-Defined Networking (SDN) concepts by implementing a learning bridge application with advanced features.

## 🎯 What You'll Build

An intelligent learning bridge that:
- 🔄 **Learns MAC addresses** and their associated switch ports
- 🚦 **Limits connections** per host (max 2 simultaneous connections by default)
- 📊 **Tracks TCP statistics** (bytes, packets, duration)
- ⏱️ **Manages flow lifecycles** with automatic cleanup

---

## 📚 Documentation Structure

**Start here:**
- [GETTING_STARTED.md](GETTING_STARTED.md) - Environment setup and first steps

**Then review:**
- [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) - Architecture, concepts, and data structures
- [ONOS_DEVELOPMENT_GUIDE.md](ONOS_DEVELOPMENT_GUIDE.md) - Development workflows and debugging
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Command cheat sheet

---

## 🚀 Quick Start for Students

### 1. Environment Setup

This project uses a two-tier architecture:
- **Dev Container** - Runs ONOS 2.7.0 + Java 11 + Maven for development
- **Mininet VM** - Runs Mininet with OVS 3.5.0 for network testing

### 2. Open in Dev Container

1. Open this folder in VS Code
2. Click **"Reopen in Container"** when prompted
3. Wait for setup (~5-10 minutes first time)

### 3. Build Your Application

```bash
cd /workspaces/OnosSDNstudent
./build.sh
```

### 4. Start ONOS

```bash
cd /opt/onos
./bin/onos-service start
```

### 5. Implement the Learning Bridge

Follow the **21 TODO tasks** in:
```
src/main/java/org/onosproject/learningbridge/LearningBridgeApp.java
```

Refer to [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) for architecture and concepts.

---

## 📋 Assignment Overview

The starter code contains **21 TODO tasks** to implement:

### Part 1: Basic Infrastructure (Tasks 1-5)
- Data structure initialization
- Application activation
- Packet processor registration

### Part 2: Packet Processing & Learning (Tasks 6-11)
- MAC address learning
- Connection tracking
- TCP connection detection
- Flow rule installation

### Part 3: Flow Lifecycle Management (Tasks 12-17)
- Flow removal handling
- Connection cleanup
- TCP statistics retrieval

### Part 4: Helper Classes & Logging (Tasks 18-21)
- ConnectionKey class implementation
- TcpConnectionInfo class implementation
- Statistics logging

---

## 🏗️ Architecture

**Two-tier setup for reliable development and testing:**

- **Dev Container** (this workspace): Runs ONOS 2.7.0 + Java 11 + Maven for app development
- **Mininet VM** (separate VirtualBox VM): Runs Mininet with OVS 3.5.0 for realistic network testing
- **Connection**: The VM connects to ONOS via exposed ports (6653 OpenFlow, 8101 CLI, 8181 Web UI)

---

---

## 💻 Development Workflow

### Initial Setup

1. **Edit** code in `src/main/java/org/onosproject/learningbridge/LearningBridgeApp.java`
2. **Build**: `./build.sh`
3. **Install** in ONOS CLI:
   ```text
   onos-cli  # Password: rocks
   onos> bundle:install -s file:/workspaces/OnosSDNstudent/target/learning-bridge-1.0-SNAPSHOT.jar
   ```
4. **Activate** required ONOS apps (first time only):
   ```text
   onos> app activate org.onosproject.openflow
   onos> app activate org.onosproject.hostprovider
   onos> app activate org.onosproject.lldpprovider
   ```

### Iterative Development

After making code changes:

1. **Rebuild**: `./build.sh`
2. **Update** bundle in ONOS CLI:
   ```text
   onos> bundle:list | grep learning  # note the ID
   onos> bundle:update <ID> file:/workspaces/OnosSDNstudent/target/learning-bridge-1.0-SNAPSHOT.jar
   ```
3. **Test** in Mininet
4. **Monitor** logs

---

## 🧪 Testing Your Implementation

### Setup Mininet VM

1. Download VM from course materials
2. Configure network (NAT or Bridged)
3. Get `start-mininet.py` from course page
4. Start Mininet:
   ```bash
   sudo ./start-mininet.py <HOST_IP>
   ```

### Test Cases

#### 1. Basic MAC Learning
```bash
mininet> pingall
# All hosts should be able to ping each other
```

#### 2. Connection Limiting
```bash
mininet> xterm h1 h1 h1

# Terminal 1: ping 10.0.0.2  ✅ Should work
# Terminal 2: ping 10.0.0.3  ✅ Should work  
# Terminal 3: ping 10.0.0.4  ❌ Should be BLOCKED
```

#### 3. TCP Statistics
```bash
mininet> xterm h1 h2

# In h2 terminal:
h2# iperf -s

# In h1 terminal:
h1# iperf -c 10.0.0.2 -t 10

# After flow expires, check logs:
tail /tmp/tcp_connections.log
```

### Monitor Logs

```bash
# Application logs
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep LearningBridge

# Connection tracking
tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep -E "(Connection ended|Active destinations)"

# TCP statistics
tail -f /tmp/tcp_connections.log
```

---

## 🎓 Learning Resources

### In This Repo
- [GETTING_STARTED.md](GETTING_STARTED.md) - **START HERE** - Environment setup guide
- [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) - Architecture and implementation concepts
- [ONOS_DEVELOPMENT_GUIDE.md](ONOS_DEVELOPMENT_GUIDE.md) - Development workflows and debugging
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Command cheat sheet

### External Resources
- 📖 [ONOS Wiki](https://wiki.onosproject.org/)
- 🔧 [OpenFlow Specification](https://www.opennetworking.org/software-defined-standards/specifications/)
- 🌐 [Mininet Documentation](http://mininet.org/)

---

## 📁 Project Structure

```
/workspaces/OnosSDNstudent/
├── pom.xml                                 # Maven build configuration
├── build.sh                                # Build script
├── src/
│   └── main/
│       ├── java/org/onosproject/learningbridge/
│       │   └── LearningBridgeApp.java     # Main application (YOUR WORK HERE)
│       └── resources/
│           └── app.xml                     # ONOS app descriptor
├── GETTING_STARTED.md                      # Setup guide (START HERE)
├── IMPLEMENTATION_GUIDE.md                 # Architecture and concepts
├── ONOS_DEVELOPMENT_GUIDE.md               # Development reference
├── QUICK_REFERENCE.md                      # Command cheat sheet
└── README.md                               # This file
```

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| Build fails | Check Java version: `java -version` (should be 11) |
| Can't connect to ONOS CLI | Create wrapper script (see GETTING_STARTED.md) |
| VM can't reach ONOS | Verify port 6653 is forwarded: `nc -vz <HOST_IP> 6653` |
| No devices in ONOS | Check OpenFlow apps are activated |
| Flows not installed | Ensure `org.onosproject.fwd` is NOT active |
| Connection limit not working | Check logs for "Connection limit reached" messages |
| No TCP stats | Wait for flow timeout, check `/tmp/tcp_connections.log` |

---

## ✅ Submission Requirements

Before submitting your assignment:

- [ ] All 21 TODO tasks completed
- [ ] Application builds without errors
- [ ] MAC learning test passes (pingall works)
- [ ] Connection limiting test passes (3rd connection blocked)
- [ ] TCP statistics are logged correctly
- [ ] Code is clean and well-commented
- [ ] Understanding of architecture and design decisions

---

## 🎯 Grading Criteria

Your implementation will be evaluated on:

1. **Correctness** (40%) - Does it work as specified?
2. **Code Quality** (30%) - Is it clean and well-structured?
3. **Testing** (20%) - Did you test all features?
4. **Understanding** (10%) - Do you understand the architecture?

---

## 📞 Support

- **Course Materials**: https://tele1.dee.fct.unl.pt/cgr
- **Issues**: Check GETTING_STARTED.md troubleshooting section
- **Questions**: Ask in course forum or office hours

---

## 📜 License

Educational use - CGR Course, FCT NOVA, 2024/2025

---

**Ready to start?** Follow [GETTING_STARTED.md](GETTING_STARTED.md) to set up your environment, then implement the TODO tasks using [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) as your reference! 🚀

*Last updated: November 2025*

