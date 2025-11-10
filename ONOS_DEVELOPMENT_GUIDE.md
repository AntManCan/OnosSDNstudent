# ONOS Learning Bridge – Student Development Guide (Manual Flow)


## Your Workflow at a Glance
- Open the project in the VS Code dev container.
- Update the app code under `src/main/java/org/onosproject/learningbridge/`.
- Run `./quick-start.sh` to rebuild the app (build only).
- Manually: start ONOS, install the bundle from file, and activate helpers.
- Use Mininet (in a separate VM) to generate traffic and validate behaviour.
- Check ONOS logs and `/tmp/tcp_connections.log` to confirm the features you added.

---

## Code You Will Touch

File | Purpose | Typical edits
-----|---------|--------------
`src/main/java/org/onosproject/learningbridge/LearningBridgeApp.java` | Main application entry point, packet processor, MAC-learning tables, TCP connection tracking. | Change logic in `LearningBridgeProcessor`, update limits/timeouts, add new behaviours.
`pom.xml` | Maven build file (already configured for ONOS 2.7.0). | Only edit if you need new dependencies.

### Useful constants inside `LearningBridgeApp`
- `MAX_CONNECTIONS_PER_HOST`: limit per host. Adjust to tune connection policy.
- `FLOW_TIMEOUT_SECONDS`: flow rule lifetime.
- `LOG_FILE_PATH`: destination for connection statistics.

After editing Java files, let `./build.sh` rebuild, or run `mvn clean install` manually if you prefer.

---

## Rebuild & Deploy (Manual)

```bash
cd /workspaces/OpenFlow
./build.sh            # build only
```

Then in a separate terminal:

1) Start ONOS if not already running
```bash
cd /opt/onos
./bin/onos-service start
```

2) Open ONOS CLI if not already running (user: onos, pass: rocks)
```bash
onos-cli
```

3) Install and activate your build 
```text
A) Reliable offline method (Karaf bundle):
   onos> bundle:install -s file:/workspaces/OpenFlow/target/learning-bridge-1.0-SNAPSHOT.jar
   onos> apps -s -a | grep learningbridge
```

4) Activate helpful ONOS services also only if not already activated (once per controller reset)
```text
onos> app activate org.onosproject.openflow
onos> app activate org.onosproject.hostprovider
onos> app activate org.onosproject.lldpprovider
onos> app activate org.onosproject.fwd
```

---

## Test the Behaviour

1. **From your Mininet VM** (not the dev container):
   
   Find your host IP and verify connectivity:
   ```bash
   nc -vz <HOST_IP> 6653
   ```
   
   Launch Mininet pointing to ONOS in the dev container:
   ```bash
   sudo mn --topo tree,2 --mac --switch ovsk,protocols=OpenFlow13 --controller remote,ip=<HOST_IP>,port=6653
   ```
   
   Replace `<HOST_IP>` with your actual host IP (e.g., `192.168.1.100` for Bridged network or `192.168.56.1` for Host-Only).

2. In the Mininet CLI (on the VM):
   ```bash
   mininet> pingall                     # basic reachability check
   mininet> h1 ping h2                  # test specific hosts
   ```

3. Generate TCP sessions:
   ```bash
   # on host h1 (server)
   mininet> h1 python3 -m http.server 8000 &

   # on host h2 (client)
   mininet> h2 curl http://10.0.0.1:8000       # repeat to hit the connection cap
   mininet> h2 curl http://10.0.0.1:8000
   mininet> h2 curl http://10.0.0.1:8000       # third should be blocked
   ```
   
   Adjust the commands as needed for your own experiments (iperf, netcat, etc.) or use the hosts terminals for other commands.

4. Inspect results **in the dev container**:
   ```bash
   # Connection statistics written by the app (if you maintain this file as the output)
   tail -f /tmp/tcp_connections.log

   # ONOS controller log filtered for your app
   tail -f /opt/onos/apache-karaf-4.2.9/data/log/karaf.log | grep LearningBridge

   # ONOS CLI
   onos-cli
   onos> apps -s
   onos> devices
   onos> hosts
   onos> flows -n
   ```
```---

## When Things Don't Work

- Re-run `./build.sh` to rebuild the bundle.
- Make sure ONOS is running: `ps aux | grep karaf` and `tail -50 /opt/onos/apache-karaf-4.2.9/data/log/karaf.log`.
- If an install attempt tries to contact the ONOS registry, use `bundle:install -s file:/...jar` instead of `app install`.
- Clean Mininet state in the VM with `sudo mn -c` if you restart the topology.
- Verify the VM can reach ONOS: `nc -vz <HOST_IP> 6653` from the VM.
- In ONOS CLI use `flows`, `hosts`, `devices`, or `log:set DEBUG org.onosproject.learningbridge` for debugging.

---

## Summary Checklist

- [ ] Edited `LearningBridgeApp.java` with your new logic.
- [ ] Ran `./build.sh` (build succeeded).
- [ ] Updated bundle in ONOS with `bundle:update <ID>`.
- [ ] Mininet VM connected to ONOS successfully.
- [ ] Mininet traffic shows the expected behaviour (pings/HTTP/tests).
- [ ] Logs or statistics confirm your feature works.

That's all you need for the lab. The dev container handles ONOS; the VM handles Mininet. Focus on writing and validating your SDN logic.
