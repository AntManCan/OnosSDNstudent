package org.onosproject.learningbridge;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ONOS Learning Bridge Application with Connection Limiting.
 * 
 * This application implements a learning bridge that:
 * 1. Learns MAC addresses and their associated ports
 * 2. Limits the number of simultaneous TCP connections per host
 * 3. Logs TCP connection statistics (packet count and duration) to a file
 */
@Component(immediate = true)
public class LearningBridgeApp {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    private ApplicationId appId;
    private LearningBridgeProcessor processor = new LearningBridgeProcessor();

    // MAC learning table: DeviceId -> (MacAddress -> PortNumber)
    private Map<DeviceId, Map<MacAddress, PortNumber>> macTables = new ConcurrentHashMap<>();

    // Connection tracking: HostMac -> Set of active connections
    private Map<MacAddress, Map<ConnectionKey, ConnectionStats>> activeConnections = new ConcurrentHashMap<>();

    // Maximum number of simultaneous connections per host
    private static final int MAX_CONNECTIONS_PER_HOST = 2; // Configurable value

    // Flow rule timeout
    private static final int FLOW_TIMEOUT = 30; // seconds

    // Log file path
    private static final String LOG_FILE_PATH = "/tmp/tcp_connections.log";

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.onosproject.learningbridge");
        packetService.addProcessor(processor, PacketProcessor.director(2));

        // Request packet-in for all packets
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Learning Bridge Application Started with connection limiting (max {} per host)", 
                 MAX_CONNECTIONS_PER_HOST);
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        flowRuleService.removeFlowRulesById(appId);

        // Write final statistics before shutdown
        logAllConnectionStats();

        log.info("Learning Bridge Application Stopped");
    }

    /**
     * Packet processor that handles incoming packets.
     */
    private class LearningBridgeProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            // Learn the source MAC address
            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();
            DeviceId deviceId = pkt.receivedFrom().deviceId();
            PortNumber inPort = pkt.receivedFrom().port();

            // Update MAC table
            macTables.putIfAbsent(deviceId, new ConcurrentHashMap<>());
            macTables.get(deviceId).put(srcMac, inPort);

            log.debug("Learned: {} -> port {} on device {}", srcMac, inPort, deviceId);

            // Check if it's a TCP packet
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
                if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_TCP) {
                    handleTcpPacket(context, ethPkt, ipv4Packet);
                    return;
                }
            }

            // Handle forwarding
            PortNumber outPort = macTables.get(deviceId).get(dstMac);

            if (outPort != null) {
                // Install flow rule and forward packet
                installRule(context, outPort);
            } else {
                // Flood the packet
                flood(context);
            }
        }

        /**
         * Handles TCP packets with connection limiting.
         */
        private void handleTcpPacket(PacketContext context, Ethernet ethPkt, IPv4 ipv4Packet) {
            TCP tcpPacket = (TCP) ipv4Packet.getPayload();
            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();
            DeviceId deviceId = context.inPacket().receivedFrom().deviceId();

            ConnectionKey connKey = new ConnectionKey(
                srcMac, dstMac,
                ipv4Packet.getSourceAddress(),
                ipv4Packet.getDestinationAddress(),
                tcpPacket.getSourcePort(),
                tcpPacket.getDestinationPort()
            );

            // Track connection state
            activeConnections.putIfAbsent(srcMac, new ConcurrentHashMap<>());
            Map<ConnectionKey, ConnectionStats> hostConnections = activeConnections.get(srcMac);

            // Check for SYN flag (new connection)
            if ((tcpPacket.getFlags() & 0x02) != 0) { // SYN flag
                if (hostConnections.size() >= MAX_CONNECTIONS_PER_HOST && !hostConnections.containsKey(connKey)) {
                    log.warn("Connection limit reached for host {}. Dropping SYN packet.", srcMac);
                    context.block(); // Drop the packet
                    return;
                }

                // Start tracking new connection
                if (!hostConnections.containsKey(connKey)) {
                    hostConnections.put(connKey, new ConnectionStats());
                    log.info("New TCP connection: {} -> {}", srcMac, dstMac);
                }
            }

            // Update statistics for existing connections
            if (hostConnections.containsKey(connKey)) {
                ConnectionStats stats = hostConnections.get(connKey);
                stats.incrementPacketCount();

                // Check for FIN or RST flag (connection closing)
                if ((tcpPacket.getFlags() & 0x01) != 0 || (tcpPacket.getFlags() & 0x04) != 0) { // FIN or RST
                    stats.setEndTime(System.currentTimeMillis());
                    logConnectionStats(srcMac, connKey, stats);
                    hostConnections.remove(connKey);
                    log.info("TCP connection closed: {} -> {}", srcMac, dstMac);
                }
            }

            // Forward the packet normally
            PortNumber outPort = macTables.get(deviceId).get(dstMac);
            if (outPort != null) {
                installRule(context, outPort);
            } else {
                flood(context);
            }
        }

        /**
         * Installs a flow rule for the given output port.
         */
        private void installRule(PacketContext context, PortNumber portNumber) {
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
            selectorBuilder.matchInPort(pkt.receivedFrom().port())
                          .matchEthSrc(ethPkt.getSourceMAC())
                          .matchEthDst(ethPkt.getDestinationMAC());

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(portNumber)
                    .build();

            ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                    .withSelector(selectorBuilder.build())
                    .withTreatment(treatment)
                    .withPriority(10)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(FLOW_TIMEOUT)
                    .add();

            flowObjectiveService.forward(pkt.receivedFrom().deviceId(), forwardingObjective);

            // Forward the packet
            context.treatmentBuilder().setOutput(portNumber);
            context.send();
        }

        /**
         * Floods the packet to all ports except the input port.
         */
        private void flood(PacketContext context) {
            context.treatmentBuilder().setOutput(PortNumber.FLOOD);
            context.send();
        }
    }

    /**
     * Logs TCP connection statistics to a file.
     */
    private void logConnectionStats(MacAddress hostMac, ConnectionKey connKey, ConnectionStats stats) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(LOG_FILE_PATH, true))) {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String timestamp = sdf.format(new Date());
            long duration = stats.getDurationMs();
            int packetCount = stats.getPacketCount();

            String logEntry = String.format("%s | Host: %s | Connection: %s -> %s:%d | Duration: %d ms | Packets: %d",
                    timestamp, hostMac, connKey.srcIp, connKey.dstIp, connKey.dstPort, duration, packetCount);

            writer.println(logEntry);
            log.info("Logged connection stats: {}", logEntry);
        } catch (IOException e) {
            log.error("Failed to write connection statistics to file", e);
        }
    }

    /**
     * Logs all active connection statistics (called during deactivation).
     */
    private void logAllConnectionStats() {
        for (Map.Entry<MacAddress, Map<ConnectionKey, ConnectionStats>> entry : activeConnections.entrySet()) {
            MacAddress hostMac = entry.getKey();
            for (Map.Entry<ConnectionKey, ConnectionStats> connEntry : entry.getValue().entrySet()) {
                ConnectionKey connKey = connEntry.getKey();
                ConnectionStats stats = connEntry.getValue();
                stats.setEndTime(System.currentTimeMillis());
                logConnectionStats(hostMac, connKey, stats);
            }
        }
    }

    /**
     * Represents a unique TCP connection.
     */
    private static class ConnectionKey {
        final MacAddress srcMac;
        final MacAddress dstMac;
        final int srcIp;
        final int dstIp;
        final int srcPort;
        final int dstPort;

        ConnectionKey(MacAddress srcMac, MacAddress dstMac, int srcIp, int dstIp, int srcPort, int dstPort) {
            this.srcMac = srcMac;
            this.dstMac = dstMac;
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ConnectionKey that = (ConnectionKey) o;
            return srcIp == that.srcIp && dstIp == that.dstIp && 
                   srcPort == that.srcPort && dstPort == that.dstPort;
        }

        @Override
        public int hashCode() {
            return 31 * srcIp + 31 * dstIp + 31 * srcPort + dstPort;
        }
    }

    /**
     * Tracks statistics for a TCP connection.
     */
    private static class ConnectionStats {
        private final long startTime;
        private long endTime;
        private int packetCount;

        ConnectionStats() {
            this.startTime = System.currentTimeMillis();
            this.endTime = 0;
            this.packetCount = 0;
        }

        void incrementPacketCount() {
            packetCount++;
        }

        void setEndTime(long endTime) {
            this.endTime = endTime;
        }

        long getDurationMs() {
            return (endTime > 0 ? endTime : System.currentTimeMillis()) - startTime;
        }

        int getPacketCount() {
            return packetCount;
        }
    }
}
