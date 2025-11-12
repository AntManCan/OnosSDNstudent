package org.onosproject.learningbridge;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleEvent;
import org.onosproject.net.flow.FlowRuleListener;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.TcpPortCriterion;
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
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ONOS Learning Bridge Application with Connection Limiting.
 * 
 * This application implements a learning bridge that:
 * 1. Learns MAC addresses and their associated ports
 * 2. Limits the number of simultaneous connections per host to MAX_CONNECTIONS_PER_HOST different destinations
 * 3. Applies the limit to ALL traffic (not just TCP)
 * 4. For TCP traffic, logs connection statistics (bytes, packets, duration) retrieved from flow rules
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

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    private ApplicationId appId;
    private LearningBridgeProcessor processor = new LearningBridgeProcessor();
    private InternalFlowListener flowListener = new InternalFlowListener();

    // MAC learning table: DeviceId -> (MacAddress -> PortNumber)
    private Map<DeviceId, Map<MacAddress, PortNumber>> macTables = new ConcurrentHashMap<>();

    // Track active destinations per source host: SourceMac -> Set of DestMacs
    private Map<MacAddress, Set<MacAddress>> activeDestinations = new ConcurrentHashMap<>();

    // TCP connection tracking for logging: ConnectionKey -> ConnectionInfo
    private Map<ConnectionKey, TcpConnectionInfo> tcpConnections = new ConcurrentHashMap<>();

    // Maximum number of simultaneous connections per host
    private static final int MAX_CONNECTIONS_PER_HOST = 2; // Configurable value

    // Flow rule timeout
    private static final int FLOW_TIMEOUT = 5; // seconds

    // Log file path
    private static final String LOG_FILE_PATH = "/tmp/tcp_connections.log";

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.onosproject.learningbridge");
        packetService.addProcessor(processor, PacketProcessor.director(2));
        flowRuleService.addListener(flowListener); // Listen for flow removal events

        // Request packet-in for all packets
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Learning Bridge Application Started with connection limiting (max {} per host)", 
                 MAX_CONNECTIONS_PER_HOST);
    }

    @Deactivate
    protected void deactivate() {
        flowRuleService.removeListener(flowListener); // Remove flow listener
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

            // Check connection limit for ALL traffic (not just TCP)
            // EXCLUDE broadcast and multicast destinations from connection limiting
            if (!dstMac.isBroadcast() && !dstMac.isMulticast()) {
                activeDestinations.putIfAbsent(srcMac, ConcurrentHashMap.newKeySet());
                Set<MacAddress> destinations = activeDestinations.get(srcMac);

                // If this is a new destination and we've reached the limit, drop the packet
                if (!destinations.contains(dstMac) && destinations.size() >= MAX_CONNECTIONS_PER_HOST) {
                    log.warn("Connection limit reached for host {}. Dropping packet to new destination {}", 
                             srcMac, dstMac);
                    context.block();
                    return;
                }

                // Add destination to active set
                destinations.add(dstMac);
            }

            // Special handling for TCP packets (for logging purposes)
            boolean isTcp = false;
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
                if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_TCP) {
                    isTcp = true;
                    handleTcpTracking(context, ethPkt, ipv4Packet);
                }
            }

            // Handle forwarding
            PortNumber outPort = macTables.get(deviceId).get(dstMac);

            if (outPort != null) {
                // Install flow rule and forward packet
                installRule(context, outPort, isTcp);
            } else {
                // Flood the packet
                flood(context);
            }
        }

        /**
         * Tracks TCP connections for statistics logging.
         * Only tracks SYN packets - flow expiry is handled by FlowRuleListener.
         */
        private void handleTcpTracking(PacketContext context, Ethernet ethPkt, IPv4 ipv4Packet) {
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

            // Check for SYN flag (new TCP connection)
            if ((tcpPacket.getFlags() & 0x02) != 0) { // SYN flag
                if (!tcpConnections.containsKey(connKey)) {
                    TcpConnectionInfo info = new TcpConnectionInfo(deviceId, srcMac, dstMac);
                    tcpConnections.put(connKey, info);
                    log.info("Tracking new TCP connection: {} -> {}:{}", 
                             srcMac, dstMac, tcpPacket.getDestinationPort());
                }
            }

            // Note: FIN/RST detection removed - flow expiry handled by InternalFlowListener
        }

        /**
         * Installs a flow rule for the given output port.
         */
        private void installRule(PacketContext context, PortNumber portNumber, boolean isTcp) {
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
            selectorBuilder.matchInPort(pkt.receivedFrom().port())
                          .matchEthSrc(ethPkt.getSourceMAC())
                          .matchEthDst(ethPkt.getDestinationMAC());
            
            // For TCP packets, add more specific matching to track flows
            if (isTcp) {
                IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
                TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                              .matchIPProtocol(IPv4.PROTOCOL_TCP)
                              .matchIPSrc(Ip4Prefix.valueOf(Ip4Address.valueOf(ipv4Packet.getSourceAddress()), 32))
                              .matchIPDst(Ip4Prefix.valueOf(Ip4Address.valueOf(ipv4Packet.getDestinationAddress()), 32))
                              .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                              .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
            }

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(portNumber)
                    .build();

            ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                    .withSelector(selectorBuilder.build())
                    .withTreatment(treatment)
                    .withPriority(isTcp ? 20 : 10) // Higher priority for TCP flows
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
     * Listens for flow rule removal events (including timeouts).
     * When a TCP flow is removed, retrieves statistics and logs them.
     */
    private class InternalFlowListener implements FlowRuleListener {
        @Override
        public void event(FlowRuleEvent event) {
            FlowRule flowRule = event.subject();

            // Only process removals of our flows
            if (flowRule.appId() != appId.id()) {
                return;
            }

            // Only interested in flow removals (including timeouts)
            if (event.type() == FlowRuleEvent.Type.RULE_REMOVED) {
                log.debug("Flow rule removed: {}", flowRule.id());
                
                // Clean up destination tracking for ALL flows (TCP, ICMP, UDP, etc.)
                handleFlowRemoval(flowRule);
                
                // Check if this was a TCP flow for statistics logging
                handleTcpFlowRemoval(flowRule);
            }
        }

        /**
         * Handles removal of ANY flow - cleans up destination tracking.
         * This ensures connection limits work correctly for all protocols (ICMP, TCP, UDP, etc.)
         */
        private void handleFlowRemoval(FlowRule flowRule) {
            TrafficSelector selector = flowRule.selector();

            try {
                // Extract MAC addresses from the flow rule
                EthCriterion srcEthCriterion = (EthCriterion) selector.getCriterion(Criterion.Type.ETH_SRC);
                EthCriterion dstEthCriterion = (EthCriterion) selector.getCriterion(Criterion.Type.ETH_DST);

                if (srcEthCriterion == null || dstEthCriterion == null) {
                    return; // Not a unicast flow
                }

                MacAddress srcMac = srcEthCriterion.mac();
                MacAddress dstMac = dstEthCriterion.mac();

                // Skip broadcast/multicast
                if (dstMac.isBroadcast() || dstMac.isMulticast()) {
                    return;
                }

                // Check if there are any remaining active flows from srcMac to dstMac
                if (!hasActiveFlowsBetween(srcMac, dstMac)) {
                    // No more flows between these hosts - remove destination from tracking
                    Set<MacAddress> destinations = activeDestinations.get(srcMac);
                    if (destinations != null) {
                        boolean removed = destinations.remove(dstMac);
                        if (removed) {
                            log.info("Connection ended: {} -> {}. Active destinations: {}", 
                                     srcMac, dstMac, destinations.size());
                        }
                    }
                }
            } catch (Exception e) {
                log.error("Error cleaning up flow removal", e);
            }
        }

        /**
         * Check if there are any active flows between source and destination MACs.
         */
        private boolean hasActiveFlowsBetween(MacAddress srcMac, MacAddress dstMac) {
            // Query all devices and check their flows
            for (Device device : deviceService.getAvailableDevices()) {
                Iterable<FlowEntry> flowEntries = flowRuleService.getFlowEntries(device.id());
                
                for (FlowEntry entry : flowEntries) {
                    // Only check our app's flows
                    if (entry.appId() != appId.id()) {
                        continue;
                    }
                    
                    TrafficSelector selector = entry.selector();
                    
                    EthCriterion srcEth = (EthCriterion) selector.getCriterion(Criterion.Type.ETH_SRC);
                    EthCriterion dstEth = (EthCriterion) selector.getCriterion(Criterion.Type.ETH_DST);
                    
                    if (srcEth != null && dstEth != null &&
                        srcEth.mac().equals(srcMac) && dstEth.mac().equals(dstMac)) {
                        return true; // Found an active flow
                    }
                }
            }
            
            return false; // No active flows
        }

        /**
         * Handles removal of TCP flows - retrieves statistics and logs.
         */
        private void handleTcpFlowRemoval(FlowRule flowRule) {
            TrafficSelector selector = flowRule.selector();

            // Check if this is a TCP flow (has IP protocol criterion)
            Criterion ipProtoCriterion = selector.getCriterion(Criterion.Type.IP_PROTO);
            if (ipProtoCriterion == null) {
                return; // Not a TCP flow
            }

            // Extract connection details from the flow rule
            try {
                MacAddress srcMac = ((EthCriterion) selector.getCriterion(Criterion.Type.ETH_SRC)).mac();
                MacAddress dstMac = ((EthCriterion) selector.getCriterion(Criterion.Type.ETH_DST)).mac();
                
                IPCriterion srcIpCriterion = (IPCriterion) selector.getCriterion(Criterion.Type.IPV4_SRC);
                IPCriterion dstIpCriterion = (IPCriterion) selector.getCriterion(Criterion.Type.IPV4_DST);
                
                TcpPortCriterion srcPortCriterion = (TcpPortCriterion) selector.getCriterion(Criterion.Type.TCP_SRC);
                TcpPortCriterion dstPortCriterion = (TcpPortCriterion) selector.getCriterion(Criterion.Type.TCP_DST);

                if (srcIpCriterion == null || dstIpCriterion == null || 
                    srcPortCriterion == null || dstPortCriterion == null) {
                    return; // Not a complete TCP flow
                }

                // Convert IP addresses to int (IPv4 only)
                Ip4Address srcIp4 = srcIpCriterion.ip().address().getIp4Address();
                Ip4Address dstIp4 = dstIpCriterion.ip().address().getIp4Address();
                int srcIp = srcIp4.toInt();
                int dstIp = dstIp4.toInt();
                int srcPort = srcPortCriterion.tcpPort().toInt();
                int dstPort = dstPortCriterion.tcpPort().toInt();

                ConnectionKey connKey = new ConnectionKey(srcMac, dstMac, srcIp, dstIp, srcPort, dstPort);

                // Check if we were tracking this connection
                TcpConnectionInfo info = tcpConnections.remove(connKey);
                if (info != null) {
                    info.setEndTime(System.currentTimeMillis());
                    
                    // Get statistics from the flow rule (if it's a FlowEntry)
                    long bytes = 0;
                    long packets = 0;
                    if (flowRule instanceof FlowEntry) {
                        FlowEntry entry = (FlowEntry) flowRule;
                        bytes = entry.bytes();
                        packets = entry.packets();
                    }

                    log.info("TCP flow expired: {} -> {} ({}:{} -> {}:{})", 
                             srcMac, dstMac, 
                             Ip4Address.valueOf(srcIp), srcPort,
                             Ip4Address.valueOf(dstIp), dstPort);
                    
                    logTcpConnectionStats(connKey, info, bytes, packets);

                    // Clean up destination tracking
                    Set<MacAddress> destinations = activeDestinations.get(srcMac);
                    if (destinations != null && !hasActiveConnectionsTo(srcMac, dstMac)) {
                        destinations.remove(dstMac);
                        log.debug("Removed destination {} from active set for {}", dstMac, srcMac);
                    }
                }
            } catch (Exception e) {
                log.error("Error processing TCP flow removal", e);
            }
        }

        /**
         * Check if a source host has any active TCP connections to a destination.
         */
        private boolean hasActiveConnectionsTo(MacAddress srcMac, MacAddress dstMac) {
            return tcpConnections.entrySet().stream()
                .anyMatch(entry -> entry.getKey().srcMac.equals(srcMac) && 
                                   entry.getKey().dstMac.equals(dstMac));
        }
    }

    /**
     * Retrieves flow statistics from the switch and logs TCP connection stats.
     */
    private void retrieveAndLogFlowStats(DeviceId deviceId, ConnectionKey connKey, TcpConnectionInfo info) {
        // Build selector to match the TCP flow
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .matchEthSrc(connKey.srcMac)
                .matchEthDst(connKey.dstMac)
                .matchIPSrc(Ip4Prefix.valueOf(Ip4Address.valueOf(connKey.srcIp), 32))
                .matchIPDst(Ip4Prefix.valueOf(Ip4Address.valueOf(connKey.dstIp), 32))
                .matchTcpSrc(TpPort.tpPort(connKey.srcPort))
                .matchTcpDst(TpPort.tpPort(connKey.dstPort))
                .build();

        // Find matching flow entries on the device
        long totalBytes = 0;
        long totalPackets = 0;
        
        for (FlowEntry entry : flowRuleService.getFlowEntries(deviceId)) {
            if (entry.appId() == appId.id() && flowSelectorsMatch(entry.selector(), selector)) {
                totalBytes += entry.bytes();
                totalPackets += entry.packets();
                log.debug("Found flow entry - Bytes: {}, Packets: {}", entry.bytes(), entry.packets());
            }
        }

        // Log the statistics
        logTcpConnectionStats(connKey, info, totalBytes, totalPackets);
    }

    /**
     * Check if two selectors match (for TCP flows).
     */
    private boolean flowSelectorsMatch(TrafficSelector entry, TrafficSelector target) {
        // Simple comparison - check if entry contains the TCP flow criteria we're looking for
        return entry.getCriterion(Criterion.Type.ETH_TYPE) != null &&
               entry.getCriterion(Criterion.Type.IP_PROTO) != null &&
               target.criteria().stream().allMatch(c -> entry.criteria().contains(c));
    }

    /**
     * Logs TCP connection statistics to a file.
     */
    private void logTcpConnectionStats(ConnectionKey connKey, TcpConnectionInfo info, 
                                       long bytes, long packets) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(LOG_FILE_PATH, true))) {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String timestamp = sdf.format(new Date());
            long duration = info.getDurationMs();

            String logEntry = String.format(
                "%s | SrcMAC: %s | DstMAC: %s | %s:%d -> %s:%d | Duration: %d ms | Bytes: %d | Packets: %d",
                timestamp, 
                connKey.srcMac, 
                connKey.dstMac,
                Ip4Address.valueOf(connKey.srcIp).toString(),
                connKey.srcPort,
                Ip4Address.valueOf(connKey.dstIp).toString(),
                connKey.dstPort,
                duration, 
                bytes, 
                packets
            );

            writer.println(logEntry);
            log.info("Logged TCP connection stats: Bytes={}, Packets={}, Duration={}ms", bytes, packets, duration);
        } catch (IOException e) {
            log.error("Failed to write TCP connection statistics to file", e);
        }
    }

    /**
     * Logs all active TCP connection statistics (called during deactivation).
     */
    private void logAllConnectionStats() {
        for (Map.Entry<ConnectionKey, TcpConnectionInfo> entry : tcpConnections.entrySet()) {
            ConnectionKey connKey = entry.getKey();
            TcpConnectionInfo info = entry.getValue();
            info.setEndTime(System.currentTimeMillis());
            retrieveAndLogFlowStats(info.deviceId, connKey, info);
        }
    }

    /**
     * Represents a unique connection (used for both TCP tracking and general connection limiting).
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
     * Tracks information for a TCP connection.
     */
    private static class TcpConnectionInfo {
        final DeviceId deviceId;
        final MacAddress srcMac;
        final MacAddress dstMac;
        private final long startTime;
        private long endTime;

        TcpConnectionInfo(DeviceId deviceId, MacAddress srcMac, MacAddress dstMac) {
            this.deviceId = deviceId;
            this.srcMac = srcMac;
            this.dstMac = dstMac;
            this.startTime = System.currentTimeMillis();
            this.endTime = 0;
        }

        void setEndTime(long endTime) {
            this.endTime = endTime;
        }

        long getDurationMs() {
            return (endTime > 0 ? endTime : System.currentTimeMillis()) - startTime;
        }
    }
}
