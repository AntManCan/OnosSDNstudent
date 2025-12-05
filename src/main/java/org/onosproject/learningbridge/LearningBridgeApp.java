package org.onosproject.learningbridge;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.IpPrefix;
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
import org.onosproject.net.flow.criteria.IPProtocolCriterion;
import org.onosproject.net.flow.criteria.TcpFlagsCriterion;
import org.onosproject.net.flow.criteria.TcpPortCriterion;
import org.onosproject.net.flow.criteria.Criterion.TcpFlags;
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
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ONOS Learning Bridge Application - Student Starter Template
 * 
 * LEARNING OBJECTIVES:
 * This application will teach you to implement a learning bridge with advanced features:
 * 1. Basic MAC address learning and forwarding
 * 2. Connection limiting (max simultaneous connections per host)
 * 3. TCP statistics logging (duration, bytes, packets)
 * 4. Flow rule management and lifecycle
 * 
 * CURRENT STATE: Acts like a HUB (floods all packets)
 * YOUR TASK: Implement learning bridge behavior with connection limiting and statistics
 * 
 * See IMPLEMENTATION_GUIDE.md for detailed guidance on architecture and data structures.
 */
@Component(immediate = true)
public class LearningBridgeApp {

    private final Logger log = LoggerFactory.getLogger(getClass());

    // ============================================================================
    // ONOS SERVICE REFERENCES (ALREADY PROVIDED)
    // ============================================================================
    // These @Reference annotations inject ONOS services into your application

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

    // ============================================================================
    // APPLICATION STATE
    // ============================================================================
    
    private ApplicationId appId;
    private LearningBridgeProcessor processor = new LearningBridgeProcessor();
    private InternalFlowListener flowListener = new InternalFlowListener();

    // TODO: TASK 1 - Declare MAC Learning Table
    // HINT: Map<DeviceId, Map<MacAddress, PortNumber>> to store MAC->Port mappings per device
    // HINT: Use ConcurrentHashMap for thread-safety
    // private Map<DeviceId, Map<MacAddress, PortNumber>> macTables = new ConcurrentHashMap<>();
    private Map<DeviceId, Map<MacAddress, PortNumber>> macTables = new ConcurrentHashMap<>();

    // TODO: TASK 2 - Declare Connection Tracking (for connection limiting)
    // HINT: Map<MacAddress, Set<MacAddress>> to track active destinations per source
    private Map<MacAddress, Set<MacAddress>> activeDestinations = new ConcurrentHashMap<>();

    // TODO: TASK 3 - Declare TCP Connection Tracking (for statistics)
    // HINT: Map<ConnectionKey, TcpConnectionInfo> to track TCP connections
    private Map<ConnectionKey, TcpConnectionInfo> tcpConnections = new ConcurrentHashMap<>();

    // TODO: TASK 4 - Define Configuration Constants
    private static final int MAX_CONNECTIONS_PER_HOST = 2;
    private static final int FLOW_TIMEOUT = 5;  // seconds
    private static final String LOG_FILE_PATH = "/tmp/tcp_connections.log";

    // ============================================================================
    // APPLICATION LIFECYCLE (ALREADY IMPLEMENTED)
    // ============================================================================

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.onosproject.learningbridge");
        packetService.addProcessor(processor, PacketProcessor.director(2));
        flowRuleService.addListener(flowListener);

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Learning Bridge Application Started (Student Version - Hub Mode)");
    }

    @Deactivate
    protected void deactivate() {
        flowRuleService.removeListener(flowListener);
        packetService.removeProcessor(processor);
        flowRuleService.removeFlowRulesById(appId);

        // TODO: TASK 5 - Call logAllConnectionStats() if implementing TCP tracking
        logAllConnectionStats();

        log.info("Learning Bridge Application Stopped");
    }

    // ============================================================================
    // PACKET PROCESSING
    // ============================================================================

    private class LearningBridgeProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            // Extract packet information (ALREADY IMPLEMENTED)
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();
            DeviceId deviceId = pkt.receivedFrom().deviceId();
            PortNumber inPort = pkt.receivedFrom().port();

            log.debug("Packet received: {} -> {} on device {} port {}", 
                      srcMac, dstMac, deviceId, inPort);

            // TODO: TASK 6 - Implement MAC Address Learning
            // HINT: Update macTables with srcMac -> inPort mapping for this deviceId
            // macTables.putIfAbsent(deviceId, new ConcurrentHashMap<>());
            // macTables.get(deviceId).put(srcMac, inPort);
            
            macTables.putIfAbsent(deviceId, new ConcurrentHashMap<>());
            macTables.get(deviceId).putIfAbsent(srcMac, inPort);
            //log.info("Learned: {} -> port {} on device {}", srcMac, inPort, deviceId);

            activeDestinations.putIfAbsent(srcMac,  new HashSet<>());

            // TODO: TASK 7 - Implement Connection Limiting (ADVANCED)
            // HINT: Only for unicast (not broadcast/multicast)
            // HINT: Check if destination count exceeds MAX_CONNECTIONS_PER_HOST
            // HINT: If limit reached, block packet with context.block()
            if (!dstMac.isBroadcast() && !dstMac.isMulticast()) {
                if (activeDestinations.get(srcMac).size() <= MAX_CONNECTIONS_PER_HOST) {
                    if (!activeDestinations.get(srcMac).contains(dstMac)) {
                        activeDestinations.get(srcMac).add(dstMac);
                        //log.info("== Connection established between {} and {}", srcMac, dstMac);
                        //log.info(activeDestinations.get(srcMac).toString());
                    }
                } else {
                    context.block();
                    //log.info("== Blocked Connection between {} and {}", srcMac, dstMac);
                }
                // Track and enforce connection limit  
            }

            // TODO: TASK 8 - Handle TCP Packets (ADVANCED)
            // HINT: Check if packet is IPv4 and TCP protocol
            // HINT: Call handleTcpTracking() to track SYN packets
            boolean isTcp = false;
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                //log.info("process: is IPv4");
                IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
                //log.info("ipv4Packet protocol: {}",ipv4Packet.getProtocol());
                //IPv4.PROTOCOL_ICMP
                if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_TCP) {
                    //log.info("process: is TCP");
                    isTcp = true;
                    handleTcpTracking(context, ethPkt, ipv4Packet);
                }
            }

            // TODO: TASK 9 - Implement Forwarding Decision
            // HINT: Look up dstMac in macTables.get(deviceId)
            // HINT: If found, call installRule(context, outPort, isTcp)
            // HINT: If not found, call flood(context)
            //|| !ethPkt.isBroadcast() || !ethPkt.isMulticast()
            if (macTables.get(deviceId).containsKey(dstMac)) {
                PortNumber outPort = macTables.get(deviceId).get(dstMac);
                installRule(context, outPort, isTcp);
                //log.info("== Installed Rule: {} -> port {} on device {}", dstMac, outPort, deviceId);
            } else {
                //log.info("Flooding!");
                // CURRENT IMPLEMENTATION: Just flood (HUB behavior)
                flood(context);
            }
        }

        /**
         * Floods packet to all ports (ALREADY IMPLEMENTED).
         * This makes the switch act like a HUB.
         */
        private void flood(PacketContext context) {
            context.treatmentBuilder().setOutput(PortNumber.FLOOD);
            context.send();
        }

        private void forward(PacketContext context, PortNumber outPort) {
            context.treatmentBuilder().setOutput(outPort);
            context.send();
        }

        // TODO: TASK 10 - Implement installRule method
        // private void installRule(PacketContext context, PortNumber portNumber, boolean isTcp) {
        //     // Build TrafficSelector with MAC addresses, input port
        //     // For TCP: add IP addresses and ports
        //     // Build TrafficTreatment with output port
        //     // Create ForwardingObjective with priority and timeout
        //     // Install with flowObjectiveService.forward()
        //     // Forward current packet
        // }
        private void installRule(PacketContext context, PortNumber portNumber, boolean isTcp) {
            // Extract packet information
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                log.info("Error in installRule: ethPkt is Null");
                return;
            }

            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();
            DeviceId deviceId = pkt.receivedFrom().deviceId();
            PortNumber inPort = pkt.receivedFrom().port();
            short ethType = ethPkt.getEtherType(); // Match ethtype?

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
            ForwardingObjective.Builder objective = DefaultForwardingObjective.builder();

            if (isTcp) {
                 
                if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                    IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();

                    TCP tcpPkt = (TCP) ipv4Packet.getPayload();

                    if (tcpPkt == null) {
                        return;
                    }

                    byte iPprotocol = ipv4Packet.getProtocol();
                    Ip4Address srcIP = Ip4Address.valueOf(ipv4Packet.getSourceAddress());
                    Ip4Address dstIP = Ip4Address.valueOf(ipv4Packet.getDestinationAddress());
                    
                    int srcTcpPort = tcpPkt.getSourcePort();
                    int dstTcpPort = tcpPkt.getDestinationPort();

                    selector.matchIPProtocol(iPprotocol);
                    selector.matchIPDst(srcIP.toIpPrefix());
                    selector.matchIPSrc(dstIP.toIpPrefix());
                    selector.matchTcpSrc(TpPort.tpPort(srcTcpPort));
                    selector.matchTcpDst(TpPort.tpPort(dstTcpPort));

                    objective.withPriority(40000);

                    //objective.makePermanent();
                    //log.info("Installed TCP Rule: {} -> {}",srcIP, dstIP);

                } else {
                    log.info("Error in installRule: ipv4Packet is Null");
                    return;
                }
                
            } else {
                objective.withPriority(32768);
            }
            
            selector.matchInPort(inPort);
            selector.matchEthSrc(srcMac);
            selector.matchEthDst(dstMac);
            selector.matchEthType(ethType);

            treatment.setOutput(portNumber);

            objective.fromApp(appId);
            objective.withSelector(selector.build());
            objective.withTreatment(treatment.build());
            objective.withFlag(ForwardingObjective.Flag.VERSATILE);
            objective.makeTemporary(FLOW_TIMEOUT);

            flowObjectiveService.forward(deviceId, objective.add());
            forward(context, portNumber);

            //log.info("== Installed Rule: {} -> port {} on device {}", dstMac, portNumber, deviceId);
            //log.info("flowRule Count = {}", flowRuleService.getFlowRuleCount(deviceId));
        }

        // TODO: TASK 11 - Implement handleTcpTracking method (ADVANCED)
        private void handleTcpTracking(PacketContext context, Ethernet ethPkt, IPv4 ipv4Packet) {
            //log.info("hadleTcpTracking to do!");
            // Extract TCP packet, check for SYN flag
            // Create ConnectionKey
            // Store in tcpConnections if new

            TCP tcpPkt = (TCP) ipv4Packet.getPayload();

            if (tcpPkt == null) {
                return;
            }

            DeviceId deviceId = context.inPacket().receivedFrom().deviceId();

            Ip4Address srcIp = Ip4Address.valueOf(ipv4Packet.getSourceAddress());
            Ip4Address dstIp = Ip4Address.valueOf(ipv4Packet.getDestinationAddress());

            int srcTcpPort = tcpPkt.getSourcePort();
            int dstTcpPort = tcpPkt.getDestinationPort();

            boolean isSyn = (tcpPkt.getFlags() & 0x02) != 0;
            boolean isFin = (tcpPkt.getFlags() & 0x01) != 0;

            if (isSyn) {
                MacAddress srcMacAddr = ethPkt.getSourceMAC();
                MacAddress dstMacAddr = ethPkt.getDestinationMAC();

                ConnectionKey connectionKey = new ConnectionKey(srcIp, dstIp, TpPort.tpPort(srcTcpPort), TpPort.tpPort(dstTcpPort), (short) ipv4Packet.getProtocol());
                
                TcpConnectionInfo tcpInfo = new TcpConnectionInfo(deviceId, srcMacAddr, dstMacAddr, System.currentTimeMillis());

                tcpConnections.putIfAbsent(connectionKey, tcpInfo);
                log.info("New TCP Connection: {} -> {}", srcIp, dstIp);
            } else if (isFin) {
                ConnectionKey connectionKey = new ConnectionKey(srcIp, dstIp, TpPort.tpPort(srcTcpPort), TpPort.tpPort(dstTcpPort), (short) ipv4Packet.getProtocol());
                log.info("handleTcpFlowTracking: srcIp={}, dstIp={}, srcTcp={}, dstTcp={}, protocol={}",
                    srcIp, dstIp, TpPort.tpPort(srcTcpPort), TpPort.tpPort(dstTcpPort), (short) ipv4Packet.getProtocol());

                if (tcpConnections.containsKey(connectionKey)) {
                    TcpConnectionInfo tcpConnectionInfo = tcpConnections.get(connectionKey);
                    tcpConnectionInfo.setEndTime(System.currentTimeMillis());
                    log.info("Closing Tcp Connection:");
                    //log.info(tcpConnectionInfo.toString());

                    FlowEntry flowEntry = findFlowEntryForPacket(ipv4Packet, tcpPkt, deviceId);
                    if (flowEntry == null) { 
                        log.info("handleTcpTracking: flowEntry == null, skipping.");
                        return;
                    }

                    logTcpConnectionStats(connectionKey, tcpConnectionInfo, flowEntry.bytes() , flowEntry.packets());
                } else {
                    log.info("Error in handleTcpTracking: no match found for key!");
                }
                
            }
             

        }

        private FlowEntry findFlowEntryForPacket(IPv4 ipv4Packet, TCP tcpPkt, DeviceId deviceId) {
            Ip4Address srcIp = Ip4Address.valueOf(ipv4Packet.getSourceAddress());
            Ip4Address dstIp = Ip4Address.valueOf(ipv4Packet.getDestinationAddress());
            TpPort srcPort = TpPort.tpPort(tcpPkt.getSourcePort());
            TpPort dstPort = TpPort.tpPort(tcpPkt.getDestinationPort());
            byte protocol = ipv4Packet.getProtocol();

            for (FlowEntry flowEntry : flowRuleService.getFlowEntries(deviceId)) {
                TrafficSelector selector = flowEntry.selector();
                Ip4Address selSrcIp = null, selDstIp = null;
                TpPort selSrcPort = null, selDstPort = null;
                Byte selProtocol = null;

                for (Criterion criterion : selector.criteria()) {
                    if (criterion instanceof IPCriterion) {
                        IPCriterion ip = (IPCriterion) criterion;
                        if (criterion.type() == Criterion.Type.IPV4_SRC) {
                            selSrcIp = ip.ip().address().getIp4Address();
                        } else if (criterion.type() == Criterion.Type.IPV4_DST) {
                            selDstIp = ip.ip().address().getIp4Address();
                        }
                    }
                    if (criterion instanceof TcpPortCriterion) {
                        TcpPortCriterion tcp = (TcpPortCriterion) criterion;
                        if (criterion.type() == Criterion.Type.TCP_SRC) {
                            selSrcPort = tcp.tcpPort();
                        } else if (criterion.type() == Criterion.Type.TCP_DST) {
                            selDstPort = tcp.tcpPort();
                        }
                    }
                    if (criterion instanceof IPProtocolCriterion) {
                        IPProtocolCriterion proto = (IPProtocolCriterion) criterion;
                        selProtocol = (byte) proto.protocol();
                    }
                }

                if (srcIp.equals(selSrcIp) && dstIp.equals(selDstIp) &&
                    srcPort.equals(selSrcPort) && dstPort.equals(selDstPort) &&
                    protocol == selProtocol) {
                    return flowEntry;
                }
            }
            return null;
        }
    }

    // ============================================================================
    // FLOW RULE MANAGEMENT
    // ============================================================================

    private class InternalFlowListener implements FlowRuleListener {
        
        @Override
        public void event(FlowRuleEvent event) {
            FlowRule flowRule = event.subject();

            if (flowRule.appId() != appId.id()) {
                return;
            }

            if (event.type() == FlowRuleEvent.Type.RULE_REMOVED) {
                // TODO: TASK 12 - Call handleFlowRemoval(flowRule)
                if (hasIpOrTcpCriteria(flowRule)) {
                    handleTcpFlowRemoval(flowRule);
                } else {
                    handleFlowRemoval(flowRule);
                }
                // TODO: TASK 13 - Call handleTcpFlowRemoval(flowRule) for TCP flows
                
                //log.info("Flow rule removed: {}", flowRule.id());
                //log.info("flowRule Count = {}", flowRuleService.getFlowRuleCount(flowRule.deviceId()));
            }
        }

        // TODO: TASK 14 - Implement handleFlowRemoval method
        // private void handleFlowRemoval(FlowRule flowRule) {
        //     // Extract src and dst MAC from flow rule
        //     // Check if any other flows exist between them
        //     // If not, remove from activeDestinations
        // }

        private boolean hasIpOrTcpCriteria(FlowRule flowRule) {
            TrafficSelector selector = flowRule.selector();
            if (selector == null) {
                return false;
            }
            for (Criterion criterion : selector.criteria()) {
                if (criterion instanceof IPCriterion ||
                    criterion instanceof IPProtocolCriterion ||
                    criterion instanceof TcpPortCriterion) {
                    return true;
                }
            }
            return false;
        }

        private void handleFlowRemoval(FlowRule flowRule) {
            MacAddress srcMac = null;
            MacAddress dstMac = null;

            //log.info("== Removing flowRule {}",flowRule.id());

            TrafficSelector selector = flowRule.selector();
            if (selector == null) {
                return;
            }
            
            for (Criterion criterion : selector.criteria()) {
                if (criterion instanceof EthCriterion) {
                    EthCriterion eth = (EthCriterion) criterion;
                    MacAddress mac = eth.mac();
                    if (criterion.type() == Criterion.Type.ETH_SRC) {
                        srcMac = mac;
                    } else if (criterion.type() == Criterion.Type.ETH_DST) {
                        dstMac = mac;
                    }
                }
            }

            //flowRuleService.removeFlowRules(flowRule);
            //log.info("Flow removed between {} -> {}", srcMac, dstMac);

            if (srcMac != null && dstMac != null) {
                // now you have srcMac and dstMac — proceed with cleanup/logic
                if (!hasActiveFlowsBetween(srcMac, dstMac)) {
                    activeDestinations.get(srcMac).remove(dstMac);
                }
            }
            
            
        }

        // TODO: TASK 15 - Implement hasActiveFlowsBetween method
        private boolean hasActiveFlowsBetween(MacAddress srcMac, MacAddress dstMac) {
            // Query all devices and their flow entries
            // Return true if any flow matches srcMac -> dstMac
            MacAddress srcMacFlow = null;
            MacAddress dstMacFlow = null;
            for (FlowEntry flowEntry : flowRuleService.getFlowEntriesById(appId)) {
                //log.info("...querying flowEntry {}", flowEntry.id());
                TrafficSelector selector = flowEntry.selector();
                if (selector == null) {
                    return false;
                }
                for (Criterion criterion : selector.criteria()) {
                    if (criterion instanceof EthCriterion) {
                        EthCriterion eth = (EthCriterion) criterion;
                        MacAddress mac = eth.mac();
                        if (criterion.type() == Criterion.Type.ETH_SRC) {
                            srcMacFlow = mac;
                        } else if (criterion.type() == Criterion.Type.ETH_DST) {
                            dstMacFlow = mac;
                        }
                    }
                }
                if (srcMac.equals(srcMacFlow) & dstMac.equals(dstMacFlow)) {
                    //log.info("flowEntry {} IS A MATCH, won't remove from activeDestinations");
                    //log.info(activeDestinations.get(srcMac).toString());
                    return true;
                }
            }

            return false;
        }

        // TODO: TASK 16 - Implement handleTcpRemoval method (ADVANCED)
        private void handleTcpFlowRemoval(FlowRule flowRule) {
            // Check if TCP flow
            // Extract connection details
            // Get statistics from FlowEntry (bytes(), packets())
            // Log to file with duration, bytes, packets

            short protocol = 0;

            IpPrefix srcIp = null;
            IpPrefix dstIp = null;

            TpPort srcTcp = null;
            TpPort dstTcp = null;

            //log.info("== Removing flowRule {}",flowRule.id());

            TrafficSelector selector = flowRule.selector();
            if (selector == null) {
                return;
            }
            
            for (Criterion criterion : selector.criteria()) {
                if (criterion instanceof IPProtocolCriterion) {
                    IPProtocolCriterion prot = (IPProtocolCriterion) criterion;
                    protocol = prot.protocol();
                }
                    
                if (criterion instanceof IPCriterion) {
                    IPCriterion ip = (IPCriterion) criterion;
                    IpPrefix ipAddr = ip.ip();
                    if (criterion.type() == Criterion.Type.IPV4_SRC) {
                        srcIp = ipAddr;
                    } else if (criterion.type() == Criterion.Type.IPV4_DST) {
                        dstIp = ipAddr;
                    }
                }

                if (criterion instanceof TcpPortCriterion) {
                    TcpPortCriterion tcp = (TcpPortCriterion) criterion;
                    TpPort tcpAddr = tcp.tcpPort();
                    if (criterion.type() == Criterion.Type.TCP_SRC) {
                        dstTcp = tcpAddr;
                    } else if (criterion.type() == Criterion.Type.TCP_DST) {
                        srcTcp = tcpAddr;
                    }

                }
                
            }

            if (srcIp == null || dstIp == null || srcTcp == null || dstTcp == null) {
                log.info("handleTcpFlowRemoval: Missing TCP/IP criteria, skipping.");
                return;
            }

            if (srcIp.prefixLength() != 32 || dstIp.prefixLength() != 32) {
                log.info("handleTcpFlowRemoval: Non-/32 prefix, skipping.");
                return;
            }

            log.info("handleTcpFlowRemoval: srcIp={}, dstIp={}, srcTcp={}, dstTcp={}, protocol={}",
                srcIp.address().getIp4Address(), dstIp.address().getIp4Address(), srcTcp, dstTcp, protocol);

            ConnectionKey connectionKey = new ConnectionKey(
                srcIp.address().getIp4Address(), dstIp.address().getIp4Address(), srcTcp, dstTcp, protocol);
            log.info("{}: {} -> {}", connectionKey.toString(), connectionKey.srcIp().toString(), connectionKey.dstIp().toString());

            if (tcpConnections.containsKey(connectionKey)) {
                TcpConnectionInfo tcpConnectionInfo = tcpConnections.get(connectionKey);
                if (tcpConnectionInfo == null) {
                    log.info("handleTcpFlowRemoval: tcpConnectionInfo == null, skipping.");
                    return;
                }
                FlowEntry flowEntry = flowRuleService.getFlowEntry(flowRule);
                if (flowEntry == null) { 
                    log.info("handleTcpFlowRemoval: flowEntry == null, skipping.");
                    return;
                }
                //long bytes = flowEntry.bytes() != null ? flowEntry.bytes() : 0;

                //logTcpConnectionStats(connectionKey, tcpConnectionInfo, flowEntry.bytes() , flowEntry.packets());

            } else {
                log.info("Error in handleTcpFlowRemoval: no match found for key!");
            }

        }

        // TODO: TASK 17 - Implement hasActiveConnectionsTo method (ADVANCED)
        private boolean hasActiveConnectionsTo(MacAddress srcMac, MacAddress dstMac) {
            // Check tcpConnections map for matching entries
            
            
            return false;
        }
    }

    // ============================================================================
    // STATISTICS AND LOGGING (ADVANCED TASKS)
    // ============================================================================

    // TODO: TASK 18 - Implement logTcpConnectionStats method
    private void logTcpConnectionStats(ConnectionKey connKey, TcpConnectionInfo info, long bytes, long packets) {
        // Format: timestamp | SrcMAC | DstMAC | srcIP:srcPort -> dstIP:dstPort | Duration(ms) | Bytes | Packets
        // Write to LOG_FILE_PATH
        
        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String formattedDate = dateFormat.format(new Date());

        if (tcpConnections.containsKey(connKey)) {
            
            MacAddress srcMac = info.srcMac();
            MacAddress dstMac = info.dstMac();

            Ip4Address srcIp = connKey.srcIp();
            Ip4Address dstIp = connKey.dstIp();

            TpPort srcPort = connKey.srcPort();
            TpPort dstPort = connKey.dstPort();

            long duration = info.getDurationMs();

            String logString = formattedDate.toString()+" | "+srcMac.toString()+" | "
                +dstMac.toString()+" | "+srcIp.toString()+":"+srcPort.toString()+" -> "
                +dstIp.toString()+":"+dstPort.toString()+" | "+duration+" | "+bytes+packets;

            try (PrintWriter out = new PrintWriter(new FileWriter(LOG_FILE_PATH, true))) {
                out.println(logString);
            } catch (IOException e) {
                log.warn("Failed to write TCP log: {}", e.getMessage());
            }

            
        } else {
            log.info("Error in logTcpConnectionStats: no match found for key!");
        } 
        
    }

    // TODO: TASK 19 - Implement logAllConnectionStats method
    private void logAllConnectionStats() {
     // Iterate through tcpConnections and log stats for each
        log.info("logAllConnectionStats to do!");
    }

    // ============================================================================
    // HELPER CLASSES
    // ============================================================================

    // TODO: TASK 20 - Implement ConnectionKey class
    // See IMPLEMENTATION_GUIDE.md for structure and purpose
    private static class ConnectionKey {
        //private final MacAddress srcMac;
        //private final MacAddress dstMac;

        private final Ip4Address srcIp;
        private final Ip4Address dstIp;
        private final TpPort srcPort;
        private final TpPort dstPort;
        private final short protocol;

        public ConnectionKey(Ip4Address srcIp, Ip4Address dstIp, TpPort srcPort, TpPort dstPort, short protocol) {
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.protocol = protocol;
        }

        public Ip4Address srcIp() { return srcIp; }
        public Ip4Address dstIp() { return dstIp; }
        public TpPort srcPort() { return srcPort; }
        public TpPort dstPort() { return dstPort; }
        public short protocol() { return protocol; }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ConnectionKey that = (ConnectionKey) o;
            return protocol == that.protocol &&
                java.util.Objects.equals(srcIp, that.srcIp) &&
                java.util.Objects.equals(dstIp, that.dstIp) &&
                java.util.Objects.equals(srcPort, that.srcPort) &&
                java.util.Objects.equals(dstPort, that.dstPort);
        }

        @Override
        public int hashCode() {
            int result = srcIp != null ? srcIp.hashCode() : 0;
            result = 31 * result + (dstIp != null ? dstIp.hashCode() : 0);
            result = 31 * result + (srcPort != null ? srcPort.hashCode() : 0);
            result = 31 * result + (dstPort != null ? dstPort.hashCode() : 0);
            result = 31 * result + (int) protocol;
            return result;
        }
    }

    // TODO: TASK 21 - Implement TcpConnectionInfo class
    // See IMPLEMENTATION_GUIDE.md for structure and purpose
    
    private static class TcpConnectionInfo {
        // Fields to store connection metadata
        private final DeviceId deviceId;
        private final MacAddress srcMac;
        private final MacAddress dstMac;
        private final long startTime;
        private long endTime = 0;
        private boolean ended = false;

        public TcpConnectionInfo(DeviceId deviceId, MacAddress srcMac, MacAddress dstMac, long startTime) {
            this.deviceId = deviceId;
            this.srcMac = srcMac;
            this.dstMac = dstMac;
            this.startTime = startTime;
        }

        public DeviceId deviceId() {return deviceId;}
        public MacAddress srcMac() {return srcMac;}
        public MacAddress dstMac() {return dstMac;}
        public long startTime() {return startTime;}
        public long endTime() {return endTime;}

        public void setEndTime(long time) {
            this.endTime = time;
            this.ended = true;
        }

        // Method to calculate duration
        public long getDurationMs() {
            if (this.ended) {
                return this.endTime - this.startTime;
            }
            else {
                return  System.currentTimeMillis() - this.startTime;
            }
        }

    }
    
}
