#!/usr/bin/env python3
"""
Mininet topology for testing ONOS Learning Bridge with connection limiting.

NOTE: This script is for REFERENCE ONLY. Mininet should run in a separate VM,
not in the dev container (OVS kernel module issues in containers).

To use:
1. Copy this file to your Mininet VM
2. Update the controller IP in createTopology() to point to your host
3. Run: sudo python3 test_topology.py

Alternatively, use the manual mn command:
  sudo mn --topo tree,2 --mac --switch ovsk,protocols=OpenFlow13 \
    --controller remote,ip=<HOST_IP>,port=6653
"""

import os
import subprocess
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def startOVS():
    """Ensure Open vSwitch is running."""
    info('*** Checking Open vSwitch status\n')
    try:
        result = subprocess.run(['service', 'openvswitch-switch', 'status'], 
                              capture_output=True, text=True)
        if 'active (running)' not in result.stdout:
            info('*** Starting Open vSwitch\n')
            subprocess.run(['service', 'openvswitch-switch', 'start'], check=True)
            info('*** Open vSwitch started\n')
        else:
            info('*** Open vSwitch already running\n')
    except Exception as e:
        info(f'*** Warning: Could not check/start OVS: {e}\n')
        info('*** If Mininet fails, run: sudo service openvswitch-switch start\n')

def createTopology():
    """
    Creates a simple topology:
    
    h1 --- s1 --- s2 --- h2
           |       |
           h3     h4
    """
    # Use OVS switch and force userspace datapath to avoid kernel module requirement in containers
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSSwitch)
    
    info('*** Adding ONOS controller\n')
    # ONOS controller on localhost
    c0 = net.addController('c0', controller=RemoteController, 
                          ip='127.0.0.1', port=6653)
    
    info('*** Adding switches\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13', datapath='user')
    s2 = net.addSwitch('s2', protocols='OpenFlow13', datapath='user')
    
    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
    
    info('*** Creating links\n')
    net.addLink(h1, s1)
    net.addLink(h3, s1)
    net.addLink(s1, s2)
    net.addLink(h2, s2)
    net.addLink(h4, s2)
    
    info('*** Starting network\n')
    net.start()
    
    info('*** Running CLI\n')
    info('*** Test connectivity with: pingall\n')
    info('*** Example commands:\n')
    info('***   pingall                    - Test all host connectivity\n')
    info('***   h1 ping h2                 - Ping between specific hosts\n')
    info('***   h1 iperf -s &              - Start iperf server on h1\n')
    info('***   h2 iperf -c 10.0.0.1 -t 10 - Test bandwidth from h2 to h1\n')
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    startOVS()
    createTopology()
