#!/bin/bash

# Build Script — Rebuild the ONOS Learning Bridge application

set -e

echo "=========================================="
echo "ONOS Learning Bridge - Build"
echo "=========================================="
echo ""

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

ONOS_HOST=${ONOS_HOST:-localhost}
ONOS_SSH_PORT=${ONOS_SSH_PORT:-8101}
ONOS_USER=${ONOS_USER:-onos}
ONOS_PASSWORD=${ONOS_PASSWORD:-rocks}
ONOS_SSH_OPTS="-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPreferredAuthentications=password -oPasswordAuthentication=yes -oNumberOfPasswordPrompts=1"

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

###############################################################################
# The original script tried to start ONOS and install the app automatically.
# To avoid brittle startup timing and external registry lookups, we now:
#  - Only verify Java 11
#  - Build the app
#  - Print clear manual commands to start ONOS and install the bundle
###############################################################################

# Step 1: Check Java version
echo "Step 1: Checking Java version..."

# Detect architecture and set JAVA_HOME
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
    export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-arm64
elif [ "$ARCH" = "x86_64" ]; then
    export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
else
    # Try to find Java 11 automatically
    export JAVA_HOME=$(update-alternatives --query java | grep 'Value:' | grep 'java-11' | awk '{print $2}' | sed 's|/bin/java||')
fi

export PATH=$JAVA_HOME/bin:$PATH
export ONOS_SSH_OPTS="-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPreferredAuthentications=password -oPasswordAuthentication=yes -oNumberOfPasswordPrompts=1"
JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d'.' -f1)

if [ "$JAVA_VERSION" == "11" ]; then
    print_success "Java 11 is installed and active (Architecture: $ARCH)"
else
    print_warning "Java 11 expected, but found version $JAVA_VERSION"
    print_error "Please ensure Java 11 is installed"
    exit 1
fi
echo ""

# Step 2: Build the application
echo "Step 2: Building ONOS application..."
cd /workspaces/OpenFlow

if mvn -q clean package -DskipTests; then
    print_success "Application built successfully"
else
    print_error "Build failed"
    exit 1
fi
echo ""

# Step 3: What to do next (manual, reliable, student-friendly)
echo "=========================================="
echo "Build Complete!"
echo "=========================================="
echo ""
echo "Next steps (first time or after code changes):"
echo ""
echo "1) Start ONOS controller (if not running):"
echo "   cd /opt/onos && ./bin/onos-service start"
echo ""
echo "2) Open ONOS CLI (create wrapper first if needed - see GETTING_STARTED.md):"
echo "   onos-cli                         # password: rocks"
echo ""
echo "3) Install the bundle (recommended method):"
echo "   onos> bundle:install -s file:/workspaces/OpenFlow/target/learning-bridge-1.0-SNAPSHOT.jar"
echo ""
echo "   To update an existing bundle:"
echo "   onos> bundle:list | grep learning       # note the bundle ID"
echo "   onos> bundle:update <ID> file:/workspaces/OpenFlow/target/learning-bridge-1.0-SNAPSHOT.jar"
echo ""
echo "4) Activate required ONOS apps (first time only):"
echo "   onos> app activate org.onosproject.openflow"
echo "   onos> app activate org.onosproject.hostprovider"
echo "   onos> app activate org.onosproject.lldpprovider"
echo "   onos> app activate org.onosproject.fwd"
echo ""
echo "5) Start Mininet test topology:"
echo "   cd /workspaces/OpenFlow && sudo python3 test_topology.py"
echo ""
echo "6) Monitor logs & stats:"
echo "   tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep LearningBridge"
echo "   tail -f /tmp/tcp_connections.log"
echo ""
print_success "Re-run ./build.sh after every code change."
