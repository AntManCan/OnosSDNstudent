#!/bin/bash

# Environment Verification Script for ONOS Development
# This script checks that all components are properly installed and configured

echo "=========================================="
echo "ONOS Development Environment Verification"
echo "=========================================="
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

SUCCESS=0
WARNINGS=0
ERRORS=0

print_check() {
    echo -n "Checking $1... "
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    SUCCESS=$((SUCCESS+1))
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
    WARNINGS=$((WARNINGS+1))
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    ERRORS=$((ERRORS+1))
}

# Check 1: Java Version
print_check "Java 11"
JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d'.' -f1)
if [ "$JAVA_VERSION" == "11" ]; then
    JAVA_FULL=$(java -version 2>&1 | head -n 1 | awk -F '"' '{print $2}')
    print_success "Java 11 is installed ($JAVA_FULL)"
else
    print_error "Java 11 not found (found version $JAVA_VERSION)"
fi

# Check 2: JAVA_HOME
print_check "JAVA_HOME"
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
  EXPECTED_JAVA_HOME="/usr/lib/jvm/java-11-openjdk-arm64"
elif [ "$ARCH" = "x86_64" ]; then
  EXPECTED_JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
else
  EXPECTED_JAVA_HOME="/usr/lib/jvm/java-11-openjdk"
fi

if [ -n "$JAVA_HOME" ] && [ -d "$JAVA_HOME" ]; then
    if [[ "$JAVA_HOME" == *"java-11"* ]]; then
        print_success "JAVA_HOME is set to Java 11 ($JAVA_HOME)"
    else
        print_warning "JAVA_HOME is set but may not point to Java 11: $JAVA_HOME"
    fi
elif [ -n "$JAVA_HOME" ]; then
    print_warning "JAVA_HOME is set but directory doesn't exist: $JAVA_HOME"
else
    print_warning "JAVA_HOME is not set (expected: $EXPECTED_JAVA_HOME)"
fi

# Check 3: Maven
print_check "Maven"
if command -v mvn &> /dev/null; then
    MVN_VERSION=$(mvn -version | head -n 1)
    print_success "Maven is installed ($MVN_VERSION)"
else
    print_error "Maven not found"
fi

# Check 4: Architecture
print_check "Architecture"
ARCH=$(uname -m)
if [ "$ARCH" == "aarch64" ]; then
    print_success "ARM64 architecture detected"
elif [ "$ARCH" == "x86_64" ]; then
    print_success "x86_64 architecture detected"
else
    print_warning "Unknown architecture: $ARCH"
fi

# Check 5: ONOS Installation
print_check "ONOS Installation"
if [ -d "/opt/onos" ]; then
    if [ -f "/opt/onos/VERSION" ]; then
        ONOS_VERSION=$(cat /opt/onos/VERSION)
        print_success "ONOS is installed (version $ONOS_VERSION)"
    else
        print_success "ONOS directory exists"
    fi
else
    print_error "ONOS not found at /opt/onos"
fi

# Check 6: ONOS Running
print_check "ONOS Process"
if pgrep -f "karaf" > /dev/null; then
    print_success "ONOS is running"
else
    print_warning "ONOS is not running (start with: cd /opt/onos && ./bin/onos-service start)"
fi

# Check 7: ONOS OpenFlow Port
print_check "OpenFlow Port (6653)"
if netstat -tlnp 2>/dev/null | grep -q ":6653"; then
    print_success "ONOS is listening on port 6653"
elif [ ! command -v netstat &> /dev/null ]; then
    print_warning "Cannot check (netstat not available)"
else
    print_warning "Port 6653 not listening (ONOS may not be fully started)"
fi

# Check 8: Project Structure
print_check "Project Structure"
if [ -f "/workspaces/OpenFlow/pom.xml" ] && [ -d "/workspaces/OpenFlow/src" ]; then
    print_success "Project structure is correct"
else
    print_error "Project structure is invalid"
fi

# Check 9: Source Code
print_check "Application Source"
if [ -f "/workspaces/OpenFlow/src/main/java/org/onosproject/learningbridge/LearningBridgeApp.java" ]; then
    print_success "LearningBridgeApp.java found"
else
    print_error "LearningBridgeApp.java not found"
fi

# Check 10: Build Output
print_check "Built Artifact"
if [ -f "/workspaces/OpenFlow/target/learning-bridge-1.0-SNAPSHOT.jar" ]; then
    JAR_SIZE=$(du -h /workspaces/OpenFlow/target/learning-bridge-1.0-SNAPSHOT.jar | cut -f1)
    print_success "Application JAR exists ($JAR_SIZE)"
else
    print_warning "Application not built yet (run: mvn clean package)"
fi

# Check 11: ARM64 Fix
print_check "ARM64 Compatibility"
if [ -f "/workspaces/OpenFlow/onos-arm64-fix.sh" ]; then
    print_success "ARM64 fix script exists"
else
    print_warning "ARM64 fix script not found"
fi

# Check 12: Mininet
print_check "Mininet"
if command -v mn &> /dev/null; then
    print_success "Mininet is installed"
else
    print_warning "Mininet not found"
fi

# Check 13: Documentation
print_check "Documentation"
if [ -f "/workspaces/OpenFlow/ONOS_DEVELOPMENT_GUIDE.md" ]; then
    print_success "Development guide exists"
else
    print_warning "Development guide not found"
fi

# Check 14: Quick Start Script
print_check "Quick Start Script"
if [ -f "/workspaces/OpenFlow/quick-start.sh" ] && [ -x "/workspaces/OpenFlow/quick-start.sh" ]; then
    print_success "Quick start script is ready"
else
    print_warning "Quick start script not found or not executable"
fi

# Summary
echo ""
echo "=========================================="
echo "Verification Summary"
echo "=========================================="
echo -e "${GREEN}✓ Passed: $SUCCESS${NC}"
echo -e "${YELLOW}⚠ Warnings: $WARNINGS${NC}"
echo -e "${RED}✗ Errors: $ERRORS${NC}"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ Environment is fully configured and ready!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Run ./quick-start.sh to start ONOS and deploy the app"
    echo "  2. Start Mininet: sudo python3 test_topology.py"
    echo "  3. Read ONOS_DEVELOPMENT_GUIDE.md for detailed instructions"
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ Environment is mostly ready with some warnings${NC}"
    echo ""
    echo "Review warnings above and fix if needed."
    echo "You can still proceed with development in most cases."
else
    echo -e "${RED}✗ Environment has errors that need to be fixed${NC}"
    echo ""
    echo "Please address the errors above before proceeding."
fi

echo ""
echo "For help, see:"
echo "  - ONOS_DEVELOPMENT_GUIDE.md"
echo "  - SETUP_COMPLETE.md"
echo "  - README.md"
echo ""

exit $ERRORS
