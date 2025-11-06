.PHONY: help build install start stop clean test logs gui cli status

# Default target
help:
	@echo "ONOS Learning Bridge - Development Commands"
	@echo ""
	@echo "Available targets:"
	@echo "  make build      - Build the ONOS application"
	@echo "  make install    - Install the application in ONOS"
	@echo "  make start      - Start ONOS controller"
	@echo "  make stop       - Stop ONOS controller"
	@echo "  make restart    - Restart ONOS controller"
	@echo "  make test       - Start Mininet test topology"
	@echo "  make logs       - Tail ONOS logs (filtered for LearningBridge)"
	@echo "  make logs-all   - Tail all ONOS logs"
	@echo "  make stats      - View TCP connection statistics"
	@echo "  make gui        - Show ONOS GUI URL"
	@echo "  make cli        - Connect to ONOS CLI"
	@echo "  make status     - Show ONOS and application status"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make clean-mn   - Clean Mininet state"
	@echo "  make setup      - Run quick start setup"
	@echo ""

# Build the application
build:
	@echo "Building ONOS application..."
	@cd /workspace/onos-apps/learning-bridge && mvn clean install
	@echo "Build complete!"

# Install the application in ONOS
install:
	@echo "Installing application in ONOS..."
	@/opt/onos/bin/onos localhost app deactivate org.onosproject.learningbridge 2>/dev/null || true
	@/opt/onos/bin/onos localhost app uninstall org.onosproject.learningbridge 2>/dev/null || true
	@sleep 2
	@/opt/onos/bin/onos localhost app install /workspace/onos-apps/learning-bridge/target/learning-bridge-1.0-SNAPSHOT.oar
	@sleep 2
	@/opt/onos/bin/onos localhost app activate org.onosproject.learningbridge
	@echo "Application installed and activated!"

# Start ONOS
start:
	@echo "Starting ONOS controller..."
	@cd /opt/onos && ./bin/onos-service start
	@echo "ONOS started. Waiting for it to be ready..."
	@sleep 30
	@echo "ONOS should be ready now."

# Stop ONOS
stop:
	@echo "Stopping ONOS controller..."
	@cd /opt/onos && ./bin/onos-service stop
	@echo "ONOS stopped."

# Restart ONOS
restart: stop
	@sleep 5
	@$(MAKE) start

# Start Mininet test topology
test:
	@echo "Starting Mininet test topology..."
	@cd /workspace/OpenFlow && python3 test_topology.py

# View application logs
logs:
	@echo "Tailing ONOS logs (filtered for LearningBridge)..."
	@tail -f /opt/onos/apache-karaf-*/data/log/karaf.log | grep --line-buffered LearningBridge

# View all ONOS logs
logs-all:
	@echo "Tailing all ONOS logs..."
	@tail -f /opt/onos/apache-karaf-*/data/log/karaf.log

# View TCP connection statistics
stats:
	@echo "TCP Connection Statistics:"
	@echo "=========================="
	@if [ -f /tmp/tcp_connections.log ]; then \
		cat /tmp/tcp_connections.log; \
	else \
		echo "No statistics file found. Start some TCP connections first."; \
	fi

# Show ONOS GUI URL
gui:
	@echo "ONOS Web GUI:"
	@echo "  URL: http://localhost:8181/onos/ui"
	@echo "  Username: onos"
	@echo "  Password: rocks"

# Connect to ONOS CLI
cli:
	@echo "Connecting to ONOS CLI (username: onos, password: rocks)..."
	@/opt/onos/bin/onos -l onos localhost

# Show status
status:
	@echo "ONOS Status:"
	@echo "============"
	@if pgrep -f "onos" > /dev/null; then \
		echo "✓ ONOS is running"; \
	else \
		echo "✗ ONOS is not running"; \
	fi
	@echo ""
	@echo "Active Applications:"
	@/opt/onos/bin/onos localhost apps -s -a 2>/dev/null | grep -E "(openflow|learningbridge|hostprovider)" || echo "Could not connect to ONOS"
	@echo ""
	@echo "Connected Devices:"
	@/opt/onos/bin/onos localhost devices 2>/dev/null || echo "Could not connect to ONOS"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@cd /workspace/onos-apps/learning-bridge && mvn clean
	@rm -f /tmp/tcp_connections.log
	@echo "Clean complete!"

# Clean Mininet
clean-mn:
	@echo "Cleaning Mininet state..."
	@sudo mn -c
	@echo "Mininet cleaned!"

# Run quick start setup
setup:
	@echo "Running quick start setup..."
	@bash /workspace/OpenFlow/quick-start.sh

# Rebuild and reinstall (convenience target)
rebuild: build install
	@echo "Rebuild and reinstall complete!"
