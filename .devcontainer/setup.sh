#!/bin/bash

# Don't exit on error - we want to try installing everything
set +e

echo "=== Installing ONOS Development Environment ==="

# Update package manager
apt-get update
apt-get upgrade -y

# Install Java 11 (LTS) - Required for ONOS 2.7.0
apt-get install -y openjdk-11-jdk

# Install build tools
apt-get install -y \
  maven \
  git \
  curl \
  wget \
  python3 \
  python3-pip \
  python3-dev \
  build-essential \
  sshpass \
  vim \
  net-tools \
  iputils-ping \
  zip \
  unzip

# Note: Mininet and OVS are NOT installed in the dev container.
# Use a separate VM (VirtualBox) with Mininet to test your ONOS apps.
# The dev container exposes ports 6653 (OpenFlow), 8101 (CLI), and 8181 (Web UI)
# so the Mininet VM can connect to ONOS running here.

# Detect architecture and set JAVA_HOME accordingly
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
  JAVA_HOME_PATH="/usr/lib/jvm/java-11-openjdk-arm64"
elif [ "$ARCH" = "x86_64" ]; then
  JAVA_HOME_PATH="/usr/lib/jvm/java-11-openjdk-amd64"
else
  # Fallback: try to find Java 11 automatically
  JAVA_HOME_PATH=$(update-alternatives --query java | grep 'Value:' | grep 'java-11' | awk '{print $2}' | sed 's|/bin/java||')
  if [ -z "$JAVA_HOME_PATH" ]; then
    echo "Warning: Could not auto-detect Java 11 path for architecture $ARCH"
    JAVA_HOME_PATH="/usr/lib/jvm/default-java"
  fi
fi

export JAVA_HOME="$JAVA_HOME_PATH"
export PATH=$JAVA_HOME/bin:$PATH

# Add JAVA_HOME to bashrc and zshrc
echo "export JAVA_HOME=\"$JAVA_HOME_PATH\"" >> /root/.bashrc
echo 'export PATH=$JAVA_HOME/bin:$PATH' >> /root/.bashrc
echo "export JAVA_HOME=\"$JAVA_HOME_PATH\"" >> /root/.zshrc
echo 'export PATH=$JAVA_HOME/bin:$PATH' >> /root/.zshrc

echo "Detected architecture: $ARCH"
echo "Java home set to: $JAVA_HOME_PATH"

# Download and install ONOS
echo "=== Downloading ONOS ==="
ONOS_VERSION="2.7.0"
mkdir -p /opt
cd /opt

if [ ! -d "onos" ]; then
  wget -O onos.tar.gz "https://repo1.maven.org/maven2/org/onosproject/onos-releases/${ONOS_VERSION}/onos-${ONOS_VERSION}.tar.gz"
  tar xzf onos.tar.gz
  mv onos-${ONOS_VERSION} onos
  rm onos.tar.gz
fi

# Set ONOS environment variables
export ONOS_ROOT=/opt/onos
echo 'export ONOS_ROOT=/opt/onos' >> /root/.bashrc
echo 'export ONOS_ROOT=/opt/onos' >> /root/.zshrc

# Configure ONOS CLI to accept ssh-rsa host keys (needed for older Karaf SSH server)
export ONOS_SSH_OPTS="-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPreferredAuthentications=password -oPasswordAuthentication=yes -oNumberOfPasswordPrompts=1"
echo 'export ONOS_SSH_OPTS="-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPreferredAuthentications=password -oPasswordAuthentication=yes -oNumberOfPasswordPrompts=1"' >> /root/.bashrc
echo 'export ONOS_SSH_OPTS="-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPreferredAuthentications=password -oPasswordAuthentication=yes -oNumberOfPasswordPrompts=1"' >> /root/.zshrc

# Install ONOS tools
echo "=== Setting up ONOS tools ==="
cd /opt/onos
# Make sure tools are accessible
chmod +x /opt/onos/bin/*

# Ensure Karaf tolerates older ONOS bundles packaged with legacy ZIP metadata
SETENV_FILE="${ONOS_ROOT}/apache-karaf-4.2.9/bin/setenv"
if [ -f "$SETENV_FILE" ] && ! grep -q "disableZip64ExtraFieldValidation" "$SETENV_FILE"; then
  cat >> "$SETENV_FILE" <<'EOF'
# Work around stricter ZIP extra field validation introduced in newer JDK 11 updates.
# ONOS 2.7.0 bundles include legacy metadata that fails the newer check, which
# prevents Karaf from caching core features. Disabling the validation restores
# compatibility without impacting runtime behaviour.
export EXTRA_JAVA_OPTS="${EXTRA_JAVA_OPTS} -Djdk.util.zip.disableZip64ExtraFieldValidation=true"
EOF
fi

# Add ONOS binaries to PATH
echo 'export PATH=$PATH:/opt/onos/bin' >> /root/.bashrc
echo 'export PATH=$PATH:/opt/onos/bin' >> /root/.zshrc

# Apply ARM64 compatibility fix if needed
if [ "$ARCH" = "aarch64" ]; then
  echo "=== Applying ARM64 Compatibility Fix ==="
  echo "Removing x86_64-only native bundles..."
  
  KARAF_DIR="$ONOS_ROOT/apache-karaf-4.2.9"
  SYSTEM_DIR="$KARAF_DIR/system"
  
  # Remove netty tcnative boringssl (x86_64 only)
  find "$SYSTEM_DIR" -name "*tcnative-boringssl-static*" -type f -delete 2>/dev/null || true
  
  # Remove sigar bundle (x86_64 only)
  find "$SYSTEM_DIR" -name "*osgi.sigar*" -type f -delete 2>/dev/null || true

  # Patch ONOS features to avoid pulling these native bundles from Maven
  FEATURES_XML="$SYSTEM_DIR/org/onosproject/onos-features/2.7.0/onos-features-2.7.0-features.xml"
  if [ -f "$FEATURES_XML" ]; then
    cp "$FEATURES_XML" "${FEATURES_XML}.bak" 2>/dev/null || true
    sed -i '/netty-tcnative-boringssl-static/d' "$FEATURES_XML" || true
    sed -i '/org\.knowhowlab\.osgi\/sigar/d' "$FEATURES_XML" || true
    echo "Patched features.xml to skip native-only bundles on ARM64. Backup saved as onos-features-2.7.0-features.xml.bak"
  else
    echo "Warning: Features XML not found at $FEATURES_XML; skipping feature patch."
  fi
  
  echo "ARM64 compatibility fix applied."
  echo "Note: Removed optional native bundles that are not needed for OpenFlow functionality."
fi

# Create workspace directories for ONOS app development
mkdir -p /workspace/onos-apps
cd /workspace/onos-apps

# Create a sample ONOS app template
echo "=== Creating ONOS app template ==="
if [ ! -d "learning-bridge" ]; then
  # We'll create the Maven project structure manually
  mkdir -p learning-bridge/src/main/java/org/onosproject/learningbridge
  mkdir -p learning-bridge/src/main/resources
  
  # Create a basic pom.xml for the app
  cat > learning-bridge/pom.xml << 'POMEOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.onosproject</groupId>
    <artifactId>learning-bridge</artifactId>
    <version>1.0-SNAPSHOT</version>
    <packaging>bundle</packaging>

    <description>ONOS Learning Bridge Application with Connection Limiting</description>

    <properties>
        <onos.version>2.7.0</onos.version>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.onosproject</groupId>
            <artifactId>onos-api</artifactId>
            <version>${onos.version}</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.onosproject</groupId>
            <artifactId>onlab-osgi</artifactId>
            <version>${onos.version}</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.osgi</groupId>
            <artifactId>org.osgi.core</artifactId>
            <version>6.0.0</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.osgi</groupId>
            <artifactId>org.osgi.service.component.annotations</artifactId>
            <version>1.3.0</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <version>1.7.25</version>
            <scope>provided</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.felix</groupId>
                <artifactId>maven-bundle-plugin</artifactId>
                <version>5.1.1</version>
                <extensions>true</extensions>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.8.1</version>
                <configuration>
                    <source>11</source>
                    <target>11</target>
                </configuration>
            </plugin>
        </plugins>
    </build>

    <repositories>
        <repository>
            <id>central</id>
            <url>https://repo.maven.apache.org/maven2</url>
        </repository>
    </repositories>
</project>
POMEOF
fi

echo ""
echo "=== Setup Complete ==="
echo "ONOS: /opt/onos"
echo "Workspace: /workspace/onos-apps"
echo ""
echo "ONOS Version: ${ONOS_VERSION}"
echo "Java Version: $(java -version 2>&1 | head -n 1)"
echo ""
echo "=== IMPORTANT: Mininet runs in a separate VM ==="
echo "This dev container only runs ONOS for app development."
echo "To test with Mininet:"
echo "  1. Set up a VirtualBox VM with Mininet installed"
echo "  2. Use Bridged or Host-Only network to reach your host"
echo "  3. From the VM, connect Mininet to ONOS at <HOST_IP>:6653"
echo ""
echo "To start ONOS:"
echo "  cd /opt/onos && ./bin/onos-service start"
echo ""

# Create onos-cli wrapper for modern OpenSSH compatibility
cat > /usr/local/bin/onos-cli << 'EOF'
#!/bin/bash
# ONOS CLI wrapper with SSH compatibility for modern OpenSSH (ssh-rsa support)
ssh -o "HostKeyAlgorithms=+ssh-rsa" \
    -o "PubkeyAcceptedAlgorithms=+ssh-rsa" \
    -o "StrictHostKeyChecking=no" \
    -o "UserKnownHostsFile=/dev/null" \
    -p 8101 onos@localhost "$@"
EOF
chmod +x /usr/local/bin/onos-cli

echo "To access ONOS CLI:"
echo "  onos-cli"
echo "  (Password: rocks)"
echo ""
echo "ONOS GUI will be available at: http://localhost:8181/onos/ui"
echo "  Username: onos"
echo "  Password: rocks"

