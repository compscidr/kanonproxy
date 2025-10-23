# Multi-stage build for KanonProxy
FROM gradle:8.11-jdk21 AS builder

WORKDIR /app

# Copy gradle files first for better layer caching
COPY gradle gradle/
COPY gradlew .
COPY settings.gradle.kts .
COPY gradle.properties .
COPY build.gradle.kts .

# Copy version catalog
COPY gradle/libs.versions.toml gradle/

# Copy all module build files
COPY core/build.gradle.kts core/
COPY server/build.gradle.kts server/
COPY client/build.gradle.kts client/
COPY android/build.gradle.kts android/

# Download dependencies
RUN ./gradlew dependencies --no-daemon || true

# Copy source code
COPY core/src core/src
COPY server/src server/src
COPY client/src client/src

# Build the project (skip Android module to avoid SDK requirements)
RUN ./gradlew :core:build :server:build :client:build -x test --no-daemon

# Create runtime image - use gradle image to keep gradle for easy execution
FROM gradle:8.11-jdk21

# Install required packages
RUN apt-get update && apt-get install -y \
    iproute2 \
    iptables \
    iputils-ping \
    curl \
    dnsutils \
    tcpdump \
    net-tools \
    netcat-openbsd \
    vim \
    sudo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the entire built project to keep gradle structure intact
COPY --from=builder /app ./

# Copy gradle cache to avoid re-downloading dependencies
COPY --from=builder /root/.gradle /root/.gradle

# Copy scripts (they're already in /app from the builder, but copy again to be explicit)
COPY client/scripts/tuntap.sh /app/
COPY client/scripts/cleanup.sh /app/
COPY client/scripts/setup-routing.sh /app/

# Make scripts executable
RUN chmod +x /app/*.sh

# Expose UDP port for proxy communication
EXPOSE 8080/udp

# Default command runs the server
CMD ["./gradlew", ":server:run", "--no-daemon", "--console=plain"]
