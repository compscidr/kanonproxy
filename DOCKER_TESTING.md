# KanonProxy Docker Testing Environment

This document describes how to use the Docker-based testing environment for KanonProxy. This setup provides complete network isolation from your host machine, allowing you to test the proxy without affecting your real network traffic.

## Architecture

The testing environment consists of four containers:

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Network                        │
│                   172.28.0.0/16                         │
│                                                         │
│  ┌──────────────┐    UDP     ┌──────────────┐         │
│  │ Proxy Client │ ◄────────► │ Proxy Server │         │
│  │  172.28.0.11 │   :8080    │  172.28.0.10 │         │
│  │              │            │              │         │
│  │ TUN: kanon   │            │              │         │
│  │ 10.0.1.1/24  │            │              │         │
│  └──────┬───────┘            └──────────────┘         │
│         │                                               │
│         │ (shares network)                             │
│         │                                               │
│  ┌──────▼───────┐            ┌──────────────┐         │
│  │ Test Client  │            │   Monitor    │         │
│  │ (Alpine)     │            │ (netshoot)   │         │
│  │              │            │ 172.28.0.100 │         │
│  └──────────────┘            └──────────────┘         │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Container Roles

1. **proxy-server** (172.28.0.10)
   - Runs the KanonProxy server
   - Listens on UDP port 8080
   - Receives packets from clients and forwards them to destinations

2. **proxy-client** (172.28.0.11)
   - Runs the KanonProxy client
   - Creates TUN device `kanon` (10.0.1.1/24)
   - Intercepts packets and sends them to the server

3. **test-client** (shares network with proxy-client)
   - Alpine Linux container for running tests
   - All traffic automatically routes through the TUN device
   - Includes tools: curl, wget, ping, dig, tcpdump

4. **monitor** (172.28.0.100)
   - Network debugging container with netshoot
   - Can capture packets on the proxy network
   - Useful for troubleshooting

## Prerequisites

- Docker (version 20.10+)
- Docker Compose (version 2.0+)
- At least 2GB free disk space (for building images)
- Root/sudo access (required for TUN device creation in containers)

## Quick Start

### 1. Start the environment

```bash
./start-test-env.sh
```

This will:
- Build the Docker images (first run takes ~5 minutes)
- Start all containers
- Create the TUN device in the client
- Show container status and IP addresses

### 2. Run automated tests

```bash
./test-proxy.sh
```

This runs a series of tests to verify:
- Server is listening on UDP port 8080
- TUN device is created correctly
- DNS resolution works through proxy
- ICMP (ping) works through proxy
- HTTP requests work through proxy
- Java processes are running

### 3. Stop the environment

```bash
./stop-test-env.sh
```

## Manual Testing

### Enter the test client

```bash
docker exec -it kanon-test-client sh
```

Once inside, you can run commands that will route through the proxy:

```bash
# DNS lookup
nslookup google.com

# Ping test
ping -c 3 8.8.8.8

# HTTP request
curl -v http://www.google.com

# HTTPS request
curl -v https://www.google.com

# Download a file
wget http://example.com/file.txt
```

### View logs

```bash
# Server logs (see packets being received/sent)
docker logs -f kanon-server

# Client logs (see TUN device activity)
docker logs -f kanon-client

# Follow logs in real-time
docker compose -f docker-compose.test.yml logs -f
```

### Inspect network configuration

```bash
# Check client TUN device
docker exec kanon-client ip addr show kanon

# Check routing table in client
docker exec kanon-client ip route

# Check server network
docker exec kanon-server ip addr

# Check test client can see TUN device
docker exec kanon-test-client ip link show kanon
```

## Packet Capture

### Capture on the proxy network

```bash
# Start capture in the monitor container
docker exec kanon-monitor tcpdump -i eth0 -w /captures/proxy.pcap

# Stop with Ctrl+C, then analyze with Wireshark
wireshark captures/proxy.pcap
```

### Capture on the TUN device

```bash
# Capture TUN traffic inside the client
docker exec kanon-client tcpdump -i kanon -w /tmp/tun.pcap

# Copy to host for analysis
docker cp kanon-client:/tmp/tun.pcap ./captures/tun.pcap
```

## Troubleshooting

### Containers won't start

```bash
# Check Docker is running
docker info

# Check for port conflicts
sudo netstat -anu | grep 8080

# View container logs
docker compose -f docker-compose.test.yml logs
```

### TUN device creation fails

The client container needs privileged mode and access to `/dev/net/tun`. This is configured in docker-compose.test.yml:

```yaml
cap_add:
  - NET_ADMIN
devices:
  - /dev/net/tun
privileged: true
```

### Client can't connect to server

```bash
# Verify server is listening
docker exec kanon-server netstat -anu | grep 8080

# Check network connectivity
docker exec kanon-client ping -c 3 proxy-server

# Check DNS resolution
docker exec kanon-client nslookup proxy-server
```

### Tests fail

Individual tests may fail if:
- Services haven't fully initialized (wait 10-15 seconds)
- Proxy doesn't support the protocol yet
- Network connectivity issues

Check logs for details:
```bash
docker logs kanon-server
docker logs kanon-client
```

## Advanced Usage

### Custom server configuration

Edit `docker-compose.test.yml` to change server settings:

```yaml
proxy-server:
  command: ./gradlew :server:run --no-daemon --console=plain --args='9090'  # Custom port
```

Note: The server uses Gradle's run task, which automatically handles all dependencies and classpath.

### Add more test clients

Add to `docker-compose.test.yml`:

```yaml
test-client-2:
  image: ubuntu:22.04
  network_mode: "service:proxy-client"
  command: sleep infinity
```

### Test with different network topologies

Modify the `proxy-net` configuration:

```yaml
networks:
  proxy-net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.10.0.0/16
```

### Enable Java debugging

Add to container environment:

```yaml
environment:
  - JAVA_OPTS=-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005
ports:
  - "5005:5005"
```

## Integration with CI/CD

This setup can be used in GitHub Actions or other CI systems:

```yaml
# .github/workflows/e2e-tests.yml
- name: Run E2E tests
  run: |
    ./start-test-env.sh
    ./test-proxy.sh
    ./stop-test-env.sh
```

Note: CI runners need Docker and may require privileged mode.

## Cleaning Up

### Remove all containers and networks

```bash
docker compose -f docker-compose.test.yml down
```

### Remove images and rebuild from scratch

```bash
docker compose -f docker-compose.test.yml down --rmi all
./start-test-env.sh
```

### Remove packet captures

```bash
rm -rf captures/
```

## Security Notes

- This environment uses `privileged: true` for TUN device access
- Only use for testing, not production
- Containers have CAP_NET_ADMIN capability
- Test traffic is isolated from host network
- Capture files may contain sensitive data

## Next Steps

1. Run the automated tests to verify basic functionality
2. Manually test specific protocols (TCP, UDP, ICMP)
3. Use packet captures to verify correct packet routing
4. Add custom test cases for your use cases
5. Integrate into your CI/CD pipeline

## Support

For issues specific to the Docker setup:
- Check container logs: `docker compose -f docker-compose.test.yml logs`
- Verify Docker version: `docker --version`
- Check system resources: `docker system df`

For KanonProxy issues:
- See main README.md
- Check GitHub issues: https://github.com/compscidr/kanonproxy/issues
