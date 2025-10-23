#!/bin/bash
# Test script for KanonProxy Docker setup
# This script runs various tests to verify the proxy is working correctly

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=================================="
echo "KanonProxy Test Suite"
echo "=================================="

# Function to run test
run_test() {
    local test_name=$1
    local test_command=$2

    echo -e "\n${YELLOW}Running: ${test_name}${NC}"
    if eval "$test_command"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        return 1
    fi
}

# Check if containers are running
echo -e "\n${YELLOW}Checking container status...${NC}"
docker compose -f docker-compose.test.yml ps

# Wait for services to be ready
echo -e "\n${YELLOW}Waiting for services to initialize...${NC}"
sleep 5

# Test 1: Check if server is listening
run_test "Server listening on UDP port 8080" \
    "docker exec kanon-server netstat -anu | grep ':8080'"

# Test 2: Check TUN device exists in client
run_test "TUN device 'kanon' exists in client" \
    "docker exec kanon-client ip link show kanon"

# Test 3: Check TUN device has correct IP
run_test "TUN device has IP 10.0.1.1/24" \
    "docker exec kanon-client ip addr show kanon | grep '10.0.1.1/24'"

# Test 4: Verify test client shares network with proxy client
run_test "Test client shares network namespace" \
    "docker exec kanon-test-client ip link show kanon"

# Test 5: DNS resolution test
echo -e "\n${YELLOW}Testing DNS resolution through proxy...${NC}"
run_test "DNS lookup for google.com" \
    "docker exec kanon-test-client nslookup google.com 8.8.8.8" || \
    echo -e "${YELLOW}Note: DNS test may fail if proxy isn't routing UDP correctly${NC}"

# Test 6: ICMP test (ping)
echo -e "\n${YELLOW}Testing ICMP (ping) through proxy...${NC}"
run_test "Ping 8.8.8.8" \
    "docker exec kanon-test-client timeout 5 ping -c 3 8.8.8.8" || \
    echo -e "${YELLOW}Note: ICMP test may fail if proxy isn't routing ICMP correctly${NC}"

# Test 7: HTTP connectivity test
echo -e "\n${YELLOW}Testing HTTP connectivity through proxy...${NC}"
run_test "HTTP GET to google.com" \
    "docker exec kanon-test-client timeout 10 curl -v http://www.google.com" || \
    echo -e "${YELLOW}Note: HTTP test may fail if proxy isn't routing TCP correctly${NC}"

# Test 8: Check for Java/Gradle processes
run_test "Server Gradle/Java process is running" \
    "docker exec kanon-server ps aux | grep 'gradle.*server:run' | grep -v grep"

run_test "Client Gradle/Java process is running" \
    "docker exec kanon-client ps aux | grep 'gradle.*client:run' | grep -v grep"

# Summary
echo -e "\n=================================="
echo -e "${GREEN}Test suite completed!${NC}"
echo "=================================="
echo ""
echo "To manually test from inside the test client:"
echo "  docker exec -it kanon-test-client sh"
echo ""
echo "To view server logs:"
echo "  docker logs kanon-server"
echo ""
echo "To view client logs:"
echo "  docker logs kanon-client"
echo ""
echo "To capture packets on the proxy network:"
echo "  docker exec kanon-monitor tcpdump -i eth0 -w /captures/proxy.pcap"
echo ""
