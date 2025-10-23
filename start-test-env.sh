#!/bin/bash
# Start the KanonProxy test environment

set -e

echo "=================================="
echo "Starting KanonProxy Test Environment"
echo "=================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

# Create captures directory for packet dumps
mkdir -p captures

# Build and start containers
echo ""
echo "Building Docker images (this may take a few minutes on first run)..."
docker compose -f docker-compose.test.yml build

echo ""
echo "Starting containers..."
docker compose -f docker-compose.test.yml up -d

echo ""
echo "Waiting for services to initialize..."
sleep 10

echo ""
echo "=================================="
echo "Environment is ready!"
echo "=================================="
echo ""
echo "Container status:"
docker compose -f docker-compose.test.yml ps
echo ""
echo "Network configuration:"
docker network inspect kanonproxy_proxy-net --format '{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{println}}{{end}}'
echo ""
echo "Next steps:"
echo "  1. Run tests:           ./test-proxy.sh"
echo "  2. View server logs:    docker logs -f kanon-server"
echo "  3. View client logs:    docker logs -f kanon-client"
echo "  4. Enter test client:   docker exec -it kanon-test-client sh"
echo "  5. Stop environment:    ./stop-test-env.sh"
echo ""
