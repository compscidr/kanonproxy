#!/bin/bash
# Stop the KanonProxy test environment

echo "=================================="
echo "Stopping KanonProxy Test Environment"
echo "=================================="

# Stop and remove containers
docker compose -f docker-compose.test.yml down

echo ""
echo "Test environment stopped."
echo ""
echo "To completely clean up (remove images and volumes):"
echo "  docker compose -f docker-compose.test.yml down --rmi all --volumes"
echo ""
