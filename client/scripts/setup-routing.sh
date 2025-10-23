#!/bin/bash
# Setup routing to send ALL traffic through the TUN device
# except traffic to the proxy server itself (to prevent routing loop)

set -e

echo "Setting up routing for TUN device..."

# Enable IP forwarding (should already be enabled)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Get the default gateway and interface
DEFAULT_GW=$(ip route | grep default | awk '{print $3}')
DEFAULT_IF=$(ip route | grep default | awk '{print $5}')

echo "Default gateway: $DEFAULT_GW via $DEFAULT_IF"

# Get the proxy server hostname and resolve it
PROXY_SERVER_HOST="$1"
if [ -n "$PROXY_SERVER_HOST" ]; then
    echo "Resolving proxy server hostname: $PROXY_SERVER_HOST"

    # Resolve the hostname to IP address
    PROXY_SERVER_IP=$(getent hosts $PROXY_SERVER_HOST | awk '{print $1}' | head -1)

    if [ -n "$PROXY_SERVER_IP" ]; then
        echo "Proxy server IP: $PROXY_SERVER_IP"
        echo "Adding route for proxy server $PROXY_SERVER_IP via $DEFAULT_GW"
        ip route add $PROXY_SERVER_IP/32 via $DEFAULT_GW dev $DEFAULT_IF 2>/dev/null || true
    else
        echo "Warning: Could not resolve proxy server hostname"
    fi
fi

# Route ALL other traffic through the TUN device
# We use two /1 routes which together cover all IP space (0.0.0.0/0)
# This is more specific than the default route, so it takes precedence
echo "Routing ALL traffic through TUN device (except proxy server)..."

ip route add 0.0.0.0/1 dev kanon 2>/dev/null || true
ip route add 128.0.0.0/1 dev kanon 2>/dev/null || true

echo ""
echo "Routing setup complete!"
echo "=================================="
echo "All traffic will route through the proxy EXCEPT:"
echo "  - Traffic to proxy server: $PROXY_SERVER_IP"
echo "  - Traffic to local Docker network: 172.28.0.0/16"
echo "=================================="
echo ""
echo "Current routes:"
ip route show
echo ""
