#!/usr/bin/env bash
# Kill kanonproxy processes, drop any routes pointed at the kanon device,
# and delete the kanon TUN interface. Idempotent: safe to run when nothing
# is up.

# Kill the JVM processes that hold the TUN fd. Use SIGTERM first so they
# release the fd cleanly, then SIGKILL anything that didn't exit.
for pat in "ProxyServer" "LinuxProxyClient" "GradleWorkerMain" "java -jar" "java -Djava.library.path"; do
    sudo pkill -f "$pat" 2>/dev/null || true
done
# Give the JVMs a moment to actually release the TUN fd. Without this,
# `ip tuntap del` can race the kernel cleanup and leave the interface
# stuck in a DOWN state.
sleep 1
for pat in "ProxyServer" "LinuxProxyClient" "GradleWorkerMain"; do
    sudo pkill -9 -f "$pat" 2>/dev/null || true
done

if ip link show kanon &>/dev/null; then
    # drop any host routes still pointed at kanon (added by older demo.sh
    # versions; the current demo doesn't add routes)
    ip route show | awk '/dev kanon/ {print $1}' | while read -r net; do
        sudo ip route del "$net" dev kanon 2>/dev/null || true
    done

    sudo ip link set dev kanon down 2>/dev/null || true

    # Retry the delete a few times — even after pkill -9, the kernel may
    # need a tick before all references to the tun fd drop.
    for _ in 1 2 3 4 5; do
        if sudo ip tuntap del dev kanon mode tun 2>/dev/null; then
            break
        fi
        sleep 1
    done

    if ip link show kanon &>/dev/null; then
        echo "warning: kanon interface is still present; something may still hold its fd" >&2
        echo "         try:  sudo lsof /dev/net/tun" >&2
    else
        echo "kanon interface removed"
    fi
else
    echo "kanon interface not present, nothing to remove"
fi