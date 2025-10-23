# CI Testing for KanonProxy

This document explains how to test KanonProxy in CI environments and the limitations you'll encounter.

## ⚠️ CI Environment Limitations

### What WON'T Work in Most CI Environments:

1. **ICMP (Ping) Tests** ❌
   - Most CI providers block outbound ICMP packets
   - GitHub Actions, GitLab CI, CircleCI all block ICMP
   - Raw socket access often restricted
   - **Workaround:** Test ICMP functionality in unit tests with mocked sockets

2. **TUN/TAP Device Creation** ⚠️
   - Requires privileged containers
   - Needs `/dev/net/tun` access
   - May require kernel modules
   - **Status:** Works on some CI providers (GitLab with Docker-in-Docker), fails on others (GitHub Actions)

3. **Full Network Routing** ❌
   - Cannot route ALL traffic through proxy in CI
   - Network isolation limitations
   - Security restrictions prevent route manipulation

### What WILL Work in Most CI Environments:

1. **Unit Tests** ✅
   - All unit tests should pass
   - Mock-based testing works fine
   - No network privileges needed

2. **TCP Tests** ✅
   - HTTP/HTTPS connections typically allowed
   - Port 80/443 usually open
   - Can test TCP proxy logic

3. **UDP Tests** ✅
   - DNS queries (port 53) usually work
   - UDP proxy logic can be tested
   - Direct packet sending/receiving works

4. **Docker Build & Run** ✅
   - Building Docker images works
   - Running non-privileged containers works
   - Basic container networking works

## 🎯 Recommended CI Strategy

### Approach 1: Unit Tests Only (Most Reliable)

Keep your existing CI setup focused on unit tests:

```yaml
# .github/workflows/test.yml
- name: Run unit tests
  run: ./gradlew :core:test :server:test :client:test
```

**Pros:**
- Always works
- Fast execution
- No privilege requirements

**Cons:**
- Doesn't test actual networking
- Can't verify TUN device interaction

### Approach 2: Limited Docker Tests

Test what's possible without full privileges:

```bash
# Use the CI-friendly compose file
docker compose -f docker-compose.ci.yml up -d

# Run tests that don't require TUN
docker compose -f docker-compose.ci.yml run test-runner
```

**Pros:**
- Tests server/client logic
- Verifies Docker deployment
- Tests UDP/TCP handling

**Cons:**
- Can't test TUN device
- Can't test full routing
- ICMP tests will fail

### Approach 3: Local E2E + CI Unit Tests (Recommended)

**In CI:**
- Run unit tests with JaCoCo coverage
- Run integration tests (no TUN required)
- Build Docker images
- Test basic connectivity

**Locally:**
- Run full Docker environment with `docker-compose.test.yml`
- Test complete routing scenarios
- Verify ICMP, TCP, UDP through proxy
- Manual QA before release

**In CI workflow:**
```yaml
jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - name: Unit tests with coverage
        run: ./gradlew test jacocoTestReport

  docker-build:
    runs-on: ubuntu-latest
    steps:
      - name: Build Docker images
        run: docker compose -f docker-compose.test.yml build

      - name: Test basic connectivity
        run: |
          docker compose -f docker-compose.ci.yml up -d
          docker compose -f docker-compose.ci.yml run test-runner
```

## 🔧 Testing in Different CI Providers

### GitHub Actions
- **TUN/TAP:** ❌ Not supported
- **ICMP:** ❌ Blocked
- **TCP/UDP:** ✅ Works
- **Docker:** ✅ Works
- **Privileged:** ⚠️ Limited

### GitLab CI (with Docker-in-Docker)
- **TUN/TAP:** ✅ Works with `privileged: true`
- **ICMP:** ⚠️ May work depending on runner config
- **TCP/UDP:** ✅ Works
- **Docker:** ✅ Works
- **Privileged:** ✅ Supported

### CircleCI
- **TUN/TAP:** ⚠️ May work with machine executor
- **ICMP:** ❌ Usually blocked
- **TCP/UDP:** ✅ Works
- **Docker:** ✅ Works
- **Privileged:** ⚠️ Limited

## 🧪 Practical CI Testing Examples

### Example 1: Test Server Startup
```yaml
- name: Test server starts
  run: |
    docker compose -f docker-compose.ci.yml up -d proxy-server
    sleep 10
    docker compose -f docker-compose.ci.yml ps | grep healthy
```

### Example 2: Test TCP Connectivity
```yaml
- name: Test TCP through proxy
  run: |
    docker run --network kanonproxy_proxy-net --rm alpine sh -c "
      apk add --no-cache curl &&
      curl --max-time 10 http://example.com
    "
```

### Example 3: Conditional ICMP Test
```yaml
- name: Try ICMP test (may fail)
  continue-on-error: true
  run: |
    docker exec kanon-test-client ping -c 2 8.8.8.8 || \
    echo "ICMP blocked (expected in CI)"
```

## 📊 Coverage Strategy

Since full E2E tests won't work in CI, ensure good coverage through:

1. **Unit Tests** (95%+ coverage target)
   - Test all TCP state machine transitions
   - Test UDP session handling
   - Test ICMP packet processing
   - Mock socket operations

2. **Integration Tests** (without TUN)
   - Test client-server communication
   - Test packet serialization/deserialization
   - Test session management

3. **Manual E2E Tests** (local Docker environment)
   - Full routing tests
   - ICMP/TCP/UDP through proxy
   - Performance testing
   - Run before releases

## 🚀 Using Self-Hosted Runners

If you need full E2E testing in CI, consider self-hosted runners:

### Setup:
1. Use a Linux server with Docker
2. Enable privileged containers
3. Configure firewall to allow ICMP
4. Install GitHub Actions runner

### Benefits:
- Full control over environment
- Can enable all privileges
- ICMP tests work
- TUN/TAP device creation works

### Configuration:
```yaml
jobs:
  e2e-tests:
    runs-on: self-hosted
    steps:
      - name: Run full E2E tests
        run: |
          ./start-test-env.sh
          ./test-proxy.sh
          ./stop-test-env.sh
```

## 📝 Summary

| Test Type | GitHub Actions | Local Docker | Self-Hosted Runner |
|-----------|----------------|--------------|-------------------|
| Unit Tests | ✅ | ✅ | ✅ |
| TCP Tests | ✅ | ✅ | ✅ |
| UDP Tests | ✅ | ✅ | ✅ |
| ICMP Tests | ❌ | ✅ | ✅ |
| TUN Device | ❌ | ✅ | ✅ |
| Full Routing | ❌ | ✅ | ✅ |

**Recommendation:** Use GitHub Actions for unit tests and basic integration tests. Run full E2E tests locally using `docker-compose.test.yml` before merging/releasing.
