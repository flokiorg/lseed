# FLND Diagnostic Tool

A diagnostic tool to analyze the FLND network graph and test node reachability.

## Configuration

Create a `flnd-diag.conf` file with your FLND connection details:

```toml
# FLND Diagnostic Tool Configuration

# Connection settings
host = "localhost:10005"
macaroon_path = "~/.flnd/data/chain/flokicoin/main/admin.macaroon"

# Test settings
test_reachability = false  # Set to true to test TCP connectivity to nodes
max_reachability_tests = 5  # Number of nodes to test for reachability
debug = false  # Enable debug logging for detailed node information
```

**Note:** TLS certificate verification is **disabled** in this diagnostic tool to allow connections to remote FLND instances where the certificate was generated for localhost/internal IPs. This is acceptable for diagnostic purposes but should not be used in production code.

## Usage

### Basic Usage

Run with default config file (`flnd-diag.conf` in current directory):
```bash
./flnd-diag
```

Or use `go run`:
```bash
go run ./cmd/flnd-diag
```

### Custom Config File

Specify a different config file:
```bash
./flnd-diag -config /path/to/custom-config.conf
```

### Remote FLND Instance

To connect to a remote FLND instance, update your config file:

```toml
host = "remote-server.example.com:10005"
macaroon_path = "/path/to/remote-admin.macaroon"
```

## Output

The tool provides:

1. **Connection Info**: FLND identity, alias, peers, and channels
2. **Graph Statistics**:
   - Total nodes in graph
   - Nodes with addresses
   - Nodes with public vs private IPs
   - IPv4 vs IPv6 breakdown
   - Port distribution (default: 5521 for Flokicoin)

3. **Reachability Tests** (if enabled):
   - Tests TCP connectivity to nodes with public IPs
   - Shows which nodes are actually reachable from your network

## Example Output

```
2026-01-08 19:00:00 INF Connecting to FLND host=localhost:10005
2026-01-08 19:00:00 INF Using credentials macaroon_path=/home/user/.flnd/data/chain/flokicoin/main/admin.macaroon
2026-01-08 19:00:00 INF Connected to FLND alias=MyNode identity_pubkey=03abc... num_active_channels=5 num_peers=10
2026-01-08 19:00:00 INF Fetching network graph...
2026-01-08 19:00:01 INF Graph fetched total_nodes=1234
2026-01-08 19:00:01 INF === Summary ===
2026-01-08 19:00:01 INF Total nodes in graph total_nodes=1234
2026-01-08 19:00:01 INF Nodes with addresses nodes_with_addresses=1100
2026-01-08 19:00:01 INF Nodes with public IP nodes_with_public_ip=950
2026-01-08 19:00:01 INF Nodes with private IP only nodes_with_private_ip=150
2026-01-08 19:00:01 INF IPv4 addresses ipv4_addresses=800
2026-01-08 19:00:01 INF IPv6 addresses ipv6_addresses=150
2026-01-08 19:00:01 INF Addresses on port 5521 default_port_5521=900
```