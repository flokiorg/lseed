package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/flokiorg/flnd/lnrpc"
	"github.com/flokiorg/flnd/macaroons"
	"github.com/flokiorg/go-flokicoin/chainutil"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	macaroon "gopkg.in/macaroon.v2"
)

var (
	configFile = flag.String("config", "flnd-diag.conf", "Path to configuration file")
	lndHomeDir = chainutil.AppDataDir("lnd", false)
)

// DiagConfig defines the configuration for the diagnostic tool
type DiagConfig struct {
	Host                 string `toml:"host"`
	TLSPath              string `toml:"tls_path"`
	MacaroonPath         string `toml:"macaroon_path"`
	TestReachability     bool   `toml:"test_reachability"`
	MaxReachabilityTests int    `toml:"max_reachability_tests"`
	Debug                bool   `toml:"debug"`
}

// loadConfig reads and parses the configuration from the specified file path
func loadConfig(path string) (*DiagConfig, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", path)
	}

	cfg := &DiagConfig{
		Host:                 "localhost:10005",
		TLSPath:              "~/.flnd/tls.cert",
		MacaroonPath:         "~/.flnd/data/chain/flokicoin/main/admin.macaroon",
		TestReachability:     false,
		MaxReachabilityTests: 5,
		Debug:                false,
	}

	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %v", err)
	}

	return cfg, nil
}

func cleanAndExpandPath(path string) string {
	if strings.HasPrefix(path, "~") {
		homeDir := filepath.Dir(lndHomeDir)
		path = strings.Replace(path, "~", homeDir, 1)
	}
	return filepath.Clean(os.ExpandEnv(path))
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}

	privateBlocks := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
	}

	for _, cidr := range privateBlocks {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.DateTime}).With().Timestamp().Logger()
	flag.Parse()

	// Load configuration
	cfg, err := loadConfig(*configFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	// Set log level
	if cfg.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Info().Msg("Debug logging enabled")
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	log.Info().Str("host", cfg.Host).Msg("Connecting to FLND")

	// Expand paths
	tlsCertPath := cleanAndExpandPath(cfg.TLSPath)
	macPath := cleanAndExpandPath(cfg.MacaroonPath)

	log.Info().Str("tls_path", tlsCertPath).Str("macaroon_path", macPath).Msg("Using credentials")

	// Load TLS credentials with InsecureSkipVerify for remote connections
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	creds := credentials.NewTLS(tlsConfig)

	// Load macaroon
	macBytes, err := ioutil.ReadFile(macPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to read macaroon")
	}

	mac := &macaroon.Macaroon{}
	if err = mac.UnmarshalBinary(macBytes); err != nil {
		log.Fatal().Err(err).Msg("Failed to unmarshal macaroon")
	}

	macCred, err := macaroons.NewMacaroonCredential(mac)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create macaroon credential")
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithPerRPCCredentials(macCred),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1 * 1024 * 1024 * 50)),
	}

	conn, err := grpc.Dial(cfg.Host, opts...)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to dial FLND")
	}
	defer conn.Close()

	lnd := lnrpc.NewLightningClient(conn)

	// Test connection
	info, err := lnd.GetInfo(context.Background(), &lnrpc.GetInfoRequest{})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get info from FLND")
	}

	log.Info().
		Str("identity_pubkey", info.IdentityPubkey).
		Str("alias", info.Alias).
		Int("num_peers", int(info.NumPeers)).
		Int("num_active_channels", int(info.NumActiveChannels)).
		Msg("Connected to FLND")

	// Get graph
	log.Info().Msg("Fetching network graph...")
	graph, err := lnd.DescribeGraph(context.Background(), &lnrpc.ChannelGraphRequest{})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get graph")
	}

	log.Info().Int("total_nodes", len(graph.Nodes)).Msg("Graph fetched")

	// Analyze nodes
	var (
		nodesWithAddrs     = 0
		nodesWithPublicIP  = 0
		nodesWithPrivateIP = 0
		ipv4Nodes          = 0
		ipv6Nodes          = 0
		defaultPortNodes   = 0
	)

	const defaultPort = 5521

	for i, node := range graph.Nodes {
		if len(node.Addresses) == 0 {
			log.Debug().
				Int("index", i).
				Str("pubkey", node.PubKey[:16]+"...").
				Str("alias", node.Alias).
				Msg("Node has NO addresses")
			continue
		}

		nodesWithAddrs++
		hasPublicIP := false
		hasPrivateIP := false

		log.Debug().
			Int("index", i).
			Str("pubkey", node.PubKey[:16]+"...").
			Str("alias", node.Alias).
			Int("num_addrs", len(node.Addresses)).
			Msg("Node")

		for _, netAddr := range node.Addresses {
			var addr string
			_, _, err := net.SplitHostPort(netAddr.Addr)
			if err != nil {
				addr = net.JoinHostPort(netAddr.Addr, strconv.Itoa(defaultPort))
			} else {
				addr = netAddr.Addr
			}

			parsedAddr, err := net.ResolveTCPAddr(netAddr.Network, addr)
			if err != nil {
				log.Debug().Err(err).Str("addr", netAddr.Addr).Msg("Failed to parse address")
				continue
			}

			isPrivate := isPrivateIP(parsedAddr.IP)

			log.Debug().
				Str("addr", parsedAddr.String()).
				Bool("is_private", isPrivate).
				Bool("is_ipv4", parsedAddr.IP.To4() != nil).
				Int("port", parsedAddr.Port).
				Msg("  Address")

			if isPrivate {
				hasPrivateIP = true
			} else {
				hasPublicIP = true
			}

			if parsedAddr.IP.To4() != nil {
				ipv4Nodes++
			} else {
				ipv6Nodes++
			}

			if parsedAddr.Port == defaultPort {
				defaultPortNodes++
			}
		}

		if hasPublicIP {
			nodesWithPublicIP++
		}
		if hasPrivateIP {
			nodesWithPrivateIP++
		}
	}

	log.Info().Msg("=== Summary ===")
	log.Info().Int("total_nodes", len(graph.Nodes)).Msg("Total nodes in graph")
	log.Info().Int("nodes_with_addresses", nodesWithAddrs).Msg("Nodes with addresses")
	log.Info().Int("nodes_with_public_ip", nodesWithPublicIP).Msg("Nodes with public IP")
	log.Info().Int("nodes_with_private_ip", nodesWithPrivateIP).Msg("Nodes with private IP only")
	log.Info().Int("ipv4_addresses", ipv4Nodes).Msg("IPv4 addresses")
	log.Info().Int("ipv6_addresses", ipv6Nodes).Msg("IPv6 addresses")
	log.Info().Int("default_port_5521", defaultPortNodes).Msg("Addresses on port 5521")

	// Test reachability if requested
	if cfg.TestReachability && nodesWithPublicIP > 0 {
		log.Info().Int("max_tests", cfg.MaxReachabilityTests).Msg("Testing reachability of nodes with public IPs...")
		tested := 0
		reachable := 0

		for _, node := range graph.Nodes {
			if tested >= cfg.MaxReachabilityTests {
				break
			}
			if len(node.Addresses) == 0 {
				continue
			}

			for _, netAddr := range node.Addresses {
				var addr string
				_, _, err := net.SplitHostPort(netAddr.Addr)
				if err != nil {
					addr = net.JoinHostPort(netAddr.Addr, strconv.Itoa(defaultPort))
				} else {
					addr = netAddr.Addr
				}

				parsedAddr, err := net.ResolveTCPAddr(netAddr.Network, addr)
				if err != nil || isPrivateIP(parsedAddr.IP) {
					continue
				}

				tested++
				log.Info().Str("addr", parsedAddr.String()).Msg("Testing reachability")

				tcpConn, err := net.DialTimeout("tcp", parsedAddr.String(), 5*time.Second)
				if err != nil {
					log.Warn().Err(err).Str("addr", parsedAddr.String()).Msg("Unreachable")
				} else {
					log.Info().Str("addr", parsedAddr.String()).Msg("✓ Reachable!")
					tcpConn.Close()
					reachable++
				}
				break
			}
		}

		log.Info().Int("tested", tested).Int("reachable", reachable).Msg("Reachability test complete")
	}
}
