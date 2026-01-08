package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	macaroon "gopkg.in/macaroon.v2"

	"github.com/flokiorg/flnd/lnrpc"
	"github.com/flokiorg/flnd/macaroons"
	"github.com/flokiorg/go-flokicoin/chainutil"
	"github.com/flokiorg/lseed/seed"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	configFile = flag.String("config", "lseed.conf", "Path to configuration file")
)

var (
	lndHomeDir = chainutil.AppDataDir("lnd", false)

	maxMsgRecvSize = grpc.MaxCallRecvMsgSize(1 * 1024 * 1024 * 50)
)

// cleanAndExpandPath expands environment variables and leading ~ in the passed
// path, cleans the result, and returns it.
// This function is taken from https://github.com/btcsuite/btcd
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		homeDir := filepath.Dir(lndHomeDir)
		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

// initLightningClient attempts to initialize, and connect out to the backing
// lnd node as specified by the lndNode ccommand line flag.
func initLightningClient(nodeHost, tlsCertPath, macPath string) (lnrpc.LightningClient, error) {

	// First attempt to establish a connection to lnd's RPC sever.
	tlsCertPath = cleanAndExpandPath(tlsCertPath)
	creds, err := credentials.NewClientTLSFromFile(tlsCertPath, "")
	if err != nil {
		return nil, fmt.Errorf("unable to read cert file: %v", err)
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	// Load the specified macaroon file.
	macPath = cleanAndExpandPath(macPath)
	macBytes, err := ioutil.ReadFile(macPath)
	if err != nil {
		return nil, err
	}
	mac := &macaroon.Macaroon{}
	if err = mac.UnmarshalBinary(macBytes); err != nil {
		return nil, err
	}

	// Now we append the macaroon credentials to the dial options.
	macCred, err := macaroons.NewMacaroonCredential(mac)
	if err != nil {
		return nil, fmt.Errorf("unable to create macaroon credential: %v", err)
	}
	opts = append(
		opts,
		grpc.WithPerRPCCredentials(macCred),
	)
	opts = append(opts, grpc.WithDefaultCallOptions(maxMsgRecvSize))

	conn, err := grpc.Dial(nodeHost, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to dial to lnd's gRPC server: %v",
			err)
	}

	// If we're able to connect out to the lnd node, then we can start up
	// our RPC connection properly.
	lnd := lnrpc.NewLightningClient(conn)

	// Before we proceed, make sure that we can query the target node.
	_, err = lnd.GetInfo(
		context.Background(), &lnrpc.GetInfoRequest{},
	)
	if err != nil {
		return nil, err
	}

	return lnd, nil
}

// poller regularly polls the backing lnd node and updates the local network
// view.
func poller(lnd lnrpc.LightningClient, nview *seed.NetworkView, pollInterval int) {
	scrapeGraph := func() {
		graphReq := &lnrpc.ChannelGraphRequest{}
		graph, err := lnd.DescribeGraph(
			context.Background(), graphReq,
		)
		if err != nil {
			return
		}

		log.Debug().Int("count", len(graph.Nodes)).Msg("Got nodes from lnd")
		for _, node := range graph.Nodes {
			if len(node.Addresses) == 0 {
				continue
			}

			if _, err := nview.AddNode(node); err != nil {
				log.Debug().Err(err).Msg("Unable to add node")
			} else {
				log.Debug().Interface("addresses", node.Addresses).Msg("Adding node")
			}
		}
	}

	scrapeGraph()

	ticker := time.NewTicker(time.Second * time.Duration(pollInterval))
	for range ticker.C {
		scrapeGraph()
	}
}

// Parse flags and configure subsystems according to flags
func configure(cfg *Config) {
	if cfg.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Info().Msg("Logging on level Debug")
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		log.Info().Msg("Logging on level Info")
	}
}

// initChain initializes a connection to a chain backend and returns a ChainView.
func initChain(name string, cfg ChainConfig, pollInterval int) (*seed.ChainView, error) {
	if cfg.Host == "" || cfg.TLSPath == "" || cfg.MacaroonPath == "" {
		return nil, fmt.Errorf("missing connection details for chain: %s", name)
	}

	log.Info().Str("chain", name).Msg("Creating chain view")

	lndNode, err := initLightningClient(
		cfg.Host, cfg.TLSPath, cfg.MacaroonPath,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to %s lnd: %v", name, err)
	}

	nView := seed.NewNetworkView(name)
	go poller(lndNode, nView, pollInterval)

	log.Info().Str("chain", name).Msg("Chain view active")

	return &seed.ChainView{
		NetView: nView,
		Node:    lndNode,
	}, nil
}

// Main entry point for the lightning-seed
func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.DateTime}).With().Timestamp().Logger()
	flag.Parse()

	cfg, err := loadConfig(*configFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	configure(cfg)

	go func() {
		if err := http.ListenAndServe(":9091", nil); err != nil {
			log.Error().Err(err).Msg("pprof server failed")
		}
	}()

	netViewMap := make(map[string]*seed.ChainView)

	// Initialize Flokicoin (Mandatory)
	if cfg.Flokicoin.Host == "" {
		log.Fatal().Msg("Flokicoin configuration is missing")
	}
	// Flokicoin usually maps to the root domain, so empty prefix + dot = ""
	// If the user provided a prefix, we use it.
	// Assuming Standard Behavior: Root domain queries go to Flokicoin.
	// If prefix is empty (default), key is "".
	flokiPrefix := ""
	if cfg.Flokicoin.PrefixRootDomain != "" {
		flokiPrefix = cfg.Flokicoin.PrefixRootDomain + "."
	}

	flokiView, err := initChain("flokicoin", cfg.Flokicoin, cfg.PollInterval)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize Flokicoin chain")
	}
	netViewMap[flokiPrefix] = flokiView

	// Initialize AltChains
	for _, altCfg := range cfg.AltChains {
		// Ensure prefix is set for altchains to avoid collision with root
		prefix := altCfg.PrefixRootDomain
		if prefix == "" {
			log.Fatal().Str("chain", altCfg.Name).Msg("AltChain must have a prefix_root_domain")
		}

		altView, err := initChain(altCfg.Name, altCfg, cfg.PollInterval)
		if err != nil {
			log.Fatal().Err(err).Str("chain", altCfg.Name).Msg("Failed to initialize chain")
		}
		netViewMap[prefix+"."] = altView
	}

	if len(netViewMap) == 0 {
		log.Fatal().Msg("Must specify at least one node type")
	}

	rootIP := net.ParseIP(cfg.AuthoritativeIP)
	dnsServer := seed.NewDnsServer(
		netViewMap, cfg.ListenAddrUDP, cfg.ListenAddrTCP, cfg.RootDomain, rootIP,
	)

	dnsServer.Serve()
}
