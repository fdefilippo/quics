package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/francesco/quics/internal/server"
	"github.com/quic-go/quic-go"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"log/syslog"
)

// Version information set during build
var (
	Version   string
	BuildDate string
	GitCommit string
)

type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	ListenPort int    `yaml:"listen_port"`
	TLS        struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	} `yaml:"tls"`
	Auth struct {
		ClientCAFile string `yaml:"client_ca_file"`
	} `yaml:"auth"`
	Storage struct {
		RootDir string `yaml:"root_dir"`
	} `yaml:"storage"`
	QUIC struct {
		MaxIdleTimeoutSeconds  int `yaml:"max_idle_timeout_seconds"`
		KeepAlivePeriodSeconds int `yaml:"keep_alive_period_seconds"`
	} `yaml:"quic"`
	Shell struct {
		Enabled          bool     `yaml:"enabled"`
		AllowedCommands  []string `yaml:"allowed_commands"`
		MaxExecutionTime int      `yaml:"max_execution_time_seconds"`
		AllowedEnvVars   []string `yaml:"allowed_env_vars"`
	} `yaml:"shell"`
	Log struct {
		Type       string `yaml:"type"`        // stderr, file, syslog
		FilePath   string `yaml:"file_path"`   // required if type=file
		SyslogHost string `yaml:"syslog_host"` // optional, default localhost
		SyslogPort int    `yaml:"syslog_port"` // optional, default 514
	} `yaml:"log"`
}

var configPath string
var versionFlag bool

var rootCmd = &cobra.Command{
	Use:   "quicsd",
	Short: "QUIC server for file transfer and remote command execution",
	Long: `QUICS server provides secure file transfer and remote command execution
over QUIC protocol with mutual TLS authentication.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if versionFlag {
			fmt.Printf("quicsd version %s (built on %s, commit %s)\n", Version, BuildDate, GitCommit)
			return nil
		}
		config, err := loadConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		return startServer(config)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "./config/server.yaml", "Path to configuration file")
	rootCmd.Flags().BoolVar(&versionFlag, "version", false, "Print version information and exit")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func setupLogging(logConfig *struct {
	Type       string `yaml:"type"`
	FilePath   string `yaml:"file_path"`
	SyslogHost string `yaml:"syslog_host"`
	SyslogPort int    `yaml:"syslog_port"`
}) error {
	switch logConfig.Type {
	case "file":
		if logConfig.FilePath == "" {
			return fmt.Errorf("file_path is required when log type is file")
		}
		file, err := os.OpenFile(logConfig.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		log.SetOutput(file)
		log.Printf("Logging to file: %s", logConfig.FilePath)
		
	case "syslog":
		// Only local syslog is supported (via Unix socket)
		if logConfig.SyslogHost != "" {
			return fmt.Errorf("remote syslog not supported yet, use local syslog (leave syslog_host empty)")
		}
		writer, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "quicsd")
		if err != nil {
			return fmt.Errorf("failed to connect to local syslog: %w", err)
		}
		log.SetOutput(writer)
		log.Print("Logging to local syslog")
		
	case "stderr", "":
		// Default to stderr
		log.SetOutput(os.Stderr)
		
	default:
		return fmt.Errorf("unknown log type: %s", logConfig.Type)
	}
	return nil
}

func startServer(config *Config) error {
	// Setup logging based on configuration
	if err := setupLogging(&config.Log); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}
	
	cert, err := tls.LoadX509KeyPair(config.TLS.CertFile, config.TLS.KeyFile)
	if err != nil {
		return fmt.Errorf("loading TLS cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quic-file-transfer"},
		// Prefer post-quantum hybrid curve (X25519MLKEM768), then X25519, then P-256
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
		// Strong TLS 1.3 cipher suites
		CipherSuites: []uint16{tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_AES_128_GCM_SHA256},
		// QUIC requires TLS 1.3
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}

	if config.Auth.ClientCAFile != "" {
		caCert, err := os.ReadFile(config.Auth.ClientCAFile)
		if err != nil {
			return fmt.Errorf("reading CA cert: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		tlsConfig.ClientAuth = tls.RequireAnyClientCert
	}

	addr := fmt.Sprintf("%s:%d", config.ListenAddr, config.ListenPort)

	// Default values
	const defaultIdleTimeout = 120 * time.Second
	const defaultKeepAlive = 15 * time.Second

	// Parse QUIC configuration
	idleTimeout := defaultIdleTimeout
	if config.QUIC.MaxIdleTimeoutSeconds > 0 {
		idleTimeout = time.Duration(config.QUIC.MaxIdleTimeoutSeconds) * time.Second
	}

	keepAlive := defaultKeepAlive
	if config.QUIC.KeepAlivePeriodSeconds == -1 {
		// -1 means disable keepalive
		keepAlive = 0
	} else if config.QUIC.KeepAlivePeriodSeconds > 0 {
		keepAlive = time.Duration(config.QUIC.KeepAlivePeriodSeconds) * time.Second
	}

	// Adjust idle timeout if max execution time is longer
	executionTimeout := time.Duration(config.Shell.MaxExecutionTime) * time.Second
	if executionTimeout > idleTimeout {
		log.Printf("Adjusting QUIC idle timeout from %v to %v to match max execution time",
			idleTimeout, executionTimeout)
		idleTimeout = executionTimeout
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:  idleTimeout,
		KeepAlivePeriod: keepAlive,
	}

	log.Printf("QUIC config: idle_timeout=%v, keepalive=%v",
		idleTimeout, keepAlive)
	listener, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()

	serverConfig := &server.Config{
		StorageRoot: config.Storage.RootDir,
		ShellConfig: &server.ShellConfig{
			Enabled:          config.Shell.Enabled,
			AllowedCommands:  config.Shell.AllowedCommands,
			MaxExecutionTime: config.Shell.MaxExecutionTime,
			AllowedEnvVars:   config.Shell.AllowedEnvVars,
		},
	}
	srv := server.NewServer(serverConfig)

	log.Printf("Server listening on %s", addr)
	log.Print("Waiting for connections...")

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		log.Printf("Accepted connection from %v", conn.RemoteAddr())

		go handleConnection(conn, srv)
	}
}

// extractUserID extracts the user identifier from a client certificate.
// It looks for the UID field (OID 0.9.2342.19200300.100.1.1) in the Subject.
// If not found, falls back to CommonName. Returns "unknown" if neither is present.
func extractUserID(cert *x509.Certificate) string {
	// OID for UID (user identifier)
	uidOID := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	
	// Search through all Subject attributes
	for _, attr := range cert.Subject.Names {
		if attr.Type.Equal(uidOID) {
			if str, ok := attr.Value.(string); ok {
				return strings.TrimSpace(str)
			}
		}
	}
	
	// Fallback to CommonName
	if cert.Subject.CommonName != "" {
		return strings.TrimSpace(cert.Subject.CommonName)
	}
	
	// If no identifier found
	return "unknown"
}

func handleConnection(conn *quic.Conn, srv *server.Server) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in connection handler: %v", r)
		}
	}()

	clientCert := conn.ConnectionState().TLS.PeerCertificates
	var userid string
	if len(clientCert) > 0 {
		userid = extractUserID(clientCert[0])
		log.Printf("Client connected: userid=%s (CN=%s)", userid, clientCert[0].Subject.CommonName)
	} else {
		userid = "unknown"
		log.Printf("Client connected: no client certificate")
	}

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("AcceptStream error: %v", err)
			return
		}

		go func(uid string) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("PANIC in stream handler: %v", r)
				}
			}()
			log.Printf("New stream accepted for user: %s", uid)
			if err := srv.HandleStream(stream, uid); err != nil {
				log.Printf("HandleStream error: %v", err)
			}
		}(userid)
	}
}
