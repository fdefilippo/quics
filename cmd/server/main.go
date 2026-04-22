package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/francesco/quics/internal/server"
	"github.com/francesco/quics/internal/webhook"
	"github.com/quic-go/quic-go"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
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
		CertsDir     string `yaml:"certs_dir"`
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
	Webhook struct {
		URL                string `yaml:"url"`
		Timeout            int    `yaml:"timeout_seconds"`
		RetryCount         int    `yaml:"retry_count"`
		Enabled            bool   `yaml:"enabled"`
		AuthType           string `yaml:"auth_type"`
		Username           string `yaml:"username"`
		Password           string `yaml:"password"`
		BearerToken        string `yaml:"bearer_token"`
		ClientCert         string `yaml:"client_cert"`
		ClientKey          string `yaml:"client_key"`
		InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	} `yaml:"webhook"`
}

var configPath string

var (
	createCAUserid    string
	createCAName      string
	createCAEmail     string
	createCertUserid  string
	createCertName    string
	createCertSurname string
	createCertEmail   string
)

var rootCmd = &cobra.Command{
	Use:   "quicsd",
	Short: "QUIC server for file transfer and remote command execution",
	Long: `QUICS server provides secure file transfer and remote command execution
over QUIC protocol with mutual TLS authentication.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := loadConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		return startServer(config)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "./config/server.yaml", "Path to configuration file")

	// create-ca command
	createCACmd := &cobra.Command{
		Use:   "create-ca",
		Short: "Create a new Certificate Authority",
		Long:  `Create a new ECDSA P-256 Certificate Authority and save to certs directory.`,
		RunE:  runCreateCA,
	}
	createCACmd.Flags().StringVarP(&createCAUserid, "userid", "u", "ca", "CA user ID (used for filename)")
	createCACmd.Flags().StringVar(&createCAName, "name", "QUICS CA", "CA common name")
	createCACmd.Flags().StringVar(&createCAEmail, "email", "", "CA email address")
	rootCmd.AddCommand(createCACmd)

	// create-cert command
	createCertCmd := &cobra.Command{
		Use:   "create-cert",
		Short: "Create a new user certificate",
		Long:  `Create a new ECDSA P-256 user certificate signed by the CA.`,
		RunE:  runCreateCert,
	}
	createCertCmd.Flags().StringVarP(&createCertUserid, "userid", "u", "", "User ID (required, used for filename)")
	createCertCmd.Flags().StringVar(&createCertName, "name", "", "User's first name")
	createCertCmd.Flags().StringVar(&createCertSurname, "surname", "", "User's last name")
	createCertCmd.Flags().StringVar(&createCertEmail, "email", "", "User's email address")
	createCertCmd.MarkFlagRequired("userid")
	rootCmd.AddCommand(createCertCmd)
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

func startServer(config *Config) error {
	cert, err := tls.LoadX509KeyPair(config.TLS.CertFile, config.TLS.KeyFile)
	if err != nil {
		return fmt.Errorf("loading TLS cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quic-file-transfer"},
	}

	// Client CA file is mandatory
	if config.Auth.ClientCAFile == "" {
		return fmt.Errorf("client_ca_file must be specified in configuration")
	}
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
		fmt.Printf("Adjusting QUIC idle timeout from %v to %v to match max execution time\n",
			idleTimeout, executionTimeout)
		idleTimeout = executionTimeout
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:  idleTimeout,
		KeepAlivePeriod: keepAlive,
	}

	fmt.Printf("QUIC config: idle_timeout=%v, keepalive=%v\n",
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
	// Create webhook notifier if enabled
	var notifier webhook.Notifier
	if config.Webhook.Enabled && config.Webhook.URL != "" {
		whConfig := &webhook.Config{
			URL:                config.Webhook.URL,
			Timeout:            config.Webhook.Timeout,
			RetryCount:         config.Webhook.RetryCount,
			Enabled:            config.Webhook.Enabled,
			AuthType:           config.Webhook.AuthType,
			Username:           config.Webhook.Username,
			Password:           config.Webhook.Password,
			BearerToken:        config.Webhook.BearerToken,
			ClientCert:         config.Webhook.ClientCert,
			ClientKey:          config.Webhook.ClientKey,
			InsecureSkipVerify: config.Webhook.InsecureSkipVerify,
		}
		notifier = webhook.New(whConfig)
		if notifier != nil {
			fmt.Printf("Webhook notifications enabled: %s\n", config.Webhook.URL)
		}
	}
	srv := server.NewServer(serverConfig, notifier)

	fmt.Printf("Server listening on %s\n", addr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			fmt.Printf("Accept error: %v\n", err)
			continue
		}

		go handleConnection(conn, srv)
	}
}

func handleConnection(conn *quic.Conn, srv *server.Server) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("PANIC in connection handler: %v\n", r)
		}
	}()

	clientCert := conn.ConnectionState().TLS.PeerCertificates
	var userid string
	if len(clientCert) > 0 {
		userid = clientCert[0].Subject.CommonName
		fmt.Printf("Client connected: %s\n", userid)
	} else {
		userid = "unknown"
		fmt.Printf("Client connected: no client certificate\n")
	}

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			fmt.Printf("AcceptStream error: %v\n", err)
			return
		}

		go func(uid string) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("PANIC in stream handler: %v\n", r)
				}
			}()
			fmt.Printf("New stream accepted for user: %s\n", uid)
			if err := srv.HandleStream(stream, uid); err != nil {
				fmt.Printf("HandleStream error: %v\n", err)
			}
		}(userid)
	}
}

func runCreateCA(cmd *cobra.Command, args []string) error {
	config, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if config.Auth.CertsDir == "" {
		return fmt.Errorf("certs_dir must be specified in configuration")
	}
	if err := os.MkdirAll(config.Auth.CertsDir, 0755); err != nil {
		return fmt.Errorf("failed to create certs directory: %w", err)
	}

	// Generate ECDSA P-256 key pair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   createCAName,
			Organization: []string{"QUICS"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour * 10), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	if createCAEmail != "" {
		template.Subject.ExtraNames = []pkix.AttributeTypeAndValue{
			{Type: []int{1, 2, 840, 113549, 1, 9, 1}, Value: createCAEmail},
		}
	}

	// Self-sign the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate
	certPath := fmt.Sprintf("%s/%s.crt", config.Auth.CertsDir, createCAUserid)
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	fmt.Printf("CA certificate written to %s\n", certPath)

	// Write private key
	keyPath := fmt.Sprintf("%s/%s.key", config.Auth.CertsDir, createCAUserid)
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer keyFile.Close()
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}
	fmt.Printf("CA private key written to %s\n", keyPath)

	// Update config's client_ca_file if it's empty
	if config.Auth.ClientCAFile == "" {
		config.Auth.ClientCAFile = certPath
		fmt.Printf("Set client_ca_file to %s in memory (update config file manually)\n", certPath)
	}

	return nil
}

func runCreateCert(cmd *cobra.Command, args []string) error {
	config, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if config.Auth.CertsDir == "" {
		return fmt.Errorf("certs_dir must be specified in configuration")
	}
	if config.Auth.ClientCAFile == "" {
		return fmt.Errorf("client_ca_file must be specified in configuration (run create-ca first)")
	}
	if createCertUserid == "" {
		return fmt.Errorf("userid is required")
	}

	// Load CA certificate and private key
	caCertPEM, err := os.ReadFile(config.Auth.ClientCAFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Find CA private key (same basename as CA cert)
	caDir := filepath.Dir(config.Auth.ClientCAFile)
	base := filepath.Base(config.Auth.ClientCAFile)
	ext := filepath.Ext(base)
	caKeyName := base[:len(base)-len(ext)] + ".key"
	caKeyPath := filepath.Join(caDir, caKeyName)
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		// Fallback to "ca.key" in same directory
		caKeyPath = filepath.Join(caDir, "ca.key")
		caKeyPEM, err = os.ReadFile(caKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read CA private key (tried %s and %s): %w", filepath.Join(caDir, caKeyName), caKeyPath, err)
		}
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil || (caKeyBlock.Type != "EC PRIVATE KEY" && caKeyBlock.Type != "PRIVATE KEY") {
		return fmt.Errorf("failed to decode CA private key PEM")
	}
	var caPriv *ecdsa.PrivateKey
	if key, err := x509.ParseECPrivateKey(caKeyBlock.Bytes); err == nil {
		caPriv = key
	} else if keyInterface, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes); err == nil {
		switch k := keyInterface.(type) {
		case *ecdsa.PrivateKey:
			caPriv = k
		default:
			return fmt.Errorf("CA private key is not ECDSA")
		}
	} else {
		return fmt.Errorf("failed to parse CA private key as EC or PKCS8: %w", err)
	}

	// Generate user key pair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate user private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	subject := pkix.Name{
		CommonName: createCertUserid,
	}
	if createCertName != "" || createCertSurname != "" {
		fullName := strings.TrimSpace(fmt.Sprintf("%s %s", createCertName, createCertSurname))
		subject.OrganizationalUnit = []string{fullName}
	}
	if createCertEmail != "" {
		subject.ExtraNames = []pkix.AttributeTypeAndValue{
			{Type: []int{1, 2, 840, 113549, 1, 9, 1}, Value: createCertEmail},
		}
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Sign with CA
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caPriv)
	if err != nil {
		return fmt.Errorf("failed to create user certificate: %w", err)
	}

	// Write certificate
	certPath := fmt.Sprintf("%s/%s.crt", config.Auth.CertsDir, createCertUserid)
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	fmt.Printf("User certificate written to %s\n", certPath)

	// Write private key
	keyPath := fmt.Sprintf("%s/%s.key", config.Auth.CertsDir, createCertUserid)
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer keyFile.Close()
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}
	fmt.Printf("User private key written to %s\n", keyPath)

	return nil
}
