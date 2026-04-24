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

	"github.com/fdefilippo/quics/internal/server"
	"github.com/fdefilippo/quics/internal/webhook"
	"github.com/quic-go/quic-go"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"software.sslmate.com/src/go-pkcs12"
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
	Identity struct {
		MapClientCNToLocalUser   bool `yaml:"map_client_cn_to_local_user"`
		RejectIfLocalUserMissing bool `yaml:"reject_if_local_user_missing"`
	} `yaml:"identity"`
	Storage struct {
		Mode           string `yaml:"mode"`
		RootDir        string `yaml:"root_dir"`
		UserRootPolicy string `yaml:"user_root_policy"`
		UserSubdir     string `yaml:"user_subdir"`
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
	createCAUserid       string
	createCAName         string
	createCAEmail        string
	createCAPassword     string
	createCertUserid     string
	createCertName       string
	createCertSurname    string
	createCertEmail      string
	createCertPassword   string
	createCertCAPassword string
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
	createCACmd.Flags().StringVar(&createCAPassword, "password", "", "Password for CA PKCS#12 file (optional, but recommended)")
	rootCmd.AddCommand(createCACmd)

	// create-cert command
	createCertCmd := &cobra.Command{
		Use:   "create-cert",
		Short: "Create a new user certificate",
		Long:  `Create a new ECDSA P-256 user certificate signed by the CA. The resulting PKCS#12 file includes the client certificate, private key, and CA certificate chain.`,
		RunE:  runCreateCert,
	}
	createCertCmd.Flags().StringVarP(&createCertUserid, "userid", "u", "", "User ID (required, used for filename)")
	createCertCmd.Flags().StringVar(&createCertName, "name", "", "User's first name")
	createCertCmd.Flags().StringVar(&createCertSurname, "surname", "", "User's last name")
	createCertCmd.Flags().StringVar(&createCertEmail, "email", "", "User's email address")
	createCertCmd.Flags().StringVar(&createCertPassword, "password", "", "Password for user PKCS#12 file (optional, but recommended)")
	createCertCmd.Flags().StringVar(&createCertCAPassword, "ca-password", "", "Password for CA PKCS#12 file (if CA was created with a password)")
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

func validateConfig(config *Config) error {
	// Validate TLS configuration
	if config.TLS.CertFile == "" {
		return fmt.Errorf("tls.cert_file must be specified in configuration")
	}
	if config.TLS.KeyFile == "" {
		return fmt.Errorf("tls.key_file must be specified in configuration")
	}

	// Validate identity/storage configuration
	if config.Identity.MapClientCNToLocalUser {
		if config.Storage.Mode == "" {
			config.Storage.Mode = "virtual-root"
		}
		if config.Storage.UserRootPolicy == "" {
			config.Storage.UserRootPolicy = "home"
		}
		if config.Storage.Mode != "shared" && config.Storage.Mode != "virtual-root" {
			return fmt.Errorf("storage.mode must be 'shared' or 'virtual-root', got %q", config.Storage.Mode)
		}
		if config.Storage.UserRootPolicy != "home" && config.Storage.UserRootPolicy != "subdir" {
			return fmt.Errorf("storage.user_root_policy must be 'home' or 'subdir', got %q", config.Storage.UserRootPolicy)
		}
	}

	// Client CA file is mandatory
	if config.Auth.ClientCAFile == "" {
		return fmt.Errorf("client_ca_file must be specified in configuration")
	}

	// Validate certs directory if specified
	if config.Auth.CertsDir != "" {
		if err := os.MkdirAll(config.Auth.CertsDir, 0755); err != nil {
			return fmt.Errorf("failed to create certs directory: %w", err)
		}
	}

	// Validate storage directory if specified
	if config.Storage.RootDir != "" {
		if err := os.MkdirAll(config.Storage.RootDir, 0755); err != nil {
			return fmt.Errorf("failed to create storage root directory: %w", err)
		}
	}

	// Validate shell configuration
	if config.Shell.MaxExecutionTime < 0 {
		return fmt.Errorf("shell.max_execution_time_seconds must be non-negative")
	}
	if config.Shell.AllowedCommands == nil {
		config.Shell.AllowedCommands = []string{}
	}
	if config.Shell.AllowedEnvVars == nil {
		config.Shell.AllowedEnvVars = []string{}
	}

	// Validate webhook configuration if enabled
	if config.Webhook.Enabled {
		if config.Webhook.URL == "" {
			return fmt.Errorf("webhook.url must be specified when webhook is enabled")
		}
		if config.Webhook.Timeout <= 0 {
			return fmt.Errorf("webhook.timeout_seconds must be positive when webhook is enabled")
		}
		if config.Webhook.RetryCount < 0 {
			return fmt.Errorf("webhook.retry_count must be non-negative when webhook is enabled")
		}
	}

	return nil
}

func startServer(config *Config) error {
	// Validate configuration early
	if err := validateConfig(config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(config.TLS.CertFile, config.TLS.KeyFile)
	if err != nil {
		return fmt.Errorf("loading TLS cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quic-file-transfer"},
	}

	// Validate identity/storage configuration
	if config.Identity.MapClientCNToLocalUser {
		if config.Storage.Mode == "" {
			config.Storage.Mode = "virtual-root"
		}
		if config.Storage.UserRootPolicy == "" {
			config.Storage.UserRootPolicy = "home"
		}
		if config.Storage.Mode != "shared" && config.Storage.Mode != "virtual-root" {
			return fmt.Errorf("storage.mode must be 'shared' or 'virtual-root', got %q", config.Storage.Mode)
		}
		if config.Storage.UserRootPolicy != "home" && config.Storage.UserRootPolicy != "subdir" {
			return fmt.Errorf("storage.user_root_policy must be 'home' or 'subdir', got %q", config.Storage.UserRootPolicy)
		}
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

	// Parse QUIC configuration
	idleTimeout := server.DefaultIdleTimeout
	if config.QUIC.MaxIdleTimeoutSeconds > 0 {
		idleTimeout = time.Duration(config.QUIC.MaxIdleTimeoutSeconds) * time.Second
	}

	keepAlive := server.DefaultKeepAlivePeriod
	if config.QUIC.KeepAlivePeriodSeconds == -1 {
		// -1 means disable keepalive
		keepAlive = 0
	} else if config.QUIC.KeepAlivePeriodSeconds > 0 {
		keepAlive = time.Duration(config.QUIC.KeepAlivePeriodSeconds) * time.Second
	}

	// Adjust idle timeout if max execution time is longer
	executionTimeout := time.Duration(config.Shell.MaxExecutionTime) * time.Second
	if executionTimeout > idleTimeout {
		srv.logger.Infow("Adjusting QUIC idle timeout", 
			"from", idleTimeout,
			"to", executionTimeout)
		idleTimeout = executionTimeout
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:  idleTimeout,
		KeepAlivePeriod: keepAlive,
	}

	// Debug: fmt.Printf("QUIC config: idle_timeout=%v, keepalive=%v\n", idleTimeout, keepAlive)
	listener, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()

	serverConfig := &server.Config{
		IdentityConfig: &server.IdentityConfig{
			MapClientCNToLocalUser:   config.Identity.MapClientCNToLocalUser,
			RejectIfLocalUserMissing: config.Identity.RejectIfLocalUserMissing,
		},
		StorageConfig: &server.StorageConfig{
			Mode:           config.Storage.Mode,
			RootDir:        config.Storage.RootDir,
			UserRootPolicy: config.Storage.UserRootPolicy,
			UserSubdir:     config.Storage.UserSubdir,
		},
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
	logger, err := logging.NewLogger("info", os.Stdout)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	notifier = webhook.New(whConfig)
	if notifier != nil {
		logger.Infow("Webhook notifications enabled", "url", config.Webhook.URL)
	}
	srv := server.NewServer(serverConfig, notifier, logger)

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
			srv.logger.Errorw("PANIC in connection handler", "error", r)
		}
	}()

	clientCert := conn.ConnectionState().TLS.PeerCertificates
	var userid string
	if len(clientCert) > 0 {
		userid = clientCert[0].Subject.CommonName
		srv.logger.Infow("Client connected", "user_id", userid)
	} else {
		userid = "unknown"
		srv.logger.Infow("Client connected", "user_id", "no client certificate")
	}

	sess, err := srv.NewSession(userid)
	if err != nil {
		srv.logger.Errorw("Failed to create session", "user_id", userid, "error", err)
		conn.CloseWithError(1, fmt.Sprintf("authentication failed: %v", err))
		return
	}
	srv.logger.Infow("Session created", 
		"user", sess.LocalUser,
		"uid", sess.Uid,
		"gid", sess.Gid,
		"home", sess.HomeDir,
		"root", sess.RootDir)

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			srv.logger.Errorw("AcceptStream error", "error", err)
			return
		}

		go func(s *server.Session) {
			defer func() {
				if r := recover(); r != nil {
					srv.logger.Errorw("PANIC in stream handler", "error", r)
				}
			}()
			srv.logger.Infow("New stream accepted", "user", s.LocalUser)
			if err := srv.HandleStream(stream, s); err != nil {
				srv.logger.Errorw("HandleStream error", "error", err)
			}
		}(sess.Copy())
	}
}

func ifEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
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

	// Create PKCS#12 file (certificate + private key)
	p12Path := fmt.Sprintf("%s/%s.p12", config.Auth.CertsDir, createCAUserid)
	p12Data, err := pkcs12.Encode(rand.Reader, priv, &x509.Certificate{Raw: derBytes}, nil, createCAPassword)
	if err != nil {
		return fmt.Errorf("failed to encode PKCS#12: %w", err)
	}
	if err := os.WriteFile(p12Path, p12Data, 0600); err != nil {
		return fmt.Errorf("failed to write PKCS#12 file: %w", err)
	}
	fmt.Printf("CA PKCS#12 file written to %s (password: %s)\n", p12Path, ifEmpty(createCAPassword, "none"))

	// Also write certificate-only PEM for server use
	certPath := fmt.Sprintf("%s/%s.crt", config.Auth.CertsDir, createCAUserid)
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	fmt.Printf("CA certificate (PEM) written to %s (for server configuration)\n", certPath)

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
	// Try PKCS#12 file first (new format)
	caDir := filepath.Dir(config.Auth.ClientCAFile)
	base := filepath.Base(config.Auth.ClientCAFile)
	ext := filepath.Ext(base)
	caP12Name := base[:len(base)-len(ext)] + ".p12"
	caP12Path := filepath.Join(caDir, caP12Name)

	var caCert *x509.Certificate
	var caPriv *ecdsa.PrivateKey

	if p12Data, err := os.ReadFile(caP12Path); err == nil {
		// Load from PKCS#12
		privInterface, cert, err := pkcs12.Decode(p12Data, createCertCAPassword)
		if err != nil {
			return fmt.Errorf("failed to decode CA PKCS#12 file %s: %w", caP12Path, err)
		}
		var ok bool
		caPriv, ok = privInterface.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("CA private key in PKCS#12 is not ECDSA")
		}
		caCert = cert
		fmt.Printf("Loaded CA from PKCS#12 file: %s\n", caP12Path)
	} else {
		// Fallback to old PEM format (for compatibility during transition)
		caCertPEM, err := os.ReadFile(config.Auth.ClientCAFile)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caBlock, _ := pem.Decode(caCertPEM)
		if caBlock == nil || caBlock.Type != "CERTIFICATE" {
			return fmt.Errorf("failed to decode CA certificate PEM")
		}
		caCert, err = x509.ParseCertificate(caBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificate: %w", err)
		}

		// Find CA private key (same basename as CA cert)
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
		fmt.Printf("Loaded CA from PEM files (legacy format)\n")
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

	// Create PKCS#12 file (certificate + private key + CA certificate)
	p12Path := fmt.Sprintf("%s/%s.p12", config.Auth.CertsDir, createCertUserid)
	p12Data, err := pkcs12.Encode(rand.Reader, priv, &x509.Certificate{Raw: derBytes}, []*x509.Certificate{caCert}, createCertPassword)
	if err != nil {
		return fmt.Errorf("failed to encode PKCS#12: %w", err)
	}
	if err := os.WriteFile(p12Path, p12Data, 0600); err != nil {
		return fmt.Errorf("failed to write PKCS#12 file: %w", err)
	}
	fmt.Printf("User PKCS#12 file written to %s (password: %s) - includes CA certificate\n", p12Path, ifEmpty(createCertPassword, "none"))

	return nil
}
