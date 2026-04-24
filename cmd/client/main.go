package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/fdefilippo/quics/internal/client"
	"github.com/fdefilippo/quics/internal/protocol"
	"github.com/quic-go/quic-go"
	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
)

type ClientConfig struct {
	ClientCert             string
	ClientKey              string
	ServerAddr             string
	CACert                 string
	Upload                 string
	Download               string
	Output                 string
	Mode                   string
	Cmd                    string
	ExecCmd                string
	Env                    []string
	Interactive            bool
	Insecure               bool
	MaxIdleTimeoutSeconds  int
	KeepAlivePeriodSeconds int
}

var (
	clientCert             string
	clientKey              string
	clientPassword         string
	serverAddr             string
	caCert                 string
	upload                 string
	download               string
	output                 string
	mode                   string
	cmdStr                 string
	execCmd                string
	env                    []string
	interactive            bool
	insecure               bool
	maxIdleTimeoutSeconds  int
	keepAlivePeriodSeconds int
	importFile             string
	importHostname         string
	changePwdFile          string
	changePwdOldPassword   string
	changePwdNewPassword   string
)

var rootCmd = &cobra.Command{
	Use:   "quicsc",
	Short: "QUIC client for file transfer and remote command execution",
	Long: `QUICS client provides secure file transfer and remote command execution
over QUIC protocol with mutual TLS authentication.`,
	PreRunE: validateConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
		// If no operation specified, show help
		if upload == "" && download == "" && cmdStr == "" && execCmd == "" && !interactive {
			return cmd.Help()
		}
		config := &ClientConfig{
			ClientCert:             clientCert,
			ClientKey:              clientKey,
			ServerAddr:             serverAddr,
			CACert:                 caCert,
			Upload:                 upload,
			Download:               download,
			Output:                 output,
			Mode:                   strings.ToUpper(mode),
			Cmd:                    cmdStr,
			ExecCmd:                execCmd,
			Env:                    env,
			Interactive:            interactive,
			Insecure:               insecure,
			MaxIdleTimeoutSeconds:  maxIdleTimeoutSeconds,
			KeepAlivePeriodSeconds: keepAlivePeriodSeconds,
		}
		return runClient(config)
	},
}

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a PKCS#12 certificate file",
	Long:  "Import a PKCS#12 certificate file into the client's certificate store.",
	RunE:  runImport,
}

var changePasswordCmd = &cobra.Command{
	Use:   "change-password",
	Short: "Change password of a PKCS#12 certificate file",
	Long:  "Decrypt a PKCS#12 file with the old password and re-encrypt it with a new one.",
	RunE:  runChangePassword,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&clientCert, "client-cert", "C", "", "Path to client certificate (PEM or PKCS#12). Default: ~/.quicsc/servers/<hostname>.p12, then ~/.quicsc/client.p12, then PEM files")
	rootCmd.PersistentFlags().StringVarP(&clientKey, "client-key", "K", "", "Path to client private key (PEM). Default: ~/.quicsc/servers/<hostname>/private.key, then ~/.quicsc/private.key (must have 600 permissions). Ignored if PKCS#12 file is used")
	rootCmd.PersistentFlags().StringVarP(&clientPassword, "password", "P", "", "Password for PKCS#12 file (if applicable)")
	rootCmd.PersistentFlags().StringVarP(&serverAddr, "server-addr", "s", "localhost:4242", "Server address")
	rootCmd.PersistentFlags().StringVarP(&caCert, "ca-cert", "a", "", "CA certificate to verify server (optional). CA is automatically extracted from PKCS#12 file; use this flag to override or when using PEM certificates")
	rootCmd.PersistentFlags().StringVarP(&upload, "upload", "u", "", "Local file to upload")
	rootCmd.PersistentFlags().StringVarP(&download, "download", "d", "", "Remote file to download")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "Output path for downloaded file")
	rootCmd.PersistentFlags().StringVarP(&mode, "mode", "m", "BIN", "Transfer mode: BIN or ASCII")
	rootCmd.PersistentFlags().StringVarP(&cmdStr, "cmd", "c", "", "Remote command to execute")
	rootCmd.PersistentFlags().StringVarP(&execCmd, "exec", "X", "", "Command to execute as the mapped local user")
	rootCmd.PersistentFlags().StringSliceVarP(&env, "env", "e", []string{}, "Environment variable in NAME=VALUE format (can be repeated)")
	rootCmd.PersistentFlags().BoolVarP(&interactive, "interactive", "i", false, "Start interactive session")
	rootCmd.PersistentFlags().BoolVarP(&insecure, "insecure", "k", false, "Skip server certificate verification")
	rootCmd.PersistentFlags().IntVarP(&maxIdleTimeoutSeconds, "max-idle-timeout", "t", int(client.DefaultIdleTimeout.Seconds()), "Maximum idle timeout in seconds (default: 120)")
	rootCmd.PersistentFlags().IntVarP(&keepAlivePeriodSeconds, "keep-alive-period", "p", int(client.DefaultKeepAlivePeriod.Seconds()), "Keep-alive period in seconds (default: 15, -1 to disable)")

	rootCmd.AddCommand(importCmd)
	importCmd.Flags().StringVarP(&importFile, "file", "f", "", "Path to PKCS#12 file to import (required)")
	importCmd.Flags().StringVarP(&importHostname, "hostname", "n", "", "Hostname for server-specific certificate (default: extracted from server-addr flag)")

	rootCmd.AddCommand(changePasswordCmd)
	changePasswordCmd.Flags().StringVarP(&changePwdFile, "file", "f", "", "Path to PKCS#12 file (default: auto-detected from --client-cert or ~/.quicsc/servers/<hostname>.p12)")
	changePasswordCmd.Flags().StringVar(&changePwdOldPassword, "old-password", "", "Current password of the PKCS#12 file")
	changePasswordCmd.Flags().StringVar(&changePwdNewPassword, "new-password", "", "New password for the PKCS#12 file (empty for no password)")
}

func extractHostname(addr string) string {
	// Remove port if present
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port, return as-is (could be hostname or IPv4/IPv6)
		return addr
	}
	return host
}

func validateConfig(cmd *cobra.Command, args []string) error {
	// Get home directory for default paths
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}
	defaultCertDir := filepath.Join(homeDir, ".quicsc")

	// Extract hostname from server address for server-specific certificate
	serverHost := extractHostname(serverAddr)
	serverSpecificCert := filepath.Join(defaultCertDir, "servers", serverHost+".p12")

	// Helper to check if file exists and set variable if not already set
	trySetCert := func(target *string, path string) bool {
		if *target == "" {
			if _, err := os.Stat(path); err == nil {
				*target = path
				return true
			}
		}
		return false
	}

	// Try to find PKCS#12 file first (new format)
	if clientCert == "" {
		// Try server-specific PKCS#12
		if !trySetCert(&clientCert, serverSpecificCert) {
			// Fallback to global PKCS#12
			trySetCert(&clientCert, filepath.Join(defaultCertDir, "client.p12"))
		}
	}

	// If clientCert ends with .p12, we have a PKCS#12 file - ignore clientKey
	usingPKCS12 := strings.HasSuffix(strings.ToLower(clientCert), ".p12")

	if !usingPKCS12 {
		// No PKCS#12 found or specified, try PEM files (legacy structure)
		serverSpecificDir := filepath.Join(defaultCertDir, "servers", serverHost)
		if clientCert == "" {
			// Try server-specific PEM certificate
			if !trySetCert(&clientCert, filepath.Join(serverSpecificDir, "public.crt")) {
				// Fallback to global PEM certificate
				trySetCert(&clientCert, filepath.Join(defaultCertDir, "public.crt"))
			}
		}

		// Client private key (only needed for PEM format)
		if clientKey == "" {
			// Try server-specific
			if !trySetCert(&clientKey, filepath.Join(serverSpecificDir, "private.key")) {
				// Fallback to global
				trySetCert(&clientKey, filepath.Join(defaultCertDir, "private.key"))
			}
		}
	}

	// CA certificate is now included in PKCS#12 file; external CA file can still be specified via --ca-cert

	// After checking defaults, validate that we have certificates
	if clientCert == "" {
		return fmt.Errorf("client certificate is required (provide via --client-cert, place PKCS#12 file as ~/.quicsc/servers/<hostname>.p12 or ~/.quicsc/client.p12, or PEM files public.crt and private.key)")
	}

	if !usingPKCS12 && clientKey == "" {
		return fmt.Errorf("client private key is required when using PEM certificate (provide via --client-key, place in ~/.quicsc/private.key or ~/.quicsc/servers/<hostname>/private.key)")
	}

	// Check that certificate files exist and are readable
	if _, err := os.Stat(clientCert); err != nil {
		return fmt.Errorf("client certificate file %s not found or not readable: %w", clientCert, err)
	}

	if !usingPKCS12 {
		if _, err := os.Stat(clientKey); err != nil {
			return fmt.Errorf("client key file %s not found or not readable: %w", clientKey, err)
		}

		// Validate private key permissions (must be 600)
		info, err := os.Stat(clientKey)
		if err != nil {
			return fmt.Errorf("failed to stat private key file: %w", err)
		}
		perm := info.Mode().Perm()
		if perm != client.PrivateKeyFileMode {
			return fmt.Errorf("private key file %s must have permissions %o (rw-------), got %o", clientKey, client.PrivateKeyFileMode, perm)
		}
	}

	if mode != "BIN" && mode != "ASCII" {
		return fmt.Errorf("mode must be BIN or ASCII")
	}

	return nil
}

func runImport(cmd *cobra.Command, args []string) error {
	// Determine hostname
	hostname := importHostname
	if hostname == "" {
		hostname = extractHostname(serverAddr)
	}
	if hostname == "" {
		hostname = "default"
	}

	if importFile == "" {
		return fmt.Errorf("--file is required")
	}

	// Read source file
	data, err := os.ReadFile(importFile)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	// Optional: validate PKCS#12 format by attempting to decode (without password)
	// We'll skip password validation; user will need to provide password when using the certificate.

	// Determine destination directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	destDir := filepath.Join(homeDir, ".quicsc", "servers")
	if err := os.MkdirAll(destDir, 0700); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}
	destPath := filepath.Join(destDir, hostname+".p12")

	// Check if destination already exists
	if _, err := os.Stat(destPath); err == nil {
		// Ask for confirmation? For now, overwrite.
		fmt.Printf("Overwriting existing certificate file %s\n", destPath)
	}

	// Copy file
	if err := os.WriteFile(destPath, data, client.CertificateFileMode); err != nil {
		return fmt.Errorf("failed to write destination file: %w", err)
	}

	fmt.Printf("Certificate imported successfully to %s\n", destPath)
	return nil
}

func runChangePassword(cmd *cobra.Command, args []string) error {
	// Determine the PKCS#12 file path
	p12File := changePwdFile
	if p12File == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		defaultCertDir := filepath.Join(homeDir, ".quicsc")
		serverHost := extractHostname(serverAddr)

		candidates := []string{
			filepath.Join(defaultCertDir, "servers", serverHost+".p12"),
			filepath.Join(defaultCertDir, "client.p12"),
		}
		if clientCert != "" {
			candidates = append([]string{clientCert}, candidates...)
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				p12File = c
				break
			}
		}
		if p12File == "" {
			return fmt.Errorf("no PKCS#12 file found; specify with --file or --client-cert")
		}
	}

	fmt.Printf("Using PKCS#12 file: %s\n", p12File)

	// Read the file
	p12Data, err := os.ReadFile(p12File)
	if err != nil {
		return fmt.Errorf("reading PKCS#12 file: %w", err)
	}

	// Decode with old password
	priv, cert, caCerts, err := pkcs12.DecodeChain(p12Data, changePwdOldPassword)
	if err != nil {
		return fmt.Errorf("decoding PKCS#12 with old password: %w", err)
	}

	// Re-encode with new password
	newP12Data, err := pkcs12.Encode(rand.Reader, priv, cert, caCerts, changePwdNewPassword)
	if err != nil {
		return fmt.Errorf("encoding PKCS#12 with new password: %w", err)
	}

	// Write back to file
	if err := os.WriteFile(p12File, newP12Data, client.PrivateKeyFileMode); err != nil {
		return fmt.Errorf("writing PKCS#12 file: %w", err)
	}

	fmt.Println("Password changed successfully.")
	return nil
}

func loadCertificateAndCA(certFile, keyFile, password string) (tls.Certificate, []*x509.Certificate, error) {
	// Check if certFile is PKCS#12
	if strings.HasSuffix(strings.ToLower(certFile), ".p12") {
		p12Data, err := os.ReadFile(certFile)
		if err != nil {
			return tls.Certificate{}, nil, fmt.Errorf("reading PKCS#12 file: %w", err)
		}

		priv, cert, caCerts, err := pkcs12.DecodeChain(p12Data, password)
		if err != nil {
			return tls.Certificate{}, nil, fmt.Errorf("decoding PKCS#12: %w", err)
		}

		// Convert to tls.Certificate
		var certDER []byte
		if cert != nil {
			certDER = cert.Raw
		}

		switch k := priv.(type) {
		case *ecdsa.PrivateKey:
			return tls.Certificate{
				Certificate: [][]byte{certDER},
				PrivateKey:  k,
				Leaf:        cert,
			}, caCerts, nil
		default:
			return tls.Certificate{}, nil, fmt.Errorf("unsupported private key type in PKCS#12: %T", priv)
		}
	}

	// PEM format (no CA chain)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	return cert, nil, err
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runClient(config *ClientConfig) error {
	cert, caCerts, err := loadCertificateAndCA(config.ClientCert, config.ClientKey, clientPassword)
	if err != nil {
		return fmt.Errorf("loading client certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{"quic-file-transfer"},
		InsecureSkipVerify: config.Insecure,
	}

	// Use CA from PKCS#12 chain if available
	if len(caCerts) > 0 {
		caCertPool := x509.NewCertPool()
		for _, ca := range caCerts {
			caCertPool.AddCert(ca)
		}
		tlsConfig.RootCAs = caCertPool
	} else if config.CACert != "" {
		// Fallback to external CA file
		caCert, err := os.ReadFile(config.CACert)
		if err != nil {
			return fmt.Errorf("reading CA cert: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Default values
	const defaultIdleTimeout = 120 * time.Second
	const defaultKeepAlive = 15 * time.Second

	// Parse QUIC configuration
	idleTimeout := defaultIdleTimeout
	if config.MaxIdleTimeoutSeconds > 0 {
		idleTimeout = time.Duration(config.MaxIdleTimeoutSeconds) * time.Second
	}

	keepAlive := defaultKeepAlive
	if config.KeepAlivePeriodSeconds == -1 {
		// -1 means disable keepalive
		keepAlive = 0
	} else if config.KeepAlivePeriodSeconds > 0 {
		keepAlive = time.Duration(config.KeepAlivePeriodSeconds) * time.Second
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:  idleTimeout,
		KeepAlivePeriod: keepAlive,
	}

	conn, err := quic.DialAddr(ctx, config.ServerAddr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("dialing server: %w", err)
	}
	defer conn.CloseWithError(0, "")

	fmt.Printf("Connected to %s\n", config.ServerAddr)

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("opening stream: %w", err)
	}
	defer stream.Close()

	if config.Upload != "" {
		return handleUpload(stream, config)
	} else if config.Download != "" {
		return handleDownload(stream, config)
	} else if config.ExecCmd != "" {
		return handleExec(stream, config)
	} else if config.Cmd != "" {
		return handleCommand(stream, config)
	} else if config.Interactive {
		return handleInteractive(stream, config)
	}

	return nil
}

func handleUpload(stream *quic.Stream, config *ClientConfig) error {
	file, err := os.Open(config.Upload)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}
	size := stat.Size()

	filename := filepath.Base(config.Upload)

	// Compute SHA-256 of the file
	hasher := sha256.New()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seeking file: %w", err)
	}
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("computing checksum: %w", err)
	}
	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Send command with checksum
	command := fmt.Sprintf("%s %s %d %s %s\n", protocol.CommandUpload, filename, size, config.Mode, checksum)
	if _, err := stream.Write([]byte(command)); err != nil {
		return fmt.Errorf("sending command: %w", err)
	}

	// Read offset response
	reader := bufio.NewReader(stream)
	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading offset response: %w", err)
	}
	status, msg := protocol.ParseResponse(strings.TrimSpace(line))
	if status != protocol.ResponseOK {
		return fmt.Errorf("server error: %s", msg)
	}
	var offset int64
	fmt.Sscanf(msg, "%d", &offset)
	fmt.Printf("Server offset: %d / %d\n", offset, size)

	if offset >= size {
		finalLine, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("reading final response: %w", err)
		}
		status2, msg2 := protocol.ParseResponse(strings.TrimSpace(finalLine))
		if status2 != protocol.ResponseOK {
			return fmt.Errorf("upload failed: %s", msg2)
		}
		fmt.Printf("Upload successful: %s\n", msg2)
		return nil
	}

	// Seek to offset in source file
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("seeking to offset %d: %w", offset, err)
	}

	// Send remaining data
	var dataWriter io.Writer = stream
	if config.Mode == protocol.ModeASCII {
		dataWriter = protocol.ASCIIWriter(stream)
	}
	remaining := size - offset
	written, err := io.CopyN(dataWriter, file, remaining)
	if err != nil {
		return fmt.Errorf("sending file data: %w", err)
	}
	if written != remaining {
		return fmt.Errorf("incomplete transfer: sent %d of %d bytes", written, remaining)
	}

	// Read final response
	finalLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("reading final response: %w", err)
	}
	status2, msg2 := protocol.ParseResponse(strings.TrimSpace(finalLine))
	if status2 != protocol.ResponseOK {
		return fmt.Errorf("upload failed: %s", msg2)
	}

	fmt.Printf("Upload successful: %s\n", msg2)
	return nil
}

func handleDownload(stream *quic.Stream, config *ClientConfig) error {
	filename := config.Download
	outputPath := config.Output
	if outputPath == "" {
		outputPath = filename
	}
	partPath := outputPath + ".part"

	// Determine resume offset from .part or outputPath
	var offset int64
	var resumeBase string
	if stat, err := os.Stat(partPath); err == nil {
		offset = stat.Size()
		resumeBase = partPath
	} else if stat, err := os.Stat(outputPath); err == nil {
		offset = stat.Size()
		resumeBase = outputPath
	}

	command := fmt.Sprintf("%s %s %s %d\n", protocol.CommandDownload, filename, config.Mode, offset)
	if _, err := stream.Write([]byte(command)); err != nil {
		return fmt.Errorf("sending command: %w", err)
	}

	// Read response: OK <remaining_size> <sha256>
	reader := bufio.NewReader(stream)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("reading response: %w", err)
	}
	status, msg := protocol.ParseResponse(strings.TrimSpace(line))
	if status != protocol.ResponseOK {
		return fmt.Errorf("server error: %s", msg)
	}

	var remainingSize int64
	var serverChecksum string
	if _, err := fmt.Sscanf(msg, "%d %s", &remainingSize, &serverChecksum); err != nil {
		return fmt.Errorf("parsing download response: %w", err)
	}

	if remainingSize == 0 {
		// Verify checksum of existing file before claiming success
		if serverChecksum != "" && offset > 0 {
			h := sha256.New()
			f, err := os.Open(resumeBase)
			if err != nil {
				return fmt.Errorf("opening existing file for checksum: %w", err)
			}
			if _, err := io.Copy(h, f); err != nil {
				f.Close()
				return fmt.Errorf("hashing existing file: %w", err)
			}
			f.Close()
			got := hex.EncodeToString(h.Sum(nil))
			if got != serverChecksum {
				os.Remove(outputPath)
				os.Remove(partPath)
				return fmt.Errorf("existing file corrupted (checksum mismatch), deleted: got %s, expected %s", got, serverChecksum)
			}
		}
		fmt.Printf("Download successful: %s (checksum verified)\n", outputPath)
		return nil
	}

	// Hash existing data for total file verification
	hasher := sha256.New()
	if offset > 0 {
		f, err := os.Open(resumeBase)
		if err != nil {
			return fmt.Errorf("opening existing file: %w", err)
		}
		if _, err := io.Copy(hasher, f); err != nil {
			f.Close()
			return fmt.Errorf("hashing existing file: %w", err)
		}
		f.Close()
	}

	// Open .part for appending (create if new, append if resuming)
	partFile, err := os.OpenFile(partPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, client.PartFileMode)
	if err != nil {
		return fmt.Errorf("creating part file: %w", err)
	}
	defer partFile.Close()

	var dataReader io.Reader = reader
	if config.Mode == protocol.ModeASCII {
		dataReader = protocol.ASCIIReader(reader)
	}

	// Hash incoming data while writing to .part
	multiWriter := io.MultiWriter(hasher, partFile)
	copied, err := io.CopyN(multiWriter, dataReader, remainingSize)
	if err != nil && err != io.EOF {
		partFile.Close()
		os.Remove(partPath)
		return fmt.Errorf("receiving file data: %w", err)
	}
	if copied != remainingSize {
		partFile.Close()
		os.Remove(partPath)
		return fmt.Errorf("incomplete transfer: received %d of %d bytes", copied, remainingSize)
	}

	// Verify checksum before touching the real output file
	partFile.Close()
	computedHex := hex.EncodeToString(hasher.Sum(nil))
	if computedHex != serverChecksum {
		os.Remove(partPath)
		return fmt.Errorf("checksum mismatch: got %s, expected %s", computedHex, serverChecksum)
	}

	// Checksum OK — commit to final path
	if offset > 0 {
		// Append .part data to outputPath, then remove .part
		src, err := os.Open(partPath)
		if err != nil {
			return fmt.Errorf("opening part file for commit: %w", err)
		}
		defer src.Close()
		dst, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			src.Close()
			return fmt.Errorf("opening output file for commit: %w", err)
		}
		if _, err := io.Copy(dst, src); err != nil {
			src.Close()
			dst.Close()
			return fmt.Errorf("committing part to output: %w", err)
		}
		src.Close()
		dst.Close()
		os.Remove(partPath)
	} else {
		if err := os.Rename(partPath, outputPath); err != nil {
			return fmt.Errorf("renaming part to output: %w", err)
		}
	}

	fmt.Printf("Download successful: %s (checksum verified)\n", outputPath)
	return nil
}

func handleCommand(stream *quic.Stream, config *ClientConfig) error {
	// Send environment variables if provided
	for _, envVar := range config.Env {
		if envVar == "" {
			continue
		}
		envCmd := fmt.Sprintf("%s %s\n", protocol.CommandEnv, envVar)
		_, err := stream.Write([]byte(envCmd))
		if err != nil {
			return fmt.Errorf("sending ENV command: %w", err)
		}
		// Read response
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil {
			return fmt.Errorf("reading ENV response: %w", err)
		}
		response := string(buf[:n])
		status, msg := protocol.ParseResponse(response)
		if status != protocol.ResponseOK {
			return fmt.Errorf("server rejected environment variable: %s", msg)
		}
	}

	// Send command
	cmdStr := fmt.Sprintf("%s %s\n", protocol.CommandCmd, config.Cmd)
	_, err := stream.Write([]byte(cmdStr))
	if err != nil {
		return fmt.Errorf("sending CMD command: %w", err)
	}

	// Read response
	reader := bufio.NewReader(stream)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading status line: %w", err)
	}
	statusLine = strings.TrimSpace(statusLine)
	status, msg := protocol.ParseResponse(statusLine)
	if status != protocol.ResponseOK {
		return fmt.Errorf("server error: %s", msg)
	}

	// Read exit code
	exitCodeLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading exit code: %w", err)
	}
	exitCode, err := strconv.Atoi(strings.TrimSpace(exitCodeLine))
	if err != nil {
		return fmt.Errorf("parsing exit code: %w", err)
	}

	// Read stdout size
	stdoutSizeLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading stdout size: %w", err)
	}
	stdoutSize, err := strconv.ParseInt(strings.TrimSpace(stdoutSizeLine), 10, 64)
	if err != nil {
		return fmt.Errorf("parsing stdout size: %w", err)
	}

	// Read stdout content
	stdoutBuf := make([]byte, stdoutSize)
	_, err = io.ReadFull(reader, stdoutBuf)
	if err != nil {
		return fmt.Errorf("reading stdout: %w", err)
	}

	// Read stderr size - handle possible extra newline after stdout
	var stderrSizeLine string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading stderr size: %w", err)
		}
		line = strings.TrimSpace(line)
		if line != "" {
			stderrSizeLine = line
			break
		}
		// Empty line means extra newline separator, continue reading
	}
	stderrSize, err := strconv.ParseInt(stderrSizeLine, 10, 64)
	if err != nil {
		return fmt.Errorf("parsing stderr size: %w", err)
	}

	// Read stderr content
	stderrBuf := make([]byte, stderrSize)
	_, err = io.ReadFull(reader, stderrBuf)
	if err != nil {
		return fmt.Errorf("reading stderr: %w", err)
	}

	// Print output
	if len(stdoutBuf) > 0 {
		os.Stdout.Write(stdoutBuf)
	}
	if len(stderrBuf) > 0 {
		os.Stderr.Write(stderrBuf)
	}

	os.Exit(exitCode)
	return nil
}

func handleExec(stream *quic.Stream, config *ClientConfig) error {
	// Send environment variables if provided
	for _, envVar := range config.Env {
		if envVar == "" {
			continue
		}
		envCmd := fmt.Sprintf("%s %s\n", protocol.CommandEnv, envVar)
		_, err := stream.Write([]byte(envCmd))
		if err != nil {
			return fmt.Errorf("sending ENV command: %w", err)
		}
		// Read response
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil {
			return fmt.Errorf("reading ENV response: %w", err)
		}
		response := string(buf[:n])
		status, msg := protocol.ParseResponse(response)
		if status != protocol.ResponseOK {
			return fmt.Errorf("server rejected environment variable: %s", msg)
		}
	}

	// Send EXEC command (user/group derived by server from CN mapping)
	cmdStr := fmt.Sprintf("%s %s\n", protocol.CommandExec, config.ExecCmd)
	_, err := stream.Write([]byte(cmdStr))
	if err != nil {
		return fmt.Errorf("sending EXEC command: %w", err)
	}

	// Read response
	reader := bufio.NewReader(stream)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading status line: %w", err)
	}
	statusLine = strings.TrimSpace(statusLine)
	status, msg := protocol.ParseResponse(statusLine)
	if status != protocol.ResponseOK {
		return fmt.Errorf("server error: %s", msg)
	}

	// Read exit code
	exitCodeLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading exit code: %w", err)
	}
	exitCode, err := strconv.Atoi(strings.TrimSpace(exitCodeLine))
	if err != nil {
		return fmt.Errorf("parsing exit code: %w", err)
	}

	// Read stdout size
	stdoutSizeLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading stdout size: %w", err)
	}
	stdoutSize, err := strconv.ParseInt(strings.TrimSpace(stdoutSizeLine), 10, 64)
	if err != nil {
		return fmt.Errorf("parsing stdout size: %w", err)
	}

	// Read stdout content
	stdoutBuf := make([]byte, stdoutSize)
	_, err = io.ReadFull(reader, stdoutBuf)
	if err != nil {
		return fmt.Errorf("reading stdout: %w", err)
	}

	// Read stderr size - handle possible extra newline after stdout
	var stderrSizeLine string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading stderr size: %w", err)
		}
		line = strings.TrimSpace(line)
		if line != "" {
			stderrSizeLine = line
			break
		}
		// Empty line means extra newline separator, continue reading
	}
	stderrSize, err := strconv.ParseInt(stderrSizeLine, 10, 64)
	if err != nil {
		return fmt.Errorf("parsing stderr size: %w", err)
	}

	// Read stderr content
	stderrBuf := make([]byte, stderrSize)
	_, err = io.ReadFull(reader, stderrBuf)
	if err != nil {
		return fmt.Errorf("reading stderr: %w", err)
	}

	// Print output
	if len(stdoutBuf) > 0 {
		os.Stdout.Write(stdoutBuf)
	}
	if len(stderrBuf) > 0 {
		os.Stderr.Write(stderrBuf)
	}

	os.Exit(exitCode)
	return nil
}

func handleInteractive(stream *quic.Stream, config *ClientConfig) error {
	fmt.Println("Interactive mode - type 'help' for commands")
	fmt.Println("Use arrow keys to navigate command history")

	// Setup readline with history
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	historyFile := filepath.Join(homeDir, ".quics_history")

	// Create autocompleter for built-in commands
	completer := readline.NewPrefixCompleter(
		readline.PcItem("help"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
		readline.PcItem("put"),
		readline.PcItem("get"),
		readline.PcItem("exec"),
	)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:       "quics> ",
		HistoryFile:  historyFile,
		AutoComplete: completer,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize readline: %w", err)
	}
	defer rl.Close()

	for {
		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				// Ctrl+C: clear line and continue
				fmt.Println("^C")
				continue
			}
			if err == io.EOF {
				// Ctrl+D: exit
				fmt.Println("exit")
				return nil
			}
			return fmt.Errorf("readline error: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Check if it's a local command (starts with !)
		if strings.HasPrefix(line, "!") {
			localCmd := strings.TrimSpace(line[1:])
			if localCmd == "" {
				continue
			}
			execLocalCommand(localCmd)
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		cmd := parts[0]
		args := parts[1:]

		switch cmd {
		case "exit", "quit":
			fmt.Println("Exiting interactive mode")
			return nil
		case "help":
			printHelp()
		case "put":
			if len(args) < 1 {
				fmt.Println("Usage: put <local> [remote] [ascii|bin]")
				continue
			}
			local := args[0]
			remote := local
			if len(args) >= 2 {
				remote = args[1]
			}
			mode := "BIN"
			if len(args) >= 3 && strings.ToUpper(args[2]) == "ASCII" {
				mode = "ASCII"
			}
			err := uploadFileInteractive(stream, local, remote, mode)
			if err != nil {
				fmt.Printf("Upload error: %v\n", err)
			}
		case "get":
			if len(args) < 1 {
				fmt.Println("Usage: get <remote> [local] [ascii|bin]")
				continue
			}
			remote := args[0]
			local := remote
			if len(args) >= 2 {
				local = args[1]
			}
			mode := "BIN"
			if len(args) >= 3 && strings.ToUpper(args[2]) == "ASCII" {
				mode = "ASCII"
			}
			err := downloadFileInteractive(stream, remote, local, mode)
			if err != nil {
				fmt.Printf("Download error: %v\n", err)
			}
		case "exec":
			if len(args) < 1 {
				fmt.Println("Usage: exec <command>")
				continue
			}
			command := strings.Join(args, " ")
			err := executeRemoteExecInteractive(stream, command)
			if err != nil {
				fmt.Printf("Exec error: %v\n", err)
			}
		default:
			// Remote command
			err := executeRemoteCommandInteractive(stream, line)
			if err != nil {
				if strings.Contains(err.Error(), "EOF") {
					fmt.Println("Connection closed by server")
					return nil
				}
				fmt.Printf("Command error: %v\n", err)
			}
		}
	}
}

func printHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  ! <cmd>              Execute local shell command")
	fmt.Println("  put <local> [remote] [ascii|bin]  Upload file")
	fmt.Println("  get <remote> [local] [ascii|bin]  Download file")
	fmt.Println("  exec <command>       Execute command as mapped user")
	fmt.Println("  <remote command>     Execute command on server")
	fmt.Println("  exit, quit           Exit interactive mode")
	fmt.Println("  help                 Show this help")
	fmt.Println("\nInteractive features:")
	fmt.Println("  Arrow keys           Navigate command history")
	fmt.Println("  Tab                  Auto-complete commands")
	fmt.Println("  Ctrl+C               Cancel current line")
	fmt.Println("  Ctrl+D               Exit interactive mode")
}

func execLocalCommand(cmd string) {
	execCmd := exec.Command("sh", "-c", cmd)
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.Stdin = os.Stdin
	err := execCmd.Run()
	if err != nil {
		fmt.Printf("Local command failed: %v\n", err)
	}
}

func uploadFileInteractive(stream *quic.Stream, local, remote, mode string) error {
	file, err := os.Open(local)
	if err != nil {
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return err
	}
	size := stat.Size()

	// Compute SHA-256
	hasher := sha256.New()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}
	checksum := hex.EncodeToString(hasher.Sum(nil))

	command := fmt.Sprintf("%s %s %d %s %s\n", protocol.CommandUpload, remote, size, mode, checksum)
	if _, err := stream.Write([]byte(command)); err != nil {
		return err
	}

	// Read offset response
	reader := bufio.NewReader(stream)
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	status, msg := protocol.ParseResponse(strings.TrimSpace(line))
	if status != protocol.ResponseOK {
		return fmt.Errorf("server error: %s", msg)
	}
	var offset int64
	fmt.Sscanf(msg, "%d", &offset)

	if offset >= size {
		finalLine, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		status2, msg2 := protocol.ParseResponse(strings.TrimSpace(finalLine))
		if status2 != protocol.ResponseOK {
			return fmt.Errorf("upload failed: %s", msg2)
		}
		fmt.Printf("Upload successful: %s\n", msg2)
		return nil
	}

	// Seek to offset
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return err
	}

	// Send remaining data
	var dataWriter io.Writer = stream
	if mode == protocol.ModeASCII {
		dataWriter = protocol.ASCIIWriter(stream)
	}
	remaining := size - offset
	if _, err := io.CopyN(dataWriter, file, remaining); err != nil {
		return err
	}

	// Read final response
	finalLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return err
	}
	status2, msg2 := protocol.ParseResponse(strings.TrimSpace(finalLine))
	if status2 != protocol.ResponseOK {
		return fmt.Errorf("upload failed: %s", msg2)
	}
	fmt.Printf("Upload successful: %s\n", msg2)
	return nil
}

func downloadFileInteractive(stream *quic.Stream, remote, local, mode string) error {
	partPath := local + ".part"

	// Determine resume offset
	var offset int64
	var resumeBase string
	if stat, err := os.Stat(partPath); err == nil {
		offset = stat.Size()
		resumeBase = partPath
	} else if stat, err := os.Stat(local); err == nil {
		offset = stat.Size()
		resumeBase = local
	}

	command := fmt.Sprintf("%s %s %s %d\n", protocol.CommandDownload, remote, mode, offset)
	if _, err := stream.Write([]byte(command)); err != nil {
		return err
	}

	// Read response: OK <remaining_size> <sha256>
	reader := bufio.NewReader(stream)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return err
	}
	status, msg := protocol.ParseResponse(strings.TrimSpace(line))
	if status != protocol.ResponseOK {
		return fmt.Errorf("server error: %s", msg)
	}

	var remainingSize int64
	var serverChecksum string
	if _, err := fmt.Sscanf(msg, "%d %s", &remainingSize, &serverChecksum); err != nil {
		return fmt.Errorf("parsing download response: %w", err)
	}

	if remainingSize == 0 {
		if serverChecksum != "" && offset > 0 {
			h := sha256.New()
			f, err := os.Open(resumeBase)
			if err != nil {
				return fmt.Errorf("opening existing file for checksum: %w", err)
			}
			if _, err := io.Copy(h, f); err != nil {
				f.Close()
				return err
			}
			f.Close()
			got := hex.EncodeToString(h.Sum(nil))
			if got != serverChecksum {
				os.Remove(local)
				os.Remove(partPath)
				return fmt.Errorf("existing file corrupted (checksum mismatch), deleted: got %s, expected %s", got, serverChecksum)
			}
		}
		fmt.Printf("Download successful: %s (checksum verified)\n", local)
		return nil
	}

	// Hash existing data for total file verification
	hasher := sha256.New()
	if offset > 0 {
		f, err := os.Open(resumeBase)
		if err != nil {
			return err
		}
		if _, err := io.Copy(hasher, f); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}

	// Open .part for appending
	partFile, err := os.OpenFile(partPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer partFile.Close()

	var dataReader io.Reader = reader
	if mode == protocol.ModeASCII {
		dataReader = protocol.ASCIIReader(reader)
	}

	// Hash incoming data while writing to .part
	multiWriter := io.MultiWriter(hasher, partFile)
	copied, err := io.CopyN(multiWriter, dataReader, remainingSize)
	if err != nil && err != io.EOF {
		partFile.Close()
		os.Remove(partPath)
		return err
	}
	if copied != remainingSize {
		partFile.Close()
		os.Remove(partPath)
		return fmt.Errorf("incomplete transfer: received %d of %d bytes", copied, remainingSize)
	}

	// Verify checksum before touching the real output file
	partFile.Close()
	computedHex := hex.EncodeToString(hasher.Sum(nil))
	if computedHex != serverChecksum {
		os.Remove(partPath)
		return fmt.Errorf("checksum mismatch: got %s, expected %s", computedHex, serverChecksum)
	}

	// Checksum OK — commit to final path
	if offset > 0 {
		src, err := os.Open(partPath)
		if err != nil {
			return fmt.Errorf("opening part file for commit: %w", err)
		}
		defer src.Close()
		dst, err := os.OpenFile(local, os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			src.Close()
			return fmt.Errorf("opening output file for commit: %w", err)
		}
		if _, err := io.Copy(dst, src); err != nil {
			src.Close()
			dst.Close()
			return fmt.Errorf("committing part to output: %w", err)
		}
		src.Close()
		dst.Close()
		os.Remove(partPath)
	} else {
		if err := os.Rename(partPath, local); err != nil {
			return fmt.Errorf("renaming part to output: %w", err)
		}
	}

	fmt.Printf("Download successful: %s (checksum verified)\n", local)
	return nil
}

func executeRemoteCommandInteractive(stream *quic.Stream, cmd string) error {
	command := fmt.Sprintf("%s %s\n", protocol.CommandCmd, cmd)
	_, err := stream.Write([]byte(command))
	if err != nil {
		return err
	}

	// Read response
	reader := bufio.NewReader(stream)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	status, msg := protocol.ParseResponse(strings.TrimSpace(statusLine))
	if status != protocol.ResponseOK {
		return fmt.Errorf("server error: %s", msg)
	}

	exitCodeLine, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	exitCode := strings.TrimSpace(exitCodeLine)

	stdoutSizeLine, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	stdoutSize, _ := strconv.ParseInt(strings.TrimSpace(stdoutSizeLine), 10, 64)

	stdoutBuf := make([]byte, stdoutSize)
	_, err = io.ReadFull(reader, stdoutBuf)
	if err != nil {
		return err
	}

	// Read stderr size - handle possible extra newline after stdout
	var stderrSizeLine string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if line != "" {
			stderrSizeLine = line
			break
		}
		// Empty line means extra newline separator, continue reading
	}
	stderrSize, _ := strconv.ParseInt(stderrSizeLine, 10, 64)

	stderrBuf := make([]byte, stderrSize)
	_, err = io.ReadFull(reader, stderrBuf)
	if err != nil {
		return err
	}

	if len(stdoutBuf) > 0 {
		os.Stdout.Write(stdoutBuf)
	}
	if len(stderrBuf) > 0 {
		os.Stderr.Write(stderrBuf)
	}

	fmt.Printf("Exit code: %s\n", exitCode)
	return nil
}

func executeRemoteExecInteractive(stream *quic.Stream, cmd string) error {
	command := fmt.Sprintf("%s %s\n", protocol.CommandExec, cmd)
	_, err := stream.Write([]byte(command))
	if err != nil {
		return err
	}

	// Read response (same as executeRemoteCommandInteractive)
	reader := bufio.NewReader(stream)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	status, msg := protocol.ParseResponse(strings.TrimSpace(statusLine))
	if status != protocol.ResponseOK {
		return fmt.Errorf("server error: %s", msg)
	}

	exitCodeLine, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	exitCode := strings.TrimSpace(exitCodeLine)

	stdoutSizeLine, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	stdoutSize, _ := strconv.ParseInt(strings.TrimSpace(stdoutSizeLine), 10, 64)

	stdoutBuf := make([]byte, stdoutSize)
	_, err = io.ReadFull(reader, stdoutBuf)
	if err != nil {
		return err
	}

	// Read stderr size - handle possible extra newline after stdout
	var stderrSizeLine string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if line != "" {
			stderrSizeLine = line
			break
		}
		// Empty line means extra newline separator, continue reading
	}
	stderrSize, _ := strconv.ParseInt(stderrSizeLine, 10, 64)

	stderrBuf := make([]byte, stderrSize)
	_, err = io.ReadFull(reader, stderrBuf)
	if err != nil {
		return err
	}

	if len(stdoutBuf) > 0 {
		os.Stdout.Write(stdoutBuf)
	}
	if len(stderrBuf) > 0 {
		os.Stderr.Write(stderrBuf)
	}

	fmt.Printf("Exit code: %s\n", exitCode)
	return nil
}
