package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/francesco/quics/internal/protocol"
	"github.com/quic-go/quic-go"
	"github.com/spf13/cobra"
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
	ExecUser               string
	ExecGroup              string
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
	serverAddr             string
	caCert                 string
	upload                 string
	download               string
	output                 string
	mode                   string
	cmdStr                 string
	execUser               string
	execGroup              string
	execCmd                string
	env                    []string
	interactive            bool
	insecure               bool
	maxIdleTimeoutSeconds  int
	keepAlivePeriodSeconds int
)

var rootCmd = &cobra.Command{
	Use:   "quicsc",
	Short: "QUIC client for file transfer and remote command execution",
	Long: `QUICS client provides secure file transfer and remote command execution
over QUIC protocol with mutual TLS authentication.`,
	PreRunE: validateConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
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
			ExecUser:               execUser,
			ExecGroup:              execGroup,
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

func init() {
	rootCmd.PersistentFlags().StringVarP(&clientCert, "client-cert", "C", "", "Path to client certificate (PEM). Default: ~/.quicsc/public.crt")
	rootCmd.PersistentFlags().StringVarP(&clientKey, "client-key", "K", "", "Path to client private key (PEM). Default: ~/.quicsc/private.key (must have 600 permissions)")
	rootCmd.PersistentFlags().StringVarP(&serverAddr, "server-addr", "s", "localhost:4242", "Server address")
	rootCmd.PersistentFlags().StringVarP(&caCert, "ca-cert", "a", "", "CA certificate to verify server (optional). Default: ~/.quicsc/ca.crt if present")
	rootCmd.PersistentFlags().StringVarP(&upload, "upload", "u", "", "Local file to upload")
	rootCmd.PersistentFlags().StringVarP(&download, "download", "d", "", "Remote file to download")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "Output path for downloaded file")
	rootCmd.PersistentFlags().StringVarP(&mode, "mode", "m", "BIN", "Transfer mode: BIN or ASCII")
	rootCmd.PersistentFlags().StringVarP(&cmdStr, "cmd", "c", "", "Remote command to execute")
	rootCmd.PersistentFlags().StringVarP(&execUser, "exec-user", "U", "", "User to run command as (use '-' for current user)")
	rootCmd.PersistentFlags().StringVarP(&execGroup, "exec-group", "G", "", "Group to run command as (use '-' for current group)")
	rootCmd.PersistentFlags().StringVarP(&execCmd, "exec-cmd", "X", "", "Command to execute with specified user/group")
	rootCmd.PersistentFlags().StringSliceVarP(&env, "env", "e", []string{}, "Environment variable in NAME=VALUE format (can be repeated)")
	rootCmd.PersistentFlags().BoolVarP(&interactive, "interactive", "i", true, "Start interactive session")
	rootCmd.PersistentFlags().BoolVarP(&insecure, "insecure", "k", false, "Skip server certificate verification")
	rootCmd.PersistentFlags().IntVarP(&maxIdleTimeoutSeconds, "max-idle-timeout", "t", 120, "Maximum idle timeout in seconds (default: 120)")
	rootCmd.PersistentFlags().IntVarP(&keepAlivePeriodSeconds, "keep-alive-period", "p", 15, "Keep-alive period in seconds (default: 15, -1 to disable)")

}

func validateConfig(cmd *cobra.Command, args []string) error {
	// Get home directory for default paths
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}
	defaultCertDir := filepath.Join(homeDir, ".quicsc")

	// Set default certificate paths if not provided
	if clientCert == "" || clientKey == "" {
		defaultCert := filepath.Join(defaultCertDir, "public.crt")
		defaultKey := filepath.Join(defaultCertDir, "private.key")

		if clientCert == "" {
			if _, err := os.Stat(defaultCert); err == nil {
				clientCert = defaultCert
			}
		}

		if clientKey == "" {
			if _, err := os.Stat(defaultKey); err == nil {
				clientKey = defaultKey
				// Check private key permissions (must be 600)
				info, err := os.Stat(defaultKey)
				if err == nil {
					perm := info.Mode().Perm()
					if perm != 0600 {
						return fmt.Errorf("private key file %s must have permissions 600 (rw-------), got %o", defaultKey, perm)
					}
				}
			}
		}
	}

	// Set default CA certificate if not provided
	if caCert == "" {
		defaultCA := filepath.Join(defaultCertDir, "ca.crt")
		if _, err := os.Stat(defaultCA); err == nil {
			caCert = defaultCA
		}
	}

	// After checking defaults, still validate that we have certificates
	if clientCert == "" || clientKey == "" {
		return fmt.Errorf("client certificate and key are required (provide via --client-cert/--client-key or place in ~/.quicsc/public.crt and ~/.quicsc/private.key)")
	}

	// Check that certificate files exist and are readable
	if _, err := os.Stat(clientCert); err != nil {
		return fmt.Errorf("client certificate file %s not found or not readable: %w", clientCert, err)
	}
	if _, err := os.Stat(clientKey); err != nil {
		return fmt.Errorf("client key file %s not found or not readable: %w", clientKey, err)
	}

	// Validate private key permissions (must be 600)
	info, err := os.Stat(clientKey)
	if err != nil {
		return fmt.Errorf("failed to stat private key file: %w", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		return fmt.Errorf("private key file %s must have permissions 600 (rw-------), got %o", clientKey, perm)
	}

	// Validate that at least one operation is specified
	// Note: interactive defaults to true, so this will only fail if explicitly set to false
	if upload == "" && download == "" && cmdStr == "" && execCmd == "" && !interactive {
		return fmt.Errorf("at least one of --upload, --download, --cmd, --exec-cmd, or --interactive must be specified")
	}

	// Validate exec parameters: if any exec flag is set, all three must be set
	if (execUser != "" || execGroup != "" || execCmd != "") && (execUser == "" || execGroup == "" || execCmd == "") {
		return fmt.Errorf("--exec-user, --exec-group, and --exec-cmd must all be specified together")
	}

	if mode != "BIN" && mode != "ASCII" {
		return fmt.Errorf("mode must be BIN or ASCII")
	}

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runClient(config *ClientConfig) error {
	cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
	if err != nil {
		return fmt.Errorf("loading client certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{"quic-file-transfer"},
		InsecureSkipVerify: config.Insecure,
	}

	if config.CACert != "" {
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

	fmt.Printf("QUIC config: idle_timeout=%v, keepalive=%v\n",
		idleTimeout, keepAlive)
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
	command := fmt.Sprintf("%s %s %d %s\n", protocol.CommandUpload, filename, size, config.Mode)
	_, err = stream.Write([]byte(command))
	if err != nil {
		return fmt.Errorf("sending command: %w", err)
	}

	var reader io.Reader = file
	var writer io.Writer = stream
	if config.Mode == protocol.ModeASCII {
		writer = protocol.ASCIIWriter(stream)
	}

	_, err = io.Copy(writer, reader)
	if err != nil {
		return fmt.Errorf("sending file data: %w", err)
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		return fmt.Errorf("reading response: %w", err)
	}

	response := string(buf[:n])
	status, msg := protocol.ParseResponse(response)
	if status != protocol.ResponseOK {
		return fmt.Errorf("server error: %s", msg)
	}

	fmt.Printf("Upload successful: %s\n", msg)
	return nil
}

func handleDownload(stream *quic.Stream, config *ClientConfig) error {
	filename := config.Download
	outputPath := config.Output
	if outputPath == "" {
		outputPath = filename
	}

	command := fmt.Sprintf("%s %s %s\n", protocol.CommandDownload, filename, config.Mode)
	_, err := stream.Write([]byte(command))
	if err != nil {
		return fmt.Errorf("sending command: %w", err)
	}

	// Read response
	reader := bufio.NewReader(stream)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("reading response: %w", err)
	}

	status, msg := protocol.ParseResponse(strings.TrimSpace(line))
	if status != protocol.ResponseOK {
		return fmt.Errorf("server error: %s", msg)
	}

	// Parse size from response message
	var size int64
	fmt.Sscanf(msg, "%d", &size)

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer file.Close()

	var writer io.Writer = file
	var dataReader io.Reader = reader
	if config.Mode == protocol.ModeASCII {
		dataReader = protocol.ASCIIReader(reader)
	}

	copied, err := io.CopyN(writer, dataReader, size)
	if err != nil && err != io.EOF {
		return fmt.Errorf("receiving file data: %w", err)
	}
	if err == io.EOF && copied < size {
		return fmt.Errorf("incomplete transfer: received %d of %d bytes", copied, size)
	}

	fmt.Printf("Download successful: %s (%d bytes, received %d)\n", outputPath, size, copied)
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

	// Send EXEC command
	cmdStr := fmt.Sprintf("%s %s %s %s\n", protocol.CommandExec, config.ExecUser, config.ExecGroup, config.ExecCmd)
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
			if len(args) < 3 {
				fmt.Println("Usage: exec <user> <group> <command>")
				continue
			}
			user := args[0]
			group := args[1]
			command := strings.Join(args[2:], " ")
			err := executeRemoteExecInteractive(stream, user, group, command)
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
	fmt.Println("  exec <user> <group> <cmd> Execute command as user/group")
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

	command := fmt.Sprintf("%s %s %d %s\n", protocol.CommandUpload, remote, size, mode)
	_, err = stream.Write([]byte(command))
	if err != nil {
		return err
	}

	var reader io.Reader = file
	var writer io.Writer = stream
	if mode == protocol.ModeASCII {
		writer = protocol.ASCIIWriter(stream)
	}

	_, err = io.Copy(writer, reader)
	if err != nil {
		return err
	}

	// Read response
	responseReader := bufio.NewReader(stream)
	line, err := responseReader.ReadString('\n')
	if err != nil && err != io.EOF {
		return err
	}
	status, msg := protocol.ParseResponse(strings.TrimSpace(line))
	if status != protocol.ResponseOK {
		return fmt.Errorf("server error: %s", msg)
	}
	fmt.Printf("Upload successful: %s\n", msg)
	return nil
}

func downloadFileInteractive(stream *quic.Stream, remote, local, mode string) error {
	command := fmt.Sprintf("%s %s %s\n", protocol.CommandDownload, remote, mode)
	_, err := stream.Write([]byte(command))
	if err != nil {
		return err
	}

	// Read response
	reader := bufio.NewReader(stream)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return err
	}
	status, msg := protocol.ParseResponse(strings.TrimSpace(line))
	if status != protocol.ResponseOK {
		return fmt.Errorf("server error: %s", msg)
	}

	var size int64
	fmt.Sscanf(msg, "%d", &size)

	file, err := os.Create(local)
	if err != nil {
		return err
	}
	defer file.Close()

	var writer io.Writer = file
	var dataReader io.Reader = reader
	if mode == protocol.ModeASCII {
		dataReader = protocol.ASCIIReader(reader)
	}

	copied, err := io.CopyN(writer, dataReader, size)
	if err != nil && err != io.EOF {
		return err
	}
	if err == io.EOF && copied < size {
		return fmt.Errorf("incomplete transfer: received %d of %d bytes", copied, size)
	}
	fmt.Printf("Download successful: %s (%d bytes, received %d)\n", local, size, copied)
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

func executeRemoteExecInteractive(stream *quic.Stream, user, group, cmd string) error {
	command := fmt.Sprintf("%s %s %s %s\n", protocol.CommandExec, user, group, cmd)
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
