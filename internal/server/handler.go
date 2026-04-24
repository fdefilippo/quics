package server

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fdefilippo/quics/internal/logging"
	"github.com/fdefilippo/quics/internal/protocol"
	"github.com/fdefilippo/quics/internal/webhook"
	"github.com/quic-go/quic-go"
)

type Server struct {
	config   *Config
	logger   *logging.Logger
	notifier webhook.Notifier
}

type IdentityConfig struct {
	MapClientCNToLocalUser   bool
	RejectIfLocalUserMissing bool
}

type StorageConfig struct {
	Mode           string
	RootDir        string
	UserRootPolicy string
	UserSubdir     string
}

type Config struct {
	IdentityConfig *IdentityConfig
	StorageConfig  *StorageConfig
	StorageRoot    string
	ShellConfig    *ShellConfig
}

type ShellConfig struct {
	Enabled          bool
	AllowedCommands  []string
	MaxExecutionTime int
	AllowedEnvVars   []string
}

type Session struct {
	CertIdentity string
	LocalUser    string
	Uid          int
	Gid          int
	HomeDir      string
	JailHomeDir  string
	Shell        string
	RootDir      string
	EnvVars      []string
}

// Copy returns a deep copy of the Session for per-stream isolation.
func (s *Session) Copy() *Session {
	envCopy := make([]string, len(s.EnvVars))
	copy(envCopy, s.EnvVars)
	return &Session{
		CertIdentity: s.CertIdentity,
		LocalUser:    s.LocalUser,
		Uid:          s.Uid,
		Gid:          s.Gid,
		HomeDir:      s.HomeDir,
		JailHomeDir:  s.JailHomeDir,
		Shell:        s.Shell,
		RootDir:      s.RootDir,
		EnvVars:      envCopy,
	}
}

// isRegexPattern returns true if the pattern contains regex metacharacters.
func isRegexPattern(pattern string) bool {
	// List of regex metacharacters that indicate a regex pattern
	metachars := []string{"^", "$", ".", "*", "+", "?", "(", ")", "[", "]", "{", "}", "|", "\\"}
	for _, ch := range metachars {
		if strings.Contains(pattern, ch) {
			return true
		}
	}
	return false
}

// matchesCommand checks if a command matches an allowed pattern.
// Patterns containing regex metacharacters are treated as regex, otherwise as exact match.
func matchesCommand(pattern, cmd string) bool {
	if isRegexPattern(pattern) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			// If pattern is invalid regex, fall back to exact match
			return pattern == cmd
		}
		return re.MatchString(cmd)
	}
	// No regex metacharacters, treat as exact match
	return pattern == cmd
}

// resolveLocalUser resolves a username to user information using getent passwd.
// It uses getent to respect NSS (LDAP, SSSD, NIS) on Linux.
func resolveLocalUser(username string) (uid int, gid int, homeDir, shell string, err error) {
	out, err := exec.Command("getent", "passwd", username).Output()
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("user %s not found on local system", username)
	}
	// passwd entry: name:password:uid:gid:gecos:home:shell
	parts := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(parts) < 7 {
		return 0, 0, "", "", fmt.Errorf("malformed passwd entry for %s", username)
	}
	uidInt, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("invalid uid for %s: %w", username, err)
	}
	gidInt, err := strconv.Atoi(parts[3])
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("invalid gid for %s: %w", username, err)
	}
	return uidInt, gidInt, parts[5], parts[6], nil
}

// computeRootDir calculates the effective virtual root for a session based on config.
func computeRootDir(sc *StorageConfig, homeDir, localUser string) (string, error) {
	var root string
	switch sc.UserRootPolicy {
	case "home":
		root = homeDir
		if sc.UserSubdir != "" {
			root = filepath.Join(root, sc.UserSubdir)
		}
	case "subdir":
		root = filepath.Join(sc.RootDir, localUser)
		if sc.UserSubdir != "" {
			root = filepath.Join(root, sc.UserSubdir)
		}
	default:
		return "", fmt.Errorf("unknown user_root_policy: %s", sc.UserRootPolicy)
	}
	// Ensure the root exists
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", fmt.Errorf("creating root directory %s: %w", root, err)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolving root directory: %w", err)
	}
	return absRoot, nil
}

// chownToSession attempts to change ownership of a file to the session user.
// It only succeeds when running as root or with CAP_CHOWN. Permission errors
// are silently ignored (the server process may not have privileges).
func chownToSession(path string, uid, gid int, logger *logging.Logger) {
	if err := os.Chown(path, uid, gid); err != nil && !os.IsPermission(err) {
		logger.Warnw("failed to chown", "path", path, "uid", uid, "gid", gid, "error", err)
	}
}

func hasEffectiveCapability(bit uint) bool {
	if os.Geteuid() == 0 {
		return true
	}
	if runtime.GOOS != "linux" {
		return false
	}

	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return false
		}
		var capEff uint64
		fmt.Sscanf(parts[1], "%x", &capEff)
		return (capEff & (1 << bit)) != 0
	}

	return false
}

// hasRequiredCapabilities returns true if the process has permission to set UID and/or GID.
// Returns true if running as root (euid == 0) or if the required capabilities are present.
// needUID and needGID indicate which capabilities are required.
func hasRequiredCapabilities(needUID, needGID bool) bool {
	if needUID && !hasEffectiveCapability(7) {
		return false
	}
	if needGID && !hasEffectiveCapability(6) {
		return false
	}
	return true
}

func NewServer(config *Config, notifier webhook.Notifier, logger *logging.Logger) *Server {
	if logger == nil {
		logger = logging.NewLogger("info", os.Stdout)
	}
	return &Server{config: config, logger: logger, notifier: notifier}
}

// NewSession creates a session from a client certificate Common Name.
// It resolves the local user, computes the virtual root, and validates
// that the mapping is valid. Returns an error if the user does not exist
// or the root cannot be determined.
func (s *Server) NewSession(cn string) (*Session, error) {
	if cn == "" {
		return nil, fmt.Errorf("empty client certificate CN")
	}
	if !s.config.IdentityConfig.MapClientCNToLocalUser {
		return &Session{
			CertIdentity: cn,
			LocalUser:    cn,
			RootDir:      s.config.StorageRoot,
		}, nil
	}
	uid, gid, homeDir, shell, err := resolveLocalUser(cn)
	if err != nil {
		if s.config.IdentityConfig.RejectIfLocalUserMissing {
			return nil, fmt.Errorf("user %s not found on local system: %w", cn, err)
		}
		return &Session{
			CertIdentity: cn,
			LocalUser:    cn,
			RootDir:      s.config.StorageRoot,
		}, nil
	}
	rootDir, err := computeRootDir(s.config.StorageConfig, homeDir, cn)
	if err != nil {
		return nil, fmt.Errorf("computing root directory for %s: %w", cn, err)
	}
	// Ensure root directory is owned by the mapped user
	chownToSession(rootDir, uid, gid, s.logger)
	return &Session{
		CertIdentity: cn,
		LocalUser:    cn,
		Uid:          uid,
		Gid:          gid,
		HomeDir:      homeDir,
		JailHomeDir:  "/",
		Shell:        shell,
		RootDir:      rootDir,
	}, nil
}

// notify sends a webhook notification asynchronously
func (s *Server) notify(action string, sess *Session, success bool, errMsg string, details map[string]interface{}) {
	if s.notifier == nil {
		return
	}
	identity := sess.CertIdentity
	if identity == "" {
		identity = sess.LocalUser
	}
	s.notifier.Notify(action, identity, success, errMsg, details)
}

// writeErrorResponse writes an error response to the stream and logs the error
func (s *Server) writeErrorResponse(stream *quic.Stream, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	s.logger.Warnw("Writing error response", "error", msg)
	stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, msg)))
}

func resolveStoragePath(root, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty filename")
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("absolute paths are not allowed")
	}

	cleanName := filepath.Clean(name)
	if cleanName == "." || cleanName == ".." {
		return "", fmt.Errorf("invalid filename")
	}

	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolving storage root: %w", err)
	}
	targetAbs, err := filepath.Abs(filepath.Join(rootAbs, cleanName))
	if err != nil {
		return "", fmt.Errorf("resolving target path: %w", err)
	}

	if targetAbs != rootAbs && !strings.HasPrefix(targetAbs, rootAbs+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes storage root")
	}
	if err := ensureNoSymlinkComponents(rootAbs, cleanName); err != nil {
		return "", err
	}

	return targetAbs, nil
}

func ensureNoSymlinkComponents(rootAbs, relPath string) error {
	if relPath == "" || relPath == "." {
		return nil
	}

	cur := rootAbs
	for _, part := range strings.Split(relPath, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("checking path component %s: %w", cur, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink path components are not allowed: %s", cur)
		}
	}

	return nil
}

func splitCommand(command string) ([]string, error) {
	args := strings.Fields(command)
	if len(args) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	return args, nil
}

func buildSessionEnv(sess *Session) []string {
	const defaultPATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	jailHome := sess.JailHomeDir
	if jailHome == "" {
		jailHome = "/"
	}

	env := []string{
		fmt.Sprintf("HOME=%s", jailHome),
		fmt.Sprintf("USER=%s", sess.LocalUser),
		fmt.Sprintf("LOGNAME=%s", sess.LocalUser),
		fmt.Sprintf("SHELL=%s", sess.Shell),
	}

	pathSet := false
	for _, envVar := range sess.EnvVars {
		if strings.HasPrefix(envVar, "PATH=") {
			pathSet = true
		}
		env = append(env, envVar)
	}
	if !pathSet {
		env = append(env, "PATH="+defaultPATH)
	}

	return env
}

func resolveExecutableInRoot(command string, env []string, rootDir string) (string, error) {
	pathValue := ""
	for _, envVar := range env {
		if strings.HasPrefix(envVar, "PATH=") {
			pathValue = strings.TrimPrefix(envVar, "PATH=")
			break
		}
	}

	checkExec := func(jailPath string) (string, error) {
		if !path.IsAbs(jailPath) {
			jailPath = "/" + jailPath
		}
		hostPath, err := resolveStoragePath(rootDir, strings.TrimPrefix(jailPath, "/"))
		if err != nil {
			return "", err
		}
		info, err := os.Stat(hostPath)
		if err != nil {
			if os.IsNotExist(err) {
				return "", os.ErrNotExist
			}
			return "", err
		}
		if info.IsDir() {
			return "", fmt.Errorf("executable is a directory: %s", jailPath)
		}
		if info.Mode()&0111 == 0 {
			return "", fmt.Errorf("executable is not executable: %s", jailPath)
		}
		return jailPath, nil
	}

	if strings.Contains(command, "/") {
		jailPath := path.Clean("/" + strings.TrimPrefix(command, "/"))
		execPath, err := checkExec(jailPath)
		if err != nil {
			return "", fmt.Errorf("resolving executable %s in virtual root: %w", command, err)
		}
		return execPath, nil
	}

	for _, dir := range filepath.SplitList(pathValue) {
		if dir == "" {
			continue
		}
		jailPath := path.Join(dir, command)
		execPath, err := checkExec(jailPath)
		if err == nil {
			return execPath, nil
		}
		if err != nil && err != os.ErrNotExist {
			return "", err
		}
	}

	return "", fmt.Errorf("command %q not found inside virtual root", command)
}

func (s *Server) HandleStream(stream *quic.Stream, sess *Session) error {
	defer stream.Close()

	reader := bufio.NewReader(stream)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading command: %w", err)
		}

		cmd, err := protocol.ParseCommand(line)
		if err != nil {
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, err.Error())))
			return err
		}
		fmt.Printf("Handling command: %s, args: %v, size: %d, mode: %s\n", cmd.Type, cmd.Args, cmd.Size, cmd.Mode)

		switch cmd.Type {
		case protocol.CommandUpload, protocol.CommandPut:
			if err := s.handleUpload(stream, cmd, sess, reader); err != nil {
				return err
			}
		case protocol.CommandDownload, protocol.CommandGet:
			if err := s.handleDownload(stream, cmd, sess); err != nil {
				return err
			}
		case protocol.CommandCmd:
			if err := s.handleCommand(stream, cmd, sess); err != nil {
				return err
			}
		case protocol.CommandExec:
			if err := s.handleExec(stream, cmd, sess); err != nil {
				return err
			}
		case protocol.CommandEnv:
			if err := s.handleEnv(stream, cmd, sess); err != nil {
				return err
			}
		default:
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "unknown command")))
			return fmt.Errorf("unknown command type: %s", cmd.Type)
		}
	}
}

	func (s *Server) handleUpload(stream *quic.Stream, cmd *protocol.Command, sess *Session, reader *bufio.Reader) error {
	filename := cmd.Args[0]
	filePath, err := resolveStoragePath(sess.RootDir, filename)
	if err != nil {
		errMsg := fmt.Sprintf("invalid filename: %v", err)
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, errMsg)))
		s.notify("upload", sess, false, errMsg, map[string]interface{}{
			"filename": filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode,
		})
		s.logger.Warnw("Invalid filename", 
			"error", err,
			"filename", filename,
			"size", cmd.Size,
			"mode", cmd.Mode)
		return nil
	}

	partPath := filePath + ".part"

	var offset int64
	if stat, err := os.Stat(partPath); err == nil {
		offset = stat.Size()
	}

	if offset >= cmd.Size {
		// .part already has the full size: validate and finalize, but keep
		// the wire protocol consistent by returning the numeric offset first.
	stream.Write([]byte(protocol.BuildResponse(protocol.ResponseOK, fmt.Sprintf("%d", offset))))
	s.logger.Debugw("Upload offset response", 
		"filename", filename,
		"offset", offset)

	if cmd.Checksum != "" {
		if err := protocol.VerifyChecksum(partPath, cmd.Checksum); err != nil {
			os.Remove(partPath)
			s.writeErrorResponse(stream, "checksum mismatch on resumed file")
			s.notify("upload", sess, false, "checksum mismatch on resumed file", map[string]interface{}{
				"filename": filename,
				"size":     cmd.Size,
				"mode":     cmd.Mode,
			})
			s.logger.Warnw("Checksum mismatch on resumed file", 
				"filename", filename,
				"size", cmd.Size,
				"mode": cmd.Mode,
				"expected_checksum", cmd.Checksum)
			return nil
		}
		s.logger.Debugw("Checksum verified on resumed file", 
			"filename", filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode)
	}
		s.logger.Debugw("Checksum verified on resumed file", 
			"filename", filename,
			"size", cmd.Size,
			"mode", cmd.Mode)
	}
	if err := os.Rename(partPath, filePath); err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to finalize: %v", err))))
		s.notify("upload", sess, false, err.Error(), map[string]interface{}{
			"filename": filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode,
		})
		return err
	}
	chownToSession(filePath, sess.Uid, sess.Gid, s.logger)
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseOK, fmt.Sprintf("upload complete (resumed, checksum verified)"))))
		s.notify("upload", sess, true, "", map[string]interface{}{
			"filename": filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode,
		})
		return nil
	}

	stream.Write([]byte(protocol.BuildResponse(protocol.ResponseOK, fmt.Sprintf("%d", offset))))

	dir := filepath.Dir(partPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to create directory: %v", err))))
		s.notify("upload", sess, false, err.Error(), map[string]interface{}{
			"filename": filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode,
		})
		s.logger.Errorw("Failed to create directory", 
			"error", err,
			"directory", dir,
			"filename", filename)
		return err
	}
	chownToSession(dir, sess.Uid, sess.Gid, s.logger)
	s.logger.Debugw("Directory created", 
		"directory", dir,
		"filename", filename)

	var file *os.File
	if offset > 0 {
		file, err = os.OpenFile(partPath, os.O_WRONLY|os.O_APPEND, 0644)
	} else {
		file, err = os.Create(partPath)
	}
	if err != nil {
		s.writeErrorResponse(stream, "invalid filename: %v", err)
		s.notify("upload", sess, false, errMsg, map[string]interface{}{
			"filename": filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode,
		})
		return nil
	}
	defer file.Close()
	chownToSession(partPath, sess.Uid, sess.Gid, s.logger)

	var writer io.Writer = file
	var dataReader io.Reader = reader
	if cmd.Mode == protocol.ModeASCII {
		dataReader = protocol.ASCIIReader(reader)
	}

	remaining := cmd.Size - offset
	written, err := io.CopyN(writer, dataReader, remaining)
	if err != nil && err != io.EOF {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to write file: %v", err))))
		s.notify("upload", sess, false, err.Error(), map[string]interface{}{
			"filename": filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode,
		})
		return err
	}

	if written != remaining {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("incomplete transfer: expected %d bytes, got %d", remaining, written))))
		s.notify("upload", sess, false, fmt.Sprintf("incomplete transfer: expected %d bytes, got %d", remaining, written), map[string]interface{}{
			"filename": filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode,
			"written":  written,
		})
		s.logger.Errorw("Incomplete transfer", 
			"filename", filename,
			"expected", remaining,
			"written", written)
		return fmt.Errorf("incomplete transfer")
	}

// Verify checksum if provided
	if cmd.Checksum != "" {
		if err := protocol.VerifyChecksum(partPath, cmd.Checksum); err != nil {
			os.Remove(partPath)
			s.writeErrorResponse(stream, "checksum mismatch"))
			s.notify("upload", sess, false, "checksum mismatch", map[string]interface{}{
				"filename": filename,
				"size":     cmd.Size,
				"mode":     cmd.Mode,
			})
			return nil
		}
		s.logger.Debugw("Checksum verified on resumed file", 
			"filename", filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode)
	}
		s.logger.Debugw("Checksum verified on resumed file", 
			"filename", filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode)
	}
	}

	// Rename .part to final name
	if err := os.Rename(partPath, filePath); err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to finalize file: %v", err))))
		s.notify("upload", sess, false, err.Error(), map[string]interface{}{
			"filename": filename,
			"size":     cmd.Size,
			"mode":     cmd.Mode,
		})
		return err
	}
	chownToSession(filePath, sess.Uid, sess.Gid, s.logger)

	stream.Write([]byte(protocol.BuildResponse(protocol.ResponseOK, fmt.Sprintf("%d bytes written", written))))
	s.notify("upload", sess, true, "", map[string]interface{}{
		"filename": filename,
		"size":     cmd.Size,
		"mode":     cmd.Mode,
		"written":  written,
	})
	return nil
}



func (s *Server) handleDownload(stream *quic.Stream, cmd *protocol.Command, sess *Session) error {
	filename := cmd.Args[0]
	filePath, err := resolveStoragePath(sess.RootDir, filename)
	if err != nil {
		errMsg := fmt.Sprintf("invalid filename: %v", err)
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, errMsg)))
		s.notify("download", sess, false, errMsg, map[string]interface{}{
			"filename": filename,
			"mode":     cmd.Mode,
		})
		return nil
	}
	s.logger.Debugw("Download request", 
		"filename", filename,
		"path", filePath)

	file, err := os.Open(filePath)
	if err != nil {
		var errMsg string
		if os.IsNotExist(err) {
			errMsg = "file not found"
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, errMsg)))
		} else {
			errMsg = fmt.Sprintf("failed to open file: %v", err)
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, errMsg)))
		}
		s.notify("download", sess, false, errMsg, map[string]interface{}{
			"filename": filename,
			"mode":     cmd.Mode,
		})
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to stat file: %v", err))))
		s.notify("download", sess, false, fmt.Sprintf("failed to stat file: %v", err), map[string]interface{}{
			"filename": filename,
			"mode":     cmd.Mode,
		})
		s.logger.Errorw("Failed to stat file", 
			"error", err,
			"filename", filename,
			"path", filePath)
		return err
	}
	size := stat.Size()

	// Validate offset
	offset := cmd.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > size {
		offset = size
	}
	remainingSize := size - offset

	// Compute SHA-256 of the entire file
	hasher := sha256.New()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to seek: %v", err))))
		return err
	}
	if _, err := io.Copy(hasher, file); err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to compute checksum: %v", err))))
		return err
	}
	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Seek to requested offset for sending
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to seek: %v", err))))
		return err
	}

	response := fmt.Sprintf("%s %d %s\n", protocol.ResponseOK, remainingSize, checksum)
	fmt.Printf("Sending response: %s", response)
	stream.Write([]byte(response))

	var reader io.Reader = file
	var writer io.Writer = stream
	if cmd.Mode == protocol.ModeASCII {
		writer = protocol.ASCIIWriter(stream)
	}

	n, err := io.CopyN(writer, reader, remainingSize)
	if err != nil {
		s.notify("download", sess, false, fmt.Sprintf("failed to send file: %v", err), map[string]interface{}{
			"filename": filename,
			"mode":     cmd.Mode,
			"size":     size,
		})
		return fmt.Errorf("failed to send file: %w", err)
	}
	fmt.Printf("File sent successfully, size: %d, offset: %d, sent: %d\n", size, offset, n)
	s.notify("download", sess, true, "", map[string]interface{}{
		"filename": filename,
		"mode":     cmd.Mode,
		"size":     size,
		"offset":   offset,
		"sent":     n,
	})
	return nil
}

func validateCommandPathArgs(args []string, rootDir string) error {
	for i, arg := range args {
		if i == 0 {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if arg == "." {
			continue
		}
		if arg == ".." || strings.HasPrefix(arg, "../") || strings.Contains(arg, "/../") || strings.HasSuffix(arg, "/..") {
			return fmt.Errorf("path traversal denied: %s", arg)
		}
		if filepath.IsAbs(arg) {
			return fmt.Errorf("absolute paths denied: %s", arg)
		}
		if strings.Contains(arg, "/") {
			cleanPath := filepath.Clean(filepath.Join(rootDir, arg))
			rootClean := filepath.Clean(rootDir)
			if !strings.HasPrefix(cleanPath, rootClean+string(os.PathSeparator)) && cleanPath != rootClean {
				return fmt.Errorf("path escapes root: %s", arg)
			}
		}
	}
	return nil
}

func (s *Server) handleCommand(stream *quic.Stream, cmd *protocol.Command, sess *Session) error {
	if !s.config.ShellConfig.Enabled {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "shell execution is disabled")))
		s.notify("command", sess, false, "shell execution is disabled", map[string]interface{}{
			"command": strings.Join(cmd.Args, " "),
		})
		return nil
	}

	// Split command into arguments (safe split, no shell interpretation)
	cmdStr := strings.Join(cmd.Args, " ")
	args, err := splitCommand(cmdStr)
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, err.Error())))
		return nil
	}

	// Check command against whitelist
	allowed := s.config.ShellConfig.AllowedCommands
	if len(allowed) > 0 {
		baseCmd := args[0]
		found := false
		for _, pattern := range allowed {
			if matchesCommand(pattern, baseCmd) {
				found = true
				break
			}
		}
		if !found {
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("command not allowed: %s", baseCmd))))
			return nil
		}
	}

	// Validate arguments against virtual root escape
	if err := validateCommandPathArgs(args, sess.RootDir); err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, err.Error())))
		s.notify("command", sess, false, err.Error(), map[string]interface{}{
			"command": cmdStr,
		})
		return nil
	}

	// Use session's uid/gid (derived from CN -> local user mapping)
	uid := sess.Uid
	gid := sess.Gid

	// Check if we need to change uid/gid
	currentUid := syscall.Geteuid()
	currentGid := syscall.Getegid()
	needUID := uid != currentUid
	needGID := gid != currentGid
	if (needUID || needGID) && !hasRequiredCapabilities(needUID, needGID) {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "insufficient privileges to set UID/GID (not root and missing required capabilities)")))
		return nil
	}
	if !hasEffectiveCapability(18) {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "insufficient privileges to chroot into virtual root")))
		return nil
	}

	// Build environment inside the jail and resolve the executable there.
	env := buildSessionEnv(sess)
	execPath, err := resolveExecutableInRoot(args[0], env, sess.RootDir)
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, err.Error())))
		s.notify("command", sess, false, err.Error(), map[string]interface{}{
			"command": cmdStr,
		})
		return nil
	}

	// Execute command with timeout (no shell)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.ShellConfig.MaxExecutionTime)*time.Second)
	defer cancel()

	fmt.Printf("Executing command: %s (args: %v, exec: %s)\n", cmdStr, args, execPath)
	execCmd := exec.CommandContext(ctx, execPath, args[1:]...)
	execCmd.Env = env
	execCmd.Dir = "/"

	// Chroot into the session root so filesystem access is truly jailed.
	execCmd.SysProcAttr = &syscall.SysProcAttr{
		Chroot: sess.RootDir,
	}
	if needUID || needGID {
		execCmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		}
	}

	stdout, err := execCmd.StdoutPipe()
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to create stdout pipe: %v", err))))
		s.notify("command", sess, false, fmt.Sprintf("failed to create stdout pipe: %v", err), map[string]interface{}{
			"command": cmdStr,
		})
		return nil // Don't return error to keep stream open
	}
	stderr, err := execCmd.StderrPipe()
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to create stderr pipe: %v", err))))
		return nil // Don't return error to keep stream open
	}

	if err := execCmd.Start(); err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to start command: %v", err))))
		return nil // Don't return error to keep stream open
	}

	// Read stdout and stderr concurrently
	var stdoutBuf, stderrBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(&stdoutBuf, stdout)
	}()
	go func() {
		defer wg.Done()
		io.Copy(&stderrBuf, stderr)
	}()
	wg.Wait()

	err = execCmd.Wait()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	// Send response according to protocol: OK\n<exit_code>\n<stdout_size>\n<stdout>\n<stderr_size>\n<stderr>
	response := fmt.Sprintf("%s\n%d\n%d\n%s\n%d\n%s", protocol.ResponseOK, exitCode, stdoutBuf.Len(), stdoutBuf.String(), stderrBuf.Len(), stderrBuf.String())
	fmt.Printf("Sending command response, exit code: %d, stdout: %d bytes, stderr: %d bytes\n", exitCode, stdoutBuf.Len(), stderrBuf.Len())
	_, err = stream.Write([]byte(response))
	if err != nil {
		fmt.Printf("Failed to send response: %v\n", err)
		return nil // Don't return error to keep stream open
	}

	sess.EnvVars = nil
	return nil
}

func (s *Server) handleExec(stream *quic.Stream, cmd *protocol.Command, sess *Session) error {
	if !s.config.ShellConfig.Enabled {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "shell execution is disabled")))
		s.notify("exec", sess, false, "shell execution is disabled", map[string]interface{}{
			"command": strings.Join(cmd.Args, " "),
		})
		return nil
	}

	// Parse arguments: command only (user/group derived from session)
	if len(cmd.Args) < 1 || cmd.Args[0] == "" {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "EXEC requires a command")))
		s.notify("exec", sess, false, "EXEC requires a command", nil)
		return nil
	}
	commandStr := cmd.Args[0]

	// Check if we're on Linux
	if runtime.GOOS != "linux" {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "EXEC is only supported on Linux")))
		s.notify("exec", sess, false, "EXEC is only supported on Linux", map[string]interface{}{
			"command": commandStr,
		})
		return nil
	}

	// Use session's uid/gid (derived from CN -> local user mapping)
	uid := sess.Uid
	gid := sess.Gid

	// Check if we need to change uid/gid
	currentUid := syscall.Geteuid()
	currentGid := syscall.Getegid()
	needUID := uid != currentUid
	needGID := gid != currentGid
	if (needUID || needGID) && !hasRequiredCapabilities(needUID, needGID) {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "insufficient privileges to set UID/GID (not root and missing required capabilities)")))
		return nil
	}
	if !hasEffectiveCapability(18) {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, "insufficient privileges to chroot into virtual root")))
		return nil
	}

	// Split command into arguments (safe split, no shell interpretation)
	args, err := splitCommand(commandStr)
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, err.Error())))
		return nil
	}

	// Check command against whitelist
	allowed := s.config.ShellConfig.AllowedCommands
	if len(allowed) > 0 {
		baseCmd := args[0]
		found := false
		for _, pattern := range allowed {
			if matchesCommand(pattern, baseCmd) {
				found = true
				break
			}
		}
		if !found {
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("command not allowed: %s", baseCmd))))
			return nil
		}
	}

	// Validate arguments against virtual root escape
	if err := validateCommandPathArgs(args, sess.RootDir); err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, err.Error())))
		s.notify("exec", sess, false, err.Error(), map[string]interface{}{
			"command": commandStr,
		})
		return nil
	}

	// Build environment inside the jail and resolve the executable there.
	env := buildSessionEnv(sess)
	execPath, err := resolveExecutableInRoot(args[0], env, sess.RootDir)
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, err.Error())))
		s.notify("exec", sess, false, err.Error(), map[string]interface{}{
			"command": commandStr,
		})
		return nil
	}

	// Execute command with timeout (no shell)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.ShellConfig.MaxExecutionTime)*time.Second)
	defer cancel()

	fmt.Printf("Executing command as uid=%d gid=%d: %s (args: %v, exec: %s)\n", uid, gid, commandStr, args, execPath)
	execCmd := exec.CommandContext(ctx, execPath, args[1:]...)
	execCmd.Env = env
	execCmd.Dir = "/"

	// Chroot into the session root so filesystem access is truly jailed.
	execCmd.SysProcAttr = &syscall.SysProcAttr{
		Chroot: sess.RootDir,
	}
	if needUID || needGID {
		execCmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		}
	}

	stdout, err := execCmd.StdoutPipe()
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to create stdout pipe: %v", err))))
		return nil
	}
	stderr, err := execCmd.StderrPipe()
	if err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to create stderr pipe: %v", err))))
		return nil
	}

	if err := execCmd.Start(); err != nil {
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, fmt.Sprintf("failed to start command: %v", err))))
		return nil
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(&stdoutBuf, stdout)
	}()
	go func() {
		defer wg.Done()
		io.Copy(&stderrBuf, stderr)
	}()
	wg.Wait()

	err = execCmd.Wait()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	response := fmt.Sprintf("%s\n%d\n%d\n%s\n%d\n%s", protocol.ResponseOK, exitCode, stdoutBuf.Len(), stdoutBuf.String(), stderrBuf.Len(), stderrBuf.String())
	_, err = stream.Write([]byte(response))
	if err != nil {
		return nil
	}

	sess.EnvVars = nil
	return nil
}

func (s *Server) handleEnv(stream *quic.Stream, cmd *protocol.Command, sess *Session) error {
	envVar := cmd.Args[0]
	fmt.Printf("Setting environment variable: %s\n", envVar)
	parts := strings.SplitN(envVar, "=", 2)
	if len(parts) != 2 {
		errMsg := "invalid format, use NAME=VALUE"
		stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, errMsg)))
		s.notify("env", sess, false, errMsg, map[string]interface{}{
			"envVar": envVar,
		})
		return nil
	}
	name := parts[0]
	value := parts[1]

	// Check if variable is allowed
	allowed := s.config.ShellConfig.AllowedEnvVars
	if len(allowed) > 0 {
		found := false
		for _, v := range allowed {
			if v == name {
				found = true
				break
			}
		}
		if !found {
			errMsg := fmt.Sprintf("environment variable not allowed: %s", name)
			stream.Write([]byte(protocol.BuildResponse(protocol.ResponseError, errMsg)))
			s.notify("env", sess, false, errMsg, map[string]interface{}{
				"name":  name,
				"value": value,
			})
			return nil
		}
	}

	sess.EnvVars = append(sess.EnvVars, envVar)
	stream.Write([]byte(protocol.BuildResponse(protocol.ResponseOK, "environment variable set")))
	s.notify("env", sess, true, "", map[string]interface{}{
		"name":  name,
		"value": value,
	})
	return nil
}
