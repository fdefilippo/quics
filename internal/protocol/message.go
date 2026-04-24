package protocol

import (
	"fmt"
	"strconv"
	"strings"
)

type Command struct {
	Type     string
	Args     []string
	Mode     string
	Size     int64
	Content  []byte
	Checksum string // SHA-256 hex string (UPLOAD/DOWNLOAD)
	Offset   int64  // resume offset (DOWNLOAD)
}

func ParseCommand(line string) (*Command, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty command")
	}

	parts := strings.Split(line, " ")
	if len(parts) < 1 {
		return nil, fmt.Errorf("invalid command format")
	}

	cmdType := parts[0]
	args := parts[1:]

	cmd := &Command{
		Type: cmdType,
		Args: args,
		Mode: DefaultMode,
	}

	switch cmdType {
	case CommandUpload, CommandPut:
		if len(args) < 2 {
			return nil, fmt.Errorf("%s requires filename and size", cmdType)
		}
		size, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid size: %v", err)
		}
		cmd.Size = size
		if len(args) >= 3 {
			cmd.Mode = strings.ToUpper(args[2])
		}
		if len(args) >= 4 {
			cmd.Checksum = args[3]
		}
	case CommandDownload, CommandGet:
		if len(args) < 1 {
			return nil, fmt.Errorf("%s requires filename", cmdType)
		}
		if len(args) >= 2 {
			cmd.Mode = strings.ToUpper(args[1])
		}
		if len(args) >= 3 {
			offset, err := strconv.ParseInt(args[2], 10, 64)
			if err == nil {
				cmd.Offset = offset
			}
		}
	case CommandCmd:
		if len(args) < 1 {
			return nil, fmt.Errorf("%s requires command", cmdType)
		}
	case CommandExec:
		if len(args) < 1 {
			return nil, fmt.Errorf("%s requires a command", cmdType)
		}
		// All args form the command (user/group are no longer sent by client)
		cmd.Args = []string{strings.Join(args, " ")}
	case CommandEnv:
		if len(args) != 1 || !strings.Contains(args[0], "=") {
			return nil, fmt.Errorf("%s requires NAME=VALUE format", cmdType)
		}
	default:
		return nil, fmt.Errorf("unknown command: %s", cmdType)
	}

	return cmd, nil
}

func BuildResponse(status string, message string) string {
	return fmt.Sprintf("%s %s\n", status, message)
}

func ParseResponse(line string) (string, string) {
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}
