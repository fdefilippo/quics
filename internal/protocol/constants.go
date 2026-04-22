package protocol

const (
	CommandUpload   = "UPLOAD"
	CommandDownload = "DOWNLOAD"
	CommandGet      = "GET"
	CommandPut      = "PUT"
	CommandCmd      = "CMD"
	CommandExec     = "EXEC"
	CommandEnv      = "ENV"

	ResponseOK    = "OK"
	ResponseError = "ERROR"

	ModeBinary = "BIN"
	ModeASCII  = "ASCII"

	DefaultMode = ModeBinary
)
