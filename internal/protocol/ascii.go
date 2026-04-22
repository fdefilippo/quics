package protocol

import (
	"io"
)

// ASCIIReader returns a reader that converts CRLF to LF for ASCII mode uploads (server side)
// and downloads (client side). Use when reading data from network to store locally.
func ASCIIReader(r io.Reader) io.Reader {
	// TODO: implement conversion
	return r
}

// ASCIIWriter returns a writer that converts LF to CRLF for ASCII mode downloads (server side)
// and uploads (client side). Use when writing data to network from local file.
func ASCIIWriter(w io.Writer) io.Writer {
	// TODO: implement conversion
	return w
}

// CountLF counts the number of line feed characters ('\n') in the reader.
// It does not count '\r' characters.
func CountLF(r io.Reader) (int64, error) {
	buf := make([]byte, 4096)
	var count int64
	for {
		n, err := r.Read(buf)
		for _, b := range buf[:n] {
			if b == '\n' {
				count++
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return count, err
		}
	}
	return count, nil
}
