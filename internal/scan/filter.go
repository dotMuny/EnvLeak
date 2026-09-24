// Package scan walks a working tree and feeds file contents to the detection
// engines through a worker pool. It owns everything to do with the
// filesystem: .gitignore, binary detection, size limits and concurrency.
package scan

import (
	"bytes"
	"io"
	"os"
)

// SniffSize is how many bytes we read to decide whether a file is binary.
const SniffSize = 8 << 10

// IsBinary reports whether a buffer looks like binary content. The heuristic
// is the same one git uses: a NUL byte in the first 8 KiB. It is cheap, has no
// false positives on text, and its only false negative — UTF-16 text — is not
// a format anyone commits secrets in.
func IsBinary(head []byte) bool {
	return bytes.IndexByte(head, 0) >= 0
}

// sniff reads the first SniffSize bytes of r and returns them along with a
// reader that replays them, so the caller can classify a file without reading
// it twice or buffering the whole thing.
func sniff(r io.Reader) ([]byte, io.Reader, error) {
	head := make([]byte, SniffSize)
	n, err := io.ReadFull(r, head)
	switch {
	case err == io.EOF:
		head = head[:0]
	case err == io.ErrUnexpectedEOF:
		head = head[:n]
	case err != nil:
		return nil, nil, err
	}
	return head, io.MultiReader(bytes.NewReader(head), r), nil
}

// openFile opens a path and returns its sniffed head plus a replaying reader.
func openFile(path string) (*os.File, []byte, io.Reader, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from the walk of the user's own tree
	if err != nil {
		return nil, nil, nil, err
	}
	head, r, err := sniff(f)
	if err != nil {
		_ = f.Close()
		return nil, nil, nil, err
	}
	return f, head, r, nil
}
