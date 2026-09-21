package addressbook

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pin/tftp/v3"
)

// maxTFTPFile bounds what a boot server will hand out.
const maxTFTPFile = 256 << 20

// tftpServer is a read-only TFTP server over one directory tree. It exists so a
// dnsmasq replacement can keep network boot working: writes are refused, names
// cannot leave the root (lexically or through symlinks), and only regular
// files are served.
type tftpServer struct {
	root string
	srv  *tftp.Server
	conn net.PacketConn
	done chan struct{}
}

// openInRoot resolves a client-supplied name beneath root, refusing anything
// that would escape it or is not a regular file.
func openInRoot(root, name string) (*os.File, error) {
	name = strings.ReplaceAll(name, "\\", "/")
	clean := filepath.Clean("/" + name)
	if clean == "/" || strings.ContainsRune(name, 0) {
		return nil, fmt.Errorf("invalid file name")
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(realRoot, clean))
	if err != nil {
		return nil, fmt.Errorf("file not found")
	}
	if rel, err := filepath.Rel(realRoot, resolved); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("file not found")
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("file not found")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxTFTPFile {
		f.Close()
		return nil, fmt.Errorf("file not found")
	}
	return f, nil
}

func newTFTP(root string, conn net.PacketConn) *tftpServer {
	t := &tftpServer{root: root, conn: conn, done: make(chan struct{})}
	t.srv = tftp.NewServer(func(name string, rf io.ReaderFrom) error {
		f, err := openInRoot(root, name)
		if err != nil {
			return err
		}
		defer f.Close()
		if info, e := f.Stat(); e == nil {
			if ot, ok := rf.(tftp.OutgoingTransfer); ok {
				ot.SetSize(info.Size())
			}
		}
		_, err = rf.ReadFrom(f)
		return err
	}, nil) // no write handler: uploads are refused
	t.srv.SetTimeout(3 * time.Second)
	t.srv.SetRetries(4)
	go func() { defer close(t.done); t.srv.Serve(conn) }()
	return t
}

func (t *tftpServer) close() {
	t.srv.Shutdown()
	<-t.done
}
