//go:build darwin || linux

package server

import "net"

// control runs fn with the file descriptor of a unix socket connection.
func control(c net.Conn, fn func(fd int)) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return
	}
	if raw, err := uc.SyscallConn(); err == nil {
		raw.Control(func(fd uintptr) { fn(int(fd)) })
	}
}
