package server

import (
	"net"

	"golang.org/x/sys/unix"
)

// PeerPID returns the PID of the process on the other end of a unix socket
// connection, or 0 if it is unknown. Use it for logs only.
func PeerPID(c net.Conn) int {
	var pid int
	control(c, func(fd int) {
		if cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
			pid = int(cred.Pid)
		}
	})
	return pid
}
