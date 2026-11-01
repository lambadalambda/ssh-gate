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
		pid, _ = unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	return pid
}
