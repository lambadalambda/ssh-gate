//go:build !darwin && !linux

package server

import "net"

// PeerPID is not implemented on this platform and returns 0.
func PeerPID(net.Conn) int { return 0 }
