//go:build linux

package ipc

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// peerUID returns the uid of the process on the other end of the unix socket
// connection via SO_PEERCRED. SEC-26.
func peerUID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, errors.New("ipc: connection is not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if credErr != nil {
		if errors.Is(credErr, syscall.ENOPROTOOPT) {
			// Kernel without SO_PEERCRED support — fall back to FS trust.
			return -1, nil
		}
		return -1, credErr
	}
	return int(cred.Uid), nil
}
