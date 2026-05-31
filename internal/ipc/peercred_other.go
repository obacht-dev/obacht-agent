//go:build !linux

package ipc

import "net"

// peerUID is a no-op on non-Linux platforms (used only for local dev on
// macOS). It returns -1 with a nil error, signalling "unknown" so the admin
// guard falls back to socket FS-permission trust. SEC-26 peer-credential
// enforcement is active on the Linux fleet where the agent actually runs.
func peerUID(_ net.Conn) (int, error) {
	return -1, nil
}
