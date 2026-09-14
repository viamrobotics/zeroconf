//go:build !linux

package zeroconf

import (
	"errors"
	"net"
)

// errNoLegacyJoin signals that no legacy-join fallback is available on this
// platform, so callers keep the original JoinGroup error. The MCAST_JOIN_GROUP
// gap this works around is specific to qemu-user emulating Linux, so no
// fallback is needed elsewhere.
var errNoLegacyJoin = errors.New("no legacy multicast-join fallback on this platform")

func legacyJoinGroup4(conn *net.UDPConn, ifi *net.Interface, group net.IP) error {
	return errNoLegacyJoin
}

func legacyJoinGroup6(conn *net.UDPConn, ifi *net.Interface, group net.IP) error {
	return errNoLegacyJoin
}
