//go:build linux

package zeroconf

import (
	"net"
	"syscall"
)

// legacyJoinGroup4 / legacyJoinGroup6 join a multicast group via the classic
// IP_ADD_MEMBERSHIP / IPV6_JOIN_GROUP socket options on the socket underlying
// conn.
//
// golang.org/x/net/ipv4 and /ipv6 join via MCAST_JOIN_GROUP (the
// protocol-independent group_req option). qemu-user does not implement that
// option and rejects it with ENOPROTOOPT, so mDNS registration silently fails
// whenever a 32-bit build runs under emulation — e.g. rdk's linux/arm/v7 CI job
// when it lands on a runner that emulates rather than executes natively
// (RSDK-14553). The legacy options ARE emulated correctly, and they register
// the membership on the same fd that the ipv4/ipv6 PacketConn reads from, so
// falling back to them restores mDNS under emulation.
//
// These are used only as a fallback after the primary JoinGroup fails, so there
// is no behavior change on hosts where the primary path works.
func legacyJoinGroup4(conn *net.UDPConn, ifi *net.Interface, group net.IP) error {
	mreq := &syscall.IPMreqn{}
	copy(mreq.Multiaddr[:], group.To4())
	if ifi != nil {
		mreq.Ifindex = int32(ifi.Index)
	}
	return controlSocket(conn, func(fd int) error {
		return syscall.SetsockoptIPMreqn(fd, syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, mreq)
	})
}

func legacyJoinGroup6(conn *net.UDPConn, ifi *net.Interface, group net.IP) error {
	mreq := &syscall.IPv6Mreq{}
	copy(mreq.Multiaddr[:], group.To16())
	if ifi != nil {
		mreq.Interface = uint32(ifi.Index)
	}
	return controlSocket(conn, func(fd int) error {
		return syscall.SetsockoptIPv6Mreq(fd, syscall.IPPROTO_IPV6, syscall.IPV6_JOIN_GROUP, mreq)
	})
}

func controlSocket(conn *net.UDPConn, fn func(fd int) error) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	if err := raw.Control(func(fd uintptr) { opErr = fn(int(fd)) }); err != nil {
		return err
	}
	return opErr
}
