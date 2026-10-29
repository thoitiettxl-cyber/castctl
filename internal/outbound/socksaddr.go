package outbound

import (
	M "github.com/sagernet/sing/common/metadata"
)

// Socksaddr is the EXACTLY ONE conversion from (host, port) to a
// sing-box Socksaddr. Every dial path in this package goes through it,
// so IP literals become Addr and domain names become Fqdn in exactly
// one place. Do not add a second conversion.
func Socksaddr(host string, port uint16) M.Socksaddr {
	return M.ParseSocksaddrHostPort(host, port)
}
