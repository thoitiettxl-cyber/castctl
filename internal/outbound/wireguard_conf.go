// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	badoption "github.com/sagernet/sing/common/json/badoption"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/redact"
)

// WireGuard conf converter: wg-quick .conf -> sing-box 1.14
// option.WireGuardEndpointOptions.
//
// Schema source (sing-box v1.14.4, option/wireguard.go:9-33):
// WireGuardEndpointOptions{System, Name, MTU, Address
// Listable[netip.Prefix], PrivateKey, ListenPort, Peers
// []WireGuardPeer, UDPTimeout, UDPMapping, UDPFiltering, UDPNATMax,
// Workers, DialerOptions}; WireGuardPeer{Address, Port, PublicKey,
// PreSharedKey, AllowedIPs Listable[netip.Prefix],
// PersistentKeepaliveInterval, Reserved}.
//
// Mapped fields: [Interface] PrivateKey -> PrivateKey, Address ->
// Address (comma list; a bare IP becomes /32 for IPv4 or /128 for
// IPv6), ListenPort -> ListenPort, MTU -> MTU; [Peer] PublicKey ->
// PublicKey, PresharedKey -> PreSharedKey, AllowedIPs -> AllowedIPs,
// Endpoint -> Address + Port (host:port split; IPv6 requires
// brackets), PersistentKeepalive -> PersistentKeepaliveInterval.
// System is always false (userspace only, Gate 2 Q4); Name is empty
// (the interface name is the file name, not file content); Reserved
// is nil (no wg-quick field maps to it).
//
// NOT mapped: wg-quick DNS= has NO field in the schema — it is
// ignored and recorded, not invented. DialerOptions.DomainResolver
// takes a DNS server tag, not a DNS IP list, so it is not a mapping
// for DNS= either. Unknown keys (PostUp, SaveConfig, ...) are
// ignored.
//
// The converter never starts a device, dials UDP, or handshakes.
// Key strings are NOT validated as key material: fixtures use the
// literal placeholder "<redacted>", which must parse. Parse errors
// never contain key values.
func ParseWireGuardConf(data []byte) (option.WireGuardEndpointOptions, error) {
	var opts option.WireGuardEndpointOptions
	var currentPeer *option.WireGuardPeer
	seenInterface := false
	unknownSection := false

	flushPeer := func() {
		if currentPeer != nil {
			opts.Peers = append(opts.Peers, *currentPeer)
			currentPeer = nil
		}
	}

	for lineno, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return opts, fmt.Errorf("outbound: wireguard conf line %d: malformed section header", lineno+1)
			}
			section := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
				flushPeer()
				seenInterface = true
				unknownSection = false
			case "peer":
				flushPeer()
				currentPeer = &option.WireGuardPeer{}
				unknownSection = false
			default:
				// Keys under an unknown section must not silently
				// fall through into [Interface] parsing (and
				// possibly overwrite PrivateKey): fail closed.
				flushPeer()
				currentPeer = nil
				unknownSection = true
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return opts, fmt.Errorf("outbound: wireguard conf line %d: expected key = value", lineno+1)
		}
		if unknownSection {
			return opts, fmt.Errorf("outbound: wireguard conf line %d: key in unknown section", lineno+1)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if currentPeer != nil {
			if err := parsePeerField(currentPeer, key, value); err != nil {
				return opts, fmt.Errorf("outbound: wireguard conf line %d: %w", lineno+1, err)
			}
			continue
		}
		if !seenInterface {
			return opts, fmt.Errorf("outbound: wireguard conf line %d: key outside [Interface]", lineno+1)
		}
		if err := parseInterfaceField(&opts, key, value); err != nil {
			return opts, fmt.Errorf("outbound: wireguard conf line %d: %w", lineno+1, err)
		}
	}
	flushPeer()

	if !seenInterface {
		return opts, errors.New("outbound: wireguard conf has no [Interface] section")
	}
	if opts.PrivateKey == "" {
		return opts, errors.New("outbound: wireguard conf [Interface] is missing PrivateKey")
	}
	for i := range opts.Peers {
		peer := &opts.Peers[i]
		if peer.PublicKey == "" {
			return opts, fmt.Errorf("outbound: wireguard conf peer %d is missing PublicKey", i+1)
		}
		if peer.Address == "" {
			return opts, fmt.Errorf("outbound: wireguard conf peer %d is missing Endpoint", i+1)
		}
	}
	return opts, nil
}

func parseInterfaceField(opts *option.WireGuardEndpointOptions, key, value string) error {
	switch key {
	case "privatekey":
		opts.PrivateKey = value
	case "address":
		prefixes, err := parsePrefixList(value)
		if err != nil {
			return err
		}
		opts.Address = append(opts.Address, prefixes...)
	case "listenport":
		port, err := parseUint(value, 65535)
		if err != nil {
			return fmt.Errorf("invalid ListenPort: %w", err)
		}
		opts.ListenPort = uint16(port)
	case "mtu":
		mtu, err := parseUint(value, 65535)
		if err != nil {
			return fmt.Errorf("invalid MTU: %w", err)
		}
		opts.MTU = uint32(mtu)
	case "dns":
		// No field in the schema. Ignored by design; see the
		// package-level mapping note above.
	}
	return nil
}

func parsePeerField(peer *option.WireGuardPeer, key, value string) error {
	switch key {
	case "publickey":
		peer.PublicKey = value
	case "presharedkey":
		peer.PreSharedKey = value
	case "allowedips":
		prefixes, err := parsePrefixList(value)
		if err != nil {
			return err
		}
		peer.AllowedIPs = append(peer.AllowedIPs, prefixes...)
	case "endpoint":
		host, port, err := splitEndpoint(value)
		if err != nil {
			return err
		}
		peer.Address = host
		peer.Port = port
	case "persistentkeepalive":
		interval, err := parseUint(value, 65535)
		if err != nil {
			return fmt.Errorf("invalid PersistentKeepalive: %w", err)
		}
		peer.PersistentKeepaliveInterval = uint16(interval)
	}
	return nil
}

func parsePrefixList(value string) (badoption.Listable[netip.Prefix], error) {
	var out badoption.Listable[netip.Prefix]
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			// Bare IP: /32 for IPv4, /128 for IPv6.
			addr, addrErr := netip.ParseAddr(item)
			if addrErr != nil {
				return nil, fmt.Errorf("invalid address %q", item)
			}
			bits := 128
			if addr.Is4() {
				bits = 32
			}
			prefix = netip.PrefixFrom(addr, bits)
		}
		out = append(out, prefix)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty address list %q", value)
	}
	return out, nil
}

// splitEndpoint splits a wg-quick Endpoint value (host:port) into host
// and port. IPv6 hosts must be bracketed; an unbracketed IPv6 literal
// is an error because the port would be ambiguous.
func splitEndpoint(value string) (string, uint16, error) {
	if strings.Count(value, ":") > 1 && !strings.HasPrefix(value, "[") {
		return "", 0, fmt.Errorf("invalid Endpoint %q: IPv6 endpoint must be bracketed", value)
	}
	host, portStr, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, fmt.Errorf("invalid Endpoint %q: %w", value, err)
	}
	if host == "" {
		return "", 0, fmt.Errorf("invalid Endpoint %q: empty host", value)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid Endpoint %q: invalid port", value)
	}
	return host, uint16(port), nil
}

func parseUint(value string, max uint64) (uint64, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil || n > max {
		return 0, fmt.Errorf("invalid number %q", value)
	}
	return n, nil
}

// WireGuardConfToEndpoint converts wg-quick conf bytes into a
// sing-box endpoint option with the given tag.
func WireGuardConfToEndpoint(data []byte, tag string) (option.Endpoint, error) {
	opts, err := ParseWireGuardConf(data)
	if err != nil {
		return option.Endpoint{}, err
	}
	return option.Endpoint{
		Type:    "wireguard",
		Tag:     tag,
		Options: &opts,
	}, nil
}

// RedactedPlaceholder is the value every secret field is replaced with
// by RedactEndpoint. It aliases redact.Marker so the marker lives in
// exactly one place.
const RedactedPlaceholder = redact.Marker

// RedactEndpoint marshals an endpoint's options and returns a JSON
// object {type, tag, options} with every secret field replaced by
// "<redacted>". The key set and the string redaction are
// redact.Value's: this package keeps no local copy of either, and
// still does not import internal/profile. The input endpoint is
// never logged and its secret fields never appear in the output.
func RedactEndpoint(ep option.Endpoint) ([]byte, error) {
	if ep.Options == nil {
		return nil, errors.New("outbound: cannot redact an endpoint with no options")
	}
	raw, err := json.Marshal(ep.Options)
	if err != nil {
		return nil, fmt.Errorf("outbound: redact endpoint: %w", err)
	}
	var options map[string]any
	if err := json.Unmarshal(raw, &options); err != nil {
		return nil, fmt.Errorf("outbound: redact endpoint: %w", err)
	}
	redactedOptions, ok := redact.Value(options).(map[string]any)
	if !ok {
		return nil, errors.New("outbound: redact endpoint: redacted options are not an object")
	}
	envelope := map[string]any{
		"type":    ep.Type,
		"tag":     ep.Tag,
		"options": redactedOptions,
	}
	// Encoder with HTML escaping disabled: encoding/json would turn
	// "<redacted>" into "\u003credacted\u003e", which breaks the
	// redaction contract (the output must literally contain
	// "<redacted>").
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(envelope); err != nil {
		return nil, fmt.Errorf("outbound: redact endpoint: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
