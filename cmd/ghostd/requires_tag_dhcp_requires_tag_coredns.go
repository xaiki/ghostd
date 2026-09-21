//go:build dhcp && !coredns

package main

// Build tags: this combination is not supported. Add the tag the name says.
var _ = tag_dhcp_requires_tag_coredns
