//go:build dnsmasq && !dhcp

package main

// Build tags: this combination is not supported. Add the tag the name says.
var _ = tag_dnsmasq_requires_tag_dhcp
