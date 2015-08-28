// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2015, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

// Motto: Long live the connections

package main // eccaproxy

import (
	"net"
	"log"
)

type listener struct {
	Destination string // ip:port or abc.domain.tld or xyz.onion address
	// ourID            // some form of authentication
	// theirID
}

// Start each of the listeners.
// To be called at startup
func connectListeners() {
	listeners, err := getAllListeners()
	check(err)

	for _, listener := range listeners {
		startListener(listener)
	}
}

func startListener(listener listener) {
	netl, err := net.Listen("tcp", listener.Destination)
	check(err)
	log.Printf("Started Listener at %v", listener.Destination)
	go AwaitIncomingConnection(netl)
}
