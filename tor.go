// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2017, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

// Motto: Long live the connections

package main

import (
	"fmt"
	"log"
	"github.com/gwitmond/goControlTor"
)

func createTorHiddenService(torPort, endpoint string) (string, string) {
	tc := &goControlTor.TorControl{}
	err := tc.Dial("unix", "/var/run/tor/control")
	check(err)
	err = tc.CookieAuthenticate("/var/run/tor/control.authcookie")
	check(err)
	log.Printf("Logged into Tor, creating hidden service")
	onion, onionPrivKey, err := tc.CreateEphemeralHiddenService(torPort, endpoint)
	check(err)
	log.Printf("Created onion address: %v", onion)
	onionAddress := fmt.Sprintf("%s.onion:443", onion)
	log.Printf("Created Listener at %v for %v", endpoint, onionAddress)
	return onionAddress, onionPrivKey
}


func restartTorHiddenService(onionPrivKey []byte, torPort, endpoint, dest string) error {
	tc := &goControlTor.TorControl{}
	err := tc.Dial("unix", "/var/run/tor/control")
	if err != nil {
		return err
	}
	err = tc.CookieAuthenticate("/var/run/tor/control.authcookie")
	if err != nil {
		return err
	}
	log.Printf("Logged into Tor, restarting hidden service")
	err = tc.RestartEphemeralHiddenService(onionPrivKey, torPort, endpoint, dest)
	if err != nil {
		return err
	}
	return nil
}
