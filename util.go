// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

package main // eccaproxy

import (
	//"log"
	"bytes"
	"crypto/tls"
	"crypto/rsa"
	"crypto/x509/pkix"
	"regexp"
	"encoding/asn1"
	"encoding/pem"
)

// This file contains simple utils to keep the main code clutter-free.


//---------------------------------------------------------------------------------
// Parse a WWW-Authenticate: Ecca header.
// It only accepts Ecca
var eccaHeaderRE = regexp.MustCompile("^Ecca ")
var realmRE      = regexp.MustCompile(" realm=\"([^\"]+)\"")
var typeRE       = regexp.MustCompile(" type=\"([^\"]+)\"")
var registerRE   = regexp.MustCompile(" register=\"([^\"]+)\"")

func ParseWWWAuthHeader (header string) (map[string] string) {
	//log.Printf("header value is %s", header)

	if eccaHeaderRE.MatchString(header) {
		values := make(map[string] string)
	 	values["realm"]    = getFirst(realmRE.FindStringSubmatch(header))
	 	values["type"]     = getFirst(typeRE.FindStringSubmatch(header))
	 	values["register"] = getFirst(registerRE.FindStringSubmatch(header))
	 	return values
	}
	return nil
}

// Return the first (not zeroth) string in the array, if not nil
func getFirst(s []string) (string) {
	if s != nil {
		return s[1]
	}
	// TODO: error out if required parameter is missing
	return ""
}

//---------------------------------------------------------------------------------
// Marshall a rsa.PublicKey into DER and PEM encoding

// type pkixPublicKey copied from crypto/x509/x509.go as it is not exported there.
type pkixPublicKey struct {
        Algo      pkix.AlgorithmIdentifier
        BitString asn1.BitString
}

// TODO: figure out why this gives an empty BEGIN PUBLIC KEY / END PUBLIC KEY block
// Something with me not knowing interfaces yet.
//derBytes, err := x509.MarshalPKIXPublicKey(pubkey)
// instead use the function copied form x509.go
// marshalPublicKey converts a public key to ASN.1 DER encoded form
func marshalPublicKey(pubkey rsa.PublicKey) ([]byte) {
	pubBytes, _ := asn1.Marshal(pubkey)
	pkix := pkixPublicKey{
        Algo: pkix.AlgorithmIdentifier{
                        Algorithm: []int{1, 2, 840, 113549, 1, 1, 1},
                        // This is a NULL parameters value which is technically
                        // superfluous, but most other code includes it and, by
                        // doing this, we match their public key hashes.
                Parameters: asn1.RawValue{
                                Tag: 5,
                        },
                },
        BitString: asn1.BitString{
                        Bytes:     pubBytes,
                        BitLength: 8 * len(pubBytes),
                },
        }
        der, _ := asn1.Marshal(pkix)
        return der
}

// PublicKeyToPEM: encode a rsa.PublicKey to PEM to make it easy to post in a http-form
func publicKeyToPEM (pubkey rsa.PublicKey) (string) {
	derBytes := marshalPublicKey(pubkey)

	var pubkeyPEM  bytes.Buffer
        pem.Encode(&pubkeyPEM, &pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
	return pubkeyPEM.String()
}


//----------------------------------------------------------------------------------

func pemDecodeCertificate(body []byte) (cert tls.Certificate) {
	certBlock, _ := pem.Decode(body) // second param is unused part of the body.
	if certBlock.Type == "CERTIFICATE" {
		cert.Certificate = append(cert.Certificate, certBlock.Bytes)
		// even though it's called append, it's a new cert instance at every call.
		return cert
	}
	panic("Not a certificate in there")
}
