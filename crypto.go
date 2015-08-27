// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

package main // eccaproxy

import (
	"log"
	"fmt"
	"net/url"
	"crypto/x509"
	"io"
	"io/ioutil"
	"encoding/pem"
	"errors"
	"bytes"
	"os"
	"os/exec"
	"strings"
	"github.com/gwitmond/eccentric-authentication" // package eccentric
)


// Encrypt a cleartext message with the public key in the certificate of the recipient using openssl
func Encrypt(cleartext string, certPEM []byte) []byte {
	certFileName := makeTempfile("ecca-cert", certPEM)
	defer os.Remove(certFileName)
	err, stdout, _ := run(strings.NewReader(cleartext), 
		"openssl", "smime", "-encrypt", "-aes128", "-binary", "-outform", "DER", certFileName)
	if err != nil {
		log.Fatal(err)
	}
	cipherDER := stdout.Bytes()
	cipherPEM := pem.EncodeToMemory(&pem.Block{Type: "ECCA ENCRYPTED MESSAGE", Bytes: cipherDER})
	return cipherPEM
}


// fetchCertificate GETs the url and parses the page as a PEM encoded certificate.
func fetchCertificatePEM(certificateURL string) ([]byte, error) {
	certURL, err := url.Parse(certificateURL)
	if err != nil { return nil, err }

	// encode query-parameters properly.
	q := certURL.Query()
	certURL.RawQuery = q.Encode()
	log.Printf("certificateURL is: %v, RawQuery is %#v, RequestURI is %v\n", certificateURL, certURL.Query(), certURL.RequestURI())

	certHostname := getHostname(certURL.Host)
	client, err := makeClient(certHostname)
	if err != nil { return nil, err }

	log.Printf("Fetching public key for %v\n", certificateURL)
	resp, err := client.Get(certificateURL)
	if err != nil { return nil, err }//	check(err)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil { return nil, err }//	check(err)

	log.Printf("Received: %q\n", body)

	// decode pem...,
	pemBlock, _ := pem.Decode(body)

	// check type...,
	if pemBlock.Type != "CERTIFICATE" {
		return nil, errors.New("Did not receive a PEM encoded certificate")
	}

	// parse der to validate the data...,
	_, err = x509.ParseCertificate(pemBlock.Bytes)
	if err != nil { return nil, err } //check(err)

	// but return the PEM so we can copy it to disk for /usr/bin/openssl
	return body, nil
}


// Decrypting a message using openssl
func Decrypt(cipherPEM []byte, privkeyPEM []byte) string {

	if len(cipherPEM) == 0 {
		return "Error, no secret message here. In fact, nothing at all."
	}

	cipherBlock, _ := pem.Decode(cipherPEM)
	if cipherBlock == nil {
		return "Error, no secret message here. Nothing we could recognize."
	}

	if cipherBlock.Type != "ECCA ENCRYPTED MESSAGE" {
		return "Error decoding secret message: expecting -----ECCA ENCRYPTED MESSAGE-----"
	}

	keyFileName := makeTempfile("ecca-key-", privkeyPEM)
	defer os.Remove(keyFileName)

	err, stdout, stderr := run(bytes.NewReader(cipherBlock.Bytes),
		"openssl", "smime", "-decrypt", "-binary", "-inform", "DER", "-inkey", keyFileName)
	if err != nil {
		return fmt.Sprintf("Error decrypting message. Openssl says: %s\n", stderr.String())
	}

	cleartext := stdout.String()
	return cleartext
}


// Sign a message
func Sign(privkeyPEM []byte, certPEM []byte, message string) (string, error) {
	// log.Printf("signing %v\n", message)
	if len(message) == 0 {
		return "", errors.New("Cannot sign empty message")
	}

	keyFileName := makeTempfile("ecca-key-", privkeyPEM)
	defer os.Remove(keyFileName)

	certFileName := makeTempfile("ecca-cert-", certPEM)
	defer os.Remove(certFileName)

	err, stdout, stderr := run(strings.NewReader(message),
		"openssl", "smime", "-sign", "-signer", certFileName,  "-inkey", keyFileName)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error signing message. Openssl says: %s\n", stderr.String()))
	}
	signature := stdout.String()
	return signature, nil
}


// Verify the message
// Return a boolean whether the message is signed by the signature.
// Return the message to show on screen, can't trust the server.
func Verify(message string, signature string, caChain []x509.Certificate) (bool, string) {
	caFile, err := ioutil.TempFile("", "ecca-ca-")
	check(err)
	caFilename := caFile.Name()
	defer os.Remove(caFilename)
	for _, cert := range caChain {
		pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	caFile.Close()

	// TODO: create template to merge message and signature in a valid openssl smime like format
	err, stdout, stderr := run(strings.NewReader(signature),
		"openssl", "smime", "-verify",  "-CAfile", caFilename)
	if err != nil {
		log.Printf("Error verifying message. Openssl says: %s\n", stderr.String())
		return false, stderr.String() // return error message for now.
	}
	// Note: with openssl smime signing, the true message is in the signature, we return what we get back from openssl
	// TODO: return message == stdout.String(), plus "error message in case it is false"
	return true, stdout.String() // or Bytes()
}

func run(stdin io.Reader, command string, args ... string) (error, bytes.Buffer, bytes.Buffer) {
	runner := exec.Command(command, args...)
	runner.Stdin = stdin
 	var stdout bytes.Buffer
	var stderr bytes.Buffer
	runner.Stdout = &stdout
	runner.Stderr = &stderr
	err := runner.Run()
	if err != nil {
		log.Printf("Error with running command: \"%v %v\"\nerror is: %v\nstderr is: %v\n", command, args, err, stderr.String())
	}
	return err, stdout, stderr
}


// Fetch the identity (users' client certificate) from the signed message.
func FetchIdentity(signature string) *x509.Certificate {
	// log.Printf("fetching identity\n")
	err, pk7, stderr := run(strings.NewReader(signature),
		"openssl", "smime", "-pk7out")
	if err != nil {
		log.Fatal(stderr.String())
		// this dies here.
	}
	// pipe the pk7 data to extract the user certificate
	err, certPEM, stderr := run(bytes.NewReader(pk7.Bytes()),
		"openssl", "pkcs7", "-print_certs")
	if err != nil {
		log.Fatal(stderr.String())
		// this dies here too.
	}
	cert := eccentric.PEMDecode(certPEM.Bytes())
	return &cert
}


// make a tempfile with given data.
// return the filename, caller needs to defer.os.Remove it.
func makeTempfile(prefix string, data []byte) string {
	tempFile, err := ioutil.TempFile("", prefix)
	check(err) // die on error
	tempFileName := tempFile.Name()
	tempFile.Write(data)
	tempFile.Close()
	return tempFileName
}


// Sign and Encrypt a message.
// Sign first and encrypt the signed message as not to leak who it's from to observers en route to the recipient.
// (i.e. only the recipient get to know and verify the sender)
func SignAndEncryptPEM(signPrivkeyPEM, signCertPEM, recipientCertPEM []byte, message string) []byte {
if len(message) == 0 {
		log.Fatal(errors.New("Cannot sign empty message"))
	}

	recipCertFileName := makeTempfile("ecca-recipcert-", recipientCertPEM)
	defer os.Remove(recipCertFileName)

	signKeyFileName := makeTempfile("ecca-signkey-", signPrivkeyPEM)
	defer os.Remove(signKeyFileName)

	signCertFileName := makeTempfile("ecca-signcert-", signCertPEM)
	defer os.Remove(signCertFileName)

	err, signStdout, signStderr := run(strings.NewReader(message),
		"openssl", "smime", "-sign", "-signer", signCertFileName,  "-inkey", signKeyFileName)
	if err != nil {
		log.Fatal(errors.New(fmt.Sprintf("Error signing message. Error: %v\nOpenssl says: %s\n", err, signStderr.String())))
	}

	// pipe the output of signing into the encryption
	signature := signStdout.Bytes()

	err, encrStdout, encrStderr := run(bytes.NewReader(signature),
		"openssl", "smime", "-encrypt", "-aes128", "-binary", "-outform", "DER", recipCertFileName)
	if err != nil {
		log.Fatal(errors.New(fmt.Sprintf("Error encrypting message. Error: %v\nOpenssl says: %s\n", err, encrStderr.String())))	
	log.Fatal(err)
	}
	cipherDER := encrStdout.Bytes()
	cipherPEM := pem.EncodeToMemory(&pem.Block{Type: "ECCA ENCRYPTED SIGNED MESSAGE", Bytes: cipherDER})
	return cipherPEM
}


// Decrypt with own key and verify signature to retrieve sender's identity
func DecryptAndVerify(cipherPEM []byte, privkeyPEM []byte) (string, *x509.Certificate) {
	if len(cipherPEM) == 0 {
		return "Error, no secret message here. In fact, nothing at all.", nil
	}

	cipherBlock, _ := pem.Decode(cipherPEM)
	if cipherBlock == nil {
		return "Error, no secret message here. Nothing we could recognize.", nil
	}

	if cipherBlock.Type != "ECCA ENCRYPTED SIGNED MESSAGE" {
		return "Error, expecting -----ECCA ENCRYPTED SIGNEDMESSAGE-----", nil
	}

	keyFileName := makeTempfile("ecca-key-", privkeyPEM)
	defer os.Remove(keyFileName)

	err, stdout, stderr := run(bytes.NewReader(cipherBlock.Bytes),
		"openssl", "smime", "-decrypt", "-binary", "-inform", "DER", "-inkey", keyFileName)
	if err != nil {
		return fmt.Sprintf("Error decrypting message. Openssl says: %s\n", stderr.String()), nil
	}
	signedMessage := stdout.String()

	// Verify message against senderCert against FPCA of sender.
	senderCert := FetchIdentity(signedMessage)
	sender := senderCert.Subject.CommonName
	username, hostname, err := eccentric.ParseCN(sender)
	log.Printf("Identity from message is %s, username is %s, hostname is %s", sender, username, hostname)
	check(err)

	// Get the root CA of the sender
	rootCACert, err := eccentric.FetchRootCA(hostname)
	check(err)

	// Fetch the chain (and validate that our idCert is a valid Eccentric cert)
	chain, err := eccentric.ValidateEccentricCertificateChain(senderCert, rootCACert)
	check(err)

	valid, message := Verify("ignore", signedMessage, chain)
	if valid {
		return message, senderCert
	} else {
		return "(invalid signature, suppressing message)", nil
	}
}
