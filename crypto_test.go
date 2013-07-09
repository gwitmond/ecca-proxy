// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

// Testing code

package main // eccaproxy

import (
	"testing"
	"testing/quick"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	//"bytes"
	"encoding/pem"
	"math/big"
	CryptoRand "crypto/rand"
	MathRand   "math/rand"
	"time"
	"errors"
	//"log"
)

var config = quick.Config {
	MaxCount: 10,
	Rand: MathRand.New(MathRand.NewSource(time.Now().UnixNano())),
}

var privPEM, certPEM = setup()

func TestEncryptDecrypt(t *testing.T) {
	encryptDecrypt := func(message string ) bool {
		t.Logf("message is %s\n", message)
		ciphertext := Encrypt(message, certPEM) 
		res := Decrypt(ciphertext, privPEM)
		return  res == message
  	}
	err := quick.Check(encryptDecrypt, &config)
	if err != nil {
		t.Error(err)
	}
}

func TestSignVerify(t *testing.T) {
	//signVerify := func(dummy string ) bool {
	signVerify := func(message string ) bool {

		// ignore message and generate our own ascii string of same length.
		// message := srand(len(message))
		signature := Sign(privPEM, certPEM, message) 
		t.Logf("message is: %s\nsignature is: %s\n", message, signature)
		//log.Printf("message is %s\nsignature is %s\n", message, signature)
		valid, res := Verify(message, signature)
		t.Logf("validity is: %v, res-message is: %q\n", valid, res)
		// this tests whether openssl returns someting and whether that is equal to the original message that was signed.
		return valid && (res == message)
	}
	err := quick.Check(signVerify, &config)
	if err != nil {
		t.Error(err)
	}

}
var alpha = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


// generates a random string of fixed size
func srand(size int) string {
    buf := make([]byte, size)
    for i := 0; i < size; i++ {
        buf[i] = alpha[MathRand.Intn(len(alpha))]
    }
    return string(buf)
}

//func (s string) Generate(rand *rand.Rand, size int) reflect.Value {
//	v := MyInt(rand.Int())
//	return reflect.ValueOf(v)
//}

//=================== helpers (and a lot of them) ===========

// Initialise math.rand seed. Otherwise it behaves as math.seed(1). ouch..
//func init() {
//	MathRand.Seed(time.Now().UnixNano())	
//}


// Create certificate and private key to encrypt and decrypt messages
func setup () ([]byte, []byte) {
	// Generate a self signed CA cert & key.
        caCert, caKey, err := generateCA("CA")
        check(err)

	// The private key to use 
	// Notice make it at least 384 as 256 will not create a signature with openssl... 
	// It won't post an error either... :-(
	privkey, err := rsa.GenerateKey(CryptoRand.Reader, 384)
	check(err)

	// Sign it into a certificate
	cert, err := signCert(privkey, caCert, caKey)
	check(err)

	// encode
	privPEM  := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privkey)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	return privPEM, certPEM
}


func generateCA(serverName string) (*x509.Certificate, *rsa.PrivateKey, error) {
        priv, err := rsa.GenerateKey(CryptoRand.Reader, 512)
        if err != nil {
                return nil, nil, err
        }

        serial := randBigInt()
        keyId := randBytes()

        template := x509.Certificate{
                Subject: pkix.Name{
                        CommonName: serverName,
                },

                SerialNumber:   serial,
                SubjectKeyId:   keyId,
                AuthorityKeyId: keyId,
                NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),
                NotAfter:       time.Now().Add(5 * time.Minute).UTC(),

                KeyUsage:              x509.KeyUsageCertSign,
                BasicConstraintsValid: true,
                IsCA:                  true,
        }

        derBytes, err := x509.CreateCertificate(CryptoRand.Reader, &template, &template, &priv.PublicKey, priv)
        if err != nil {
                return nil, nil, err
        }

        certs, err := x509.ParseCertificates(derBytes)
        if err != nil {
                return nil, nil, err
        }

        if len(certs) != 1 {
                return nil, nil, errors.New("Failed to generate a parsable certificate")
        }

        return certs[0], priv, nil
}

func signCert(priv *rsa.PrivateKey, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, error) {
        serial := randBigInt()
        keyId := randBytes()

        template := x509.Certificate{
                Subject: pkix.Name{
                        CommonName: "test",
                },

                SerialNumber:   serial,
                SubjectKeyId:   keyId,
                AuthorityKeyId: caCert.AuthorityKeyId,
                NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),
                NotAfter:       time.Now().Add(5 * time.Minute).UTC(),
        }

        derBytes, err := x509.CreateCertificate(CryptoRand.Reader, &template, caCert, &priv.PublicKey, caKey)
        if err != nil {
                return nil, err
        }

        certs, err := x509.ParseCertificates(derBytes)
        if err != nil {
                return nil, err
        }

        if len(certs) != 1 {
                return nil, errors.New("Failed to generate a parsable certificate")
        }
	return certs[0], nil
}

var (
        maxInt64 int64 = 0x7FFFFFFFFFFFFFFF
        maxBig64  = big.NewInt(maxInt64)
)

func randBigInt() (value *big.Int) {
        value, _ = CryptoRand.Int(CryptoRand.Reader, maxBig64)
        return
}

func randBytes() (bytes []byte) {
        bytes = make([]byte, 20)
        CryptoRand.Read(bytes)
        return
}


