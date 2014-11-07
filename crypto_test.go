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
	"bytes"
	"encoding/pem"
	"math/big"
	CryptoRand "crypto/rand"
	MathRand   "math/rand"
	"time"
	"errors"
	//"github.com/gwitmond/eccentric-authentication" // package eccentric
	"github.com/gwitmond/eccentric-authentication/fpca" // package eccentric/fpca	
	"github.com/gwitmond/eccentric-authentication/utils/camaker" // CA maker tools.
	//"log"
)

var config = quick.Config {
	MaxCount: 1, // just one test
	Rand: MathRand.New(MathRand.NewSource(time.Now().UnixNano())),
}

// Generate a self signed CA cert & key.
var  caCert, caKey, _ = camaker.GenerateCA("The Root CA", "CA", 512)
var caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

var fpcaCert, fpcaKey, _ = camaker.GenerateFPCA("The FPCA Org", "FPCA-CN", caCert, caKey, 512)
var fpcaCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fpcaCert.Raw})


var subca = &fpca.FPCA{
	Namespace: "testca",
	CaCert: fpcaCert,
	CaPrivKey: fpcaKey,
}

// create the chain certificate
var buf = bytes.NewBuffer(caCertPEM)
var n, _  =  buf.WriteString("\n")
var m, _ =  buf.Write(fpcaCertPEM)
var chainPEM = buf.Bytes()

// generate client key and certificate with ROOT CA
//var privKey, clientCert = setupClient("test-client", caCert, caKey)
var privKey, _ = rsa.GenerateKey(CryptoRand.Reader, 384)
var clientCert, _ =  subca.SignClientCert("test-client", &privKey.PublicKey)
var privPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
var  certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert})

// Test single level message encryption and decryption
func TestEncryptDecryptRoot(t *testing.T) {
	encryptDecrypt := func(message string ) bool {
		//t.Logf("message to encrypt-decrypt with Root is %s\n", message)
		ciphertext := Encrypt(message, certPEM) 
		res := Decrypt(ciphertext, privPEM)
		return  res == message
  	}
	err := quick.Check(encryptDecrypt, &config)
	if err != nil {
		t.Error(err)
	}
}

// generate client key and certificate with FPCA CA
var priv2Key, client2Cert = setupClient("test-client", fpcaCert, fpcaKey)
var priv2PEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv2Key)})
var  cert2PEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: client2Cert.Raw})

// Test two level certificate for message encryption and decryption.
// Should work as single level, as encryption is independent of certificate chain length.
func TestEncryptDecryptFPCA(t *testing.T) {
	encryptDecrypt := func(message string ) bool {
		//t.Logf("message to encrypt-decrypt with FPCA is %s\n", message)
		ciphertext := Encrypt(message, cert2PEM) 
		res := Decrypt(ciphertext, priv2PEM)
		return  res == message
  	}
	err := quick.Check(encryptDecrypt, &config)
	if err != nil {
		t.Error(err)
	}
}


// sign and verify.
// Sign with a client certificate. Verify against chain of RootCA and FPCA.
func TestSignVerifyFPCA(t *testing.T) {
	signVerify := func(message string ) bool {
		// ignore message and generate our own ascii string of same length.
		message = srand(len(message))
		signature, _ := Sign(priv2PEM, cert2PEM, message) 
		//t.Logf("message is: %s\nsignature is: %s\nerror is: %v", message, signature, err)
		valid, res := Verify(message, signature, chainPEM)
		//t.Logf("validity is: %v, res is: %q\n", valid, res)
		// this tests whether openssl returns someting and whether that is equal to the original message that was signed.
		return valid && (res == message)
	}
	err := quick.Check(signVerify, &config)
	if err != nil {
		t.Error(err)
	}
}

func TestSignEmptyMessage(t *testing.T) {
	message := "" //empty
	signature, err := Sign(priv2PEM, cert2PEM, message) 
	if err.Error() != "Cannot sign empty message" {
		t.Errorf("Expected error 'Cannot sign empty message', got %#v, %#v\n", signature, err)
	}
}

// test whether the signature contains the correct (and same) client certificate.
func TestFetchIdentity(t *testing.T) {
	testIdentity := func(CN string ) bool {
		// create our own client certificates, use different names from the global ones.
		prKey, clCert := setupClient(CN, caCert, caKey)
		prPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(prKey)})
		crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clCert.Raw})

		message := "A simple test message"
		signature, err := Sign(prPEM, crtPEM, message) 
		//t.Logf("message is: %s\nsignature is: %s, error is %v\n", message, signature, err)

		id, err := FetchIdentity(signature)
		check(err)
		//t.Logf("identity is: %v", id)
		return bytes.Contains(id.Bytes(), crtPEM)
	}
	err := quick.Check(testIdentity, &config)
	if err != nil {
		t.Error(err)
	}
}


var alpha = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
// generates a random string of expected size
func srand(size int) string {
	if size == 0 { size = 1 }
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
func setupClient(CN string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*rsa.PrivateKey, *x509.Certificate) {
	// The private key to use 
	// Notice: make it at least 384 as 256 will not create a signature with openssl... 
	// It won't post an error either... :-(
	privkey, err := rsa.GenerateKey(CryptoRand.Reader, 512)
	check(err)

	// Sign it into a certificate
	cert, err := signClientCert(CN, privkey, caCert, caKey)
	check(err)

	return privkey, cert
}


func signClientCert(CN string, priv *rsa.PrivateKey, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, error) {
	serial := randBigInt()
	keyId := randBytes()
	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: CN,
		},
		
		SerialNumber:   serial,
		SubjectKeyId:   keyId,
		KeyUsage:   x509.KeyUsageDigitalSignature | 
			x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment | 
			x509.KeyUsageDataEncipherment | 
			x509.KeyUsageKeyAgreement ,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageEmailProtection,
		},
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

