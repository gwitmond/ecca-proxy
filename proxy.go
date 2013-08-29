// Ecca Authentication Proxy
//
// Handles Eccentric Authentication in a web proxy for browsers.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE
	
package main // eccaproxy

import (
	"github.com/elazarl/goproxy"
	"log"
	"fmt"
	"flag"
	"net/http"
	"time"
	"crypto/x509"
	"crypto/tls"
	MathRand   "math/rand"
	"os"
	"io/ioutil"
	"bytes"
	"encoding/xml"
	"github.com/jteeuwen/go-pkg-xmlx"
	// "dnssec"  // TODO fork dnssec.go into separate package
	//"github.com/gwitmond/eccentric-authentication" // package eccentric
)

// map between sitename and the url where to sign up for a certificate
var registerURLmap = map[string]string{}

var port = flag.Int("p", 8000, "port to listen to")
var verbose = flag.Bool("v", true, "should every proxy request be logged to stdout")
//var registryUrl = flag.String("registry", "https://registry-of-honesty.eccentric-authentication.org:1024/", "The Registry of (dis)honesty to query for duplicate certificates.")

func main() {
	flag.Parse()
	
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose
	
	// Requests for eccaHandlerHost allow the user to select and create certificates
	// This handler sends a response to the client, never upstream.
	proxy.OnRequest(goproxy.DstHostIs(eccaHandlerHost)).DoFunc(eccaHandler)
	
	// All other requests (where the user want to go to) are handled here.
	// When this needs an account, it redirects the client to the eccaHandler above.
	proxy.OnRequest().DoFunc(eccaProxy)

	
	// Decode any messages when we have the "Eccentric-Authentication" header set to "decrypt"
	proxy.OnResponse().DoFunc(DecodeMessages)

	// Verify any messages where we have the Eccentric-Authentication header set to "verification"
	proxy.OnResponse().DoFunc(VerifyMessages)

	// Change the redirect location (from https) to http so the client gets back to us.
	proxy.OnResponse().DoFunc(ChangeToHttp)
	
	log.Printf("We are starting at [::1]:%d and at 127.0.0.1:%d\n", *port, *port)
	log.Printf("Configure your browser to use one of those as http-proxy.\n")
	log.Printf("Then browse to http://www.ecca.wtmnd.nl  or http://dating.wtmnd.nl:10443/\n")
	log.Printf("Use http (not https) to benefit from this proxy.\n")
	log.Printf("For assistence, please see: http://eccentric-authentication.org/contact.html\n")

	// run or die. Try ipv6 first
	go http.ListenAndServe(fmt.Sprintf("[::1]:%d", *port), proxy)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", *port), proxy))
}

// eccaProxy: proxy the user requests and authenticate with the credentials we know.
func eccaProxy (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	log.Println("\n\n\nRequest is ", req.Method, req.URL.String())

	// set the scheme to https so we connect upstream securely
	if req.URL.Scheme == "http" {
		req.URL.Scheme = "https"
	}
	
	// Copy the body because we need it untouched. But we also need to parse 
	// the POST parameters and that eats the original buffer with the body
	body, err := ioutil.ReadAll(req.Body)
	check(err)
	req.Body.Close() // close it before replacing. Prevents leaking file descriptors.
	
	// give the data back immedeately.
	req.Body = ioutil.NopCloser(bytes.NewReader(body))
	
	// Read the parameters
	req.ParseForm()  // eats req.Body
	req.Body = ioutil.NopCloser(bytes.NewReader(body)) // copy back in again

	// Check for POST method with 'encrypt' param. 
	// transparantly encrypt the data.
	if req.Method == "POST" {
		if req.Form.Get("encrypt") == "required" {
			return encryptMessage(req)
		}
		// Now see if we need to sign 
		if req.Form.Get("sign") == "required" || req.Form.Get("sign") == "optional" {
			return signMessage(req, ctx)
		}
		//TODO: handle singning and encrypting at one operation for secure messaging.
	}
	resp, err := fetchRequest(req, ctx)

	if err != nil {
		log.Println("There was an error fetching the users' request: ", err)
		return req, goproxy.NewResponse(req,
			goproxy.ContentTypeText, http.StatusInternalServerError,
			"Some server error!")
	}
		
	log.Printf("response is %#v\n", resp) 
	return nil, resp // let goproxy send our response
}

// encrypt a message with a public key from a certificate in the url.	
func encryptMessage(req  *http.Request)  (*http.Request, *http.Response) {
	// First, fetch the recipients public key from where the server tells us to expect it.
	certPEM, err := fetchCertificatePEM( req.Form.Get("certificate_url"))
	check(err)

	// Do the actual encryption
	cleartext := req.Form.Get("cleartext")
	ciphertext := Encrypt(cleartext, certPEM)
	req.Form.Set("ciphertext", string(ciphertext))
	
	// TODO: refactor this duplicate code from signMessage
	client2, err := makeClient(req.URL.Host)
	if err != nil {
		log.Println("error is ", err)
		return nil, nil
	}
	
	resp, err := client2.PostForm(req.URL.String(), req.Form)
	if err != nil {
		log.Println("error is ", err)
		return nil, nil
	}
	return nil, resp
}


// signMessage signs a message with our current logged in account (private key) and adds the signature to the original request. Then it sends it on to the web site.
func signMessage(req  *http.Request, ctx *goproxy.ProxyCtx)  (*http.Request, *http.Response) {
	cleartext := req.Form.Get("cleartext") 
	// cleartext is the message, for now we ignore the title and other fields in theg signature
	
	// get the current logged in account (and private key)
	// TODO: change to use the server certificate Root CA identity. Not the req.URL.Host.
	log.Printf("req.URL.Host is: %v\n ", req.URL.Host)
	creds := getLoggedInCreds(req.URL.Host)
	
	if creds == nil {
		if req.Form.Get("sign") == "required" {
			log.Println("Form says to sign a message but no user is logged in.\nConfigure server to require login before handing the form.\nHint: Use the ecca.LoggedInHandler.")
			return nil, goproxy.NewResponse(req,
				goproxy.ContentTypeText, http.StatusInternalServerError,
				"Ecca Proxy error: Server says to sign your message but you haven't logged in. Please log in first, then type your message again. Later we might cache your data and redirect you to the login-screen.")
		}

		// creds is nil but signing is optional. Send the current form unchanged to the upstream server.
		resp, err := fetchRequest(req, ctx)
		check(err)
		return nil, resp
	}

	log.Printf("creds are: %v\n", creds.CN)
	
	signature, err := Sign(creds.Priv, creds.Cert, cleartext)
	log.Printf("signature is: %#v\n", signature)
	check(err)
	req.Form.Set("signature", signature)   // add signature to the request

	// TODO: refactor this duplicate code from encryptMessage
	client2, err := makeClient(req.URL.Host)
	if err != nil {
		log.Println("error is ", err)
		return nil, nil
	}
	log.Printf("Client to send signed message to: %#v\n", client2)

	log.Printf("POSTING Form to service: %#v\n", req.Form)
	resp, err := client2.PostForm(req.URL.String(), req.Form)
	if err != nil {
		log.Println("error is ", err)
		return nil, nil
	}
	return nil, resp
}


// makeCertConfig creates a new Client Config struct with the given CA-Cert in PEM format.
// Set the TLS-SNI to servername to those who have shared ipv4-addressess
func makeCertConfig (servername string, caCert *x509.Certificate) (*http.Transport) {
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	tr := &http.Transport{ TLSClientConfig: &tls.Config{
		RootCAs: pool,
		ServerName: servername}}
	return tr
}

// makeClient creates a http.Client struct with expected server CA-certficate configured.
// host is name[:port]
func makeClient(host string) (*http.Client, error) {
	var caCert *x509.Certificate
	var err error
	serverCred, haveIt := getServerCreds(host)
	if haveIt == true {
		// use cached certificate from previous connections.
		caCert = serverCred.caCert
	} else {
		// Get and cache server certificate from DNSSEC/DANE.
		caCert, err = GetCACert(getHostname(host))
		if err != nil { return nil, err }
		setServerCreds(host, serverCert{
			caCert: caCert,
		})
	}

	// create new client config at each connection 
	// just to make sure that we don't reuse previously used certificates when a user changes accounts
	// TODO: verify if we can change client certificates in a transport struct without reusing an
	// existing user connection. We don't want to leak the fact that these certificates belong to
	// the same person. 
	tr := makeCertConfig(getHostname(host), caCert)
	
	// Get the current active account and log in with it if we have it.
	// Otherwise, just do without client certificate
	cred := getLoggedInCreds(host)
	if cred != nil {
		cert, err := tls.X509KeyPair(cred.Cert, cred.Priv)
		if err != nil { return nil, err }
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}
	client := &http.Client{Transport: tr}
	return client, nil
}

// fetchRequest fetches the original users' request.
// adds client certificate to authenticate
func fetchRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
	// clean up the recycled header we got from the user
	req.RequestURI="" 
		
	client, err := makeClient(req.URL.Host)
	if err != nil { return nil, err }

	log.Printf("Connecting to: %s", req.URL.String())
	resp, err := client.Do(req)
	if err != nil { return nil, err }

// The rest of this function should go in a separate Response handler..
	// test if we need to authenticate.
	if resp.StatusCode != 401 {
		// nope, we're done. Exit here.
		return resp, nil
	}
	log.Printf("status code is 401\n")
	
	// We have an 401-authorization failed 
	// Test for a WWW-Authenticate: Ecca .... header.
	
	auth := ParseWWWAuthHeader(resp.Header.Get("Www-Authenticate"))
	if auth == nil {
		// No Ecca-authentication required. We're done. Exit here.
		log.Printf("No WWW-Authenticate: Ecca header, sending 401 response to client")
		return resp, nil
	}
	log.Printf("WWW-Authenticate: Ecca header found: %#v\n", auth)

	// remember registerURL for the signup-phase
	registerURLmap[req.Host] = auth["register"]

	// redirect to Ecca-Proxy user agent (ourself) to log in or sign up 
	resp = redirectToSelector(req)
	return resp, nil
}





// IsRepsonseRedirected checks to see if the response has any set of the known redirect codes
func IsResponseRedirected(resp *http.Response) bool {
	return  resp.StatusCode == 301 || 
		resp.StatusCode == 302 ||
		resp.StatusCode == 303 || 
		resp.StatusCode == 307
}

// ChangeToHttp On redirect change the response location from https to http. 
// It makes the client come back to us over http.
func ChangeToHttp(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if IsResponseRedirected(resp) {
		location, _ := resp.Location()
		if location != nil {
			if location.Scheme == "https" {
				location.Scheme = "http"
				resp.Header.Set("Location", location.String())
				println("ChangeToHttp response handler: ", ctx.Req.Host,"->",resp.Header.Get("Location"))
			}
		}
	}
	return resp
}


// DecodeMessages decodes any <message><ciphertext> tags and places the result in <cleartext>
// Decode only when ?decode=true is passed. To show that it's the proxy doing decoding.
func DecodeMessages(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp.Header.Get("Eccentric-Authentication") ==  "decryption=\"required\"" {
		println("DecodeMessages response handler has header: ", resp.Header.Get("Eccentric-Authentication"))
		// get whether the user wants to decode the encrypted messages
		decode := ctx.Req.Form.Get("decode") == "true"
		
		// create the link that allows him to set that request
		decodeURL := ctx.Req.URL
		if decodeURL.Scheme == "https" { decodeURL.Scheme = "http" }
		query := decodeURL.Query()
		query.Set("decode", "true")
		decodeURL.RawQuery = query.Encode()
		
		// get the users' Private key for this CN and hostname
		cred := getLoggedInCreds(ctx.Req.URL.Host)
		if cred == nil { 
			// we are not logged in, we don't have private keys, 
			// we cannot decode, return reponse unchanged
			return resp 
		}
		
		// Parse the response body and decode the messages from //ecca_message/ciphertext
		// store the decoded response in //ecca_message/cleartext
		doc := xmlx.New()
		err := doc.LoadStream(resp.Body, nil)
		check(err)

		list := doc.SelectNodes("", "ecca_message")
		log.Printf("list is: %#v\n", list)
		
		for _, message := range list {

			log.Printf("Message is %#v\n", message)
			ciphertextNode := message.SelectNode("", "ciphertext")
			cleartextNode  := message.SelectNode("", "cleartext")
			
			if decode == true {
				// replace cleartext with decrypted ciphertext
				//ciphertext := message.S("", "ciphertext")
				ciphertext := ciphertextNode.Value // may return nil-pointer error
				cleartext := Decrypt([]byte(ciphertext), cred.Priv)
				cleartextNode.Value = cleartext
				
				// take out the ciphertext
				ciphertextNode.Value = "Here is the decoded message:"
			} else {
				// tell user how to get decoded output
				cleartextNode.Value = ""

				// make the xml-node
				node := xmlx.NewNode(xmlx.NT_ELEMENT)
				node.Name = xml.Name{"", "a"}
				node.Attributes = append(node.Attributes,
					&xmlx.Attr{xml.Name{"", "href"}, decodeURL.String()})
				node.Value = "Message is encoded. Press here to decode"
				cleartextNode.AddChild(node)
			}
		}
		
		doc.SaveDocType = false
		xmlx.IndentPrefix = "  "
		body := doc.SaveBytes()
		resp.Body = ioutil.NopCloser(bytes.NewReader(body))
		return resp
	}
	return resp
}

// VerifyMessages verifies the signature on a message and show whether it is correct. 
// If signature is correct, show the details on the page.
// Verify only when ?verify=true is passed. To show that it's the proxy doing verifying.
func VerifyMessages(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp.Header.Get("Eccentric-Authentication") ==  "verify" {
		println("VerifyMessage response handler has header: ", resp.Header.Get("Eccentric-Authentication"))
		// get whether the user wants to decode the encrypted messages
		//verify := ctx.Req.Form.Get("verify") == "true"
		
		// create the link that allows him to set that request
		//verifyURL := ctx.Req.URL
		//if verifyURL.Scheme == "https" { verifyURL.Scheme = "http" }
		//query := verifyURL.Query()
		//query.Set("verify", "true")
		//verifyURL.RawQuery = query.Encode()
		
		// get the users' Private key for this CN and hostname
		//cred := getLoggedInCreds(ctx.Req.URL.Host)
		//if cred == nil { 
		//	// we are not logged in, we don't have private keys, 
		//	// we cannot decode, return reponse unchanged
		//	return resp 
		//}
		
		// Parse the response body and decode the messages from //ecca_message/ciphertext
		// store the decoded response in //ecca_message/cleartext
		doc := xmlx.New()
		err := doc.LoadStream(resp.Body, nil)
		check(err)

		list := doc.SelectNodes("", "ecca_signed_message")
		log.Printf("list is: %#v\n", list)
		
		for _, blog := range list {
			log.Printf("Message is %#v\n", blog)
			textNode := blog.SelectNode("", "ecca_text")
			signatureNode  := blog.SelectNode("", "ecca_signature")
			validationNode := blog.SelectNode("", "ecca_validation")
			
			//if verify == true {
			messageText := textNode.Value // may return nil-pointer error
			signature := signatureNode.Value

			if len(signature) > 0 {
				//idPEM, err := FetchIdentity(signature)
				//check(err)
				//idCert := eccentric.PEMDecode(idPEM.Bytes())
				
				// validate and fetch the FPCA certificate (openssl needs it too)
				// TODO: get FPCA Cert Tree to Root CA validated by DNSSEC/DANE
				//site, username, caCert, err := eccentric.ValidateEccentricCertificate(&idCert)
				//check(err)
				//chainPEM := eccentric.PEMEncode(caCert)
				
				//log.Printf("Identity from message is %s, %s\n", site, username)
				//log.Printf("CaCert for message is %s, %s\n", caCert.Subject.CommonName, caCert.Issuer.CommonName)
				chainPEM := slurpFile("./Cryptoblog-chain.pem")
				valid, message := Verify(messageText, signature, chainPEM)
				// TODO: verify certificate certificate chain
			
				textNode.Value = message
				signatureNode.Value = ""
				validationNode.Value = fmt.Sprintf("Signature valid: %v", valid)
			} else {
				// no signature.
				validationNode.Value = fmt.Sprintf("No signature found: Don't trust this message")
			}

			// } else {
			// 	// tell user how to get decoded output
			// 	cleartextNode.Value = ""

			// 	// make the xml-node
			// 	node := xmlx.NewNode(xmlx.NT_ELEMENT)
			// 	node.Name = xml.Name{"", "a"}
			// 	node.Attributes = append(node.Attributes,
			// 		&xmlx.Attr{xml.Name{"", "href"}, decodeURL.String()})
			// 	node.Value = "Message is encoded. Press here to decode"
			// 	cleartextNode.AddChild(node)
			// }
		}
		
		doc.SaveDocType = false
		xmlx.IndentPrefix = "  "
		body := doc.SaveBytes()
		resp.Body = ioutil.NopCloser(bytes.NewReader(body))
		return resp
	}
	return resp
}

// Initialise math.rand seed. Otherwise it behaves as math.seed(1). ouch..
func init() {
	MathRand.Seed(time.Now().UnixNano())	
}

func slurpFile(filename string) []byte {
        f, err := os.Open(filename)
        check(err)
        defer f.Close()
        contents, err := ioutil.ReadAll(f)
        check(err)
        return contents
}
