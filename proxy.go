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
	"path"
	"path/filepath"
	"io/ioutil"
	"bytes"
	"encoding/xml"
	"html/template"
	"github.com/gwitmond/go-pkg-xmlx"
	"github.com/gwitmond/unbound"
	"github.com/gwitmond/eccentric-authentication" // package eccentric
)

// map between sitename and the url where to sign up for a certificate
var registerURLmap = map[string]string{}

var port = flag.Int("p", 8000, "port to listen to")
var ip4ListenAddr = flag.String("4", "127.0.0.1", "IPv4 address to listen on")
var ip6ListenAddr = flag.String("6", "[::1]", "IPv6 address to listen on")

var verbose = flag.Bool("v", true, "should every proxy request be logged to stdout")
//var registryUrl = flag.String("registry", "https://registry-of-honesty.eccentric-authentication.org:1024/", "The Registry of (dis)honesty to query for duplicate certificates.")
var datastore = flag.String("datastore", "ecca-proxy.sqlite3", "The location where to store the identities and invitations")
var torSocksPort = flag.String("torsocks", "127.0.0.1:9050", "The address of the TorSocks port to connect to for outbound connections")
var torControlPort = flag.String("torcontrolport", "127.0.0.1:9051", "The address of the Tor ControlPort to create hidden services")
var torControlPassword = flag.String("torcontrolpassword", "geheim", "The password to authenticate at the Tor ControlPort")

var baseDir string // use this to find /templates and /static subdirs

func main() {
        var err error
        execPath, err := os.Executable()
	check(err)
	realPath, err := filepath.EvalSymlinks(execPath)
	check(err)
	baseDir = path.Dir(realPath) + "/"
	log.Printf("baseDir is: %v\n", baseDir)
	initialiseTemplates(baseDir)

	flag.Parse()
	init_datastore(*datastore)

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

	restartAllTorListeners()

	log.Printf("Starting proxy access at %s:%d and at %s:%d\n", *ip6ListenAddr, *port, *ip4ListenAddr, *port)
	log.Printf("Configure your browser to use one of those as http-proxy.\n")
	log.Printf("Then browse to http://dating.wtmnd.nl/\n")
	log.Printf("Use http (not https) to benefit from this proxy.\n")
	log.Printf("For assistence, please see: http://eccentric-authentication.org/contact.html\n")

	server6 := &http.Server {
		Addr: fmt.Sprintf("%s:%d", *ip6ListenAddr, *port),
		Handler: proxy,
	}
	// TODO: disable KeepAlives when your golang version supports it
	//server6.SetKeepAlivesEnabled(false)

	server4 := &http.Server {
		Addr: fmt.Sprintf("%s:%d", *ip4ListenAddr, *port),
		Handler: proxy,
	}
	// TODO: disable KeepAlives when your golang version supports it
	//server4.SetKeepAlivesEnabled(false)

	// run or die. Try ipv6 first
	go server6.ListenAndServe()
	log.Fatal(server4.ListenAndServe())
}

// eccaProxy: proxy the user requests and authenticate with the credentials we know.
func eccaProxy (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	//log.Println("\n\n\nRequest is ", req.Method, req.URL.String())
	ctx.Logf("Start-of-eccaProxy handler")
	for _, c := range req.Cookies() {
		ctx.Logf("Cookie send by the client is: %#v", c.Name)
	}

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

	// Check for POST method with 'encrypt', 'sign' or 'initiate-direct-connection' parameter.
	if req.Method == "POST" {
		if req.Form.Get("initiate-direct-connection") == "required" {
			// create a direct connection listener, awaiting reply
			return initiateDirectConnection(req)
		} else if req.Form.Get("encrypt") == "required" {
			// transparantly encrypt and sign for a private message
			return encryptMessage(req)
		} else if req.Form.Get("sign") == "required" || req.Form.Get("sign") == "optional" {
			// transparently sign the message before publication
			return signMessage(req, ctx)
		}
	}

	// Fetch the request from upstream
	resp, err := fetchRequest(req, ctx)
	if err != nil {
		ctx.Warnf("There was an error fetching the users' request: %v", err)
		return req, goproxy.NewResponse(req,
			goproxy.ContentTypeText, http.StatusInternalServerError,
			"Some server error!")
	}

	ctx.Logf("response is %#v", resp)
	for _, c := range resp.Cookies() {
		ctx.Logf("Cookie send by the server is: %#v\n", c.Name)
	}
	ctx.Logf("End-of-eccaProxy handler")
	//log.Printf("Sleeping for 10 seconds...\n")
	//time.Sleep(10 * time.Second)
	return nil, resp // let goproxy send our response
}

// encrypt a message with a public key from a certificate in the url.
func encryptMessage(req  *http.Request)  (*http.Request, *http.Response) {
	// First, check our credentials
	// get the current logged in account (and private key)

	// TODO: change to use the server certificate Root CA identity. Not the req.URL.Host.
	// log.Printf("req.tls.ConnectionState is %#v", req.TLS) => returns nil
	// Need to connect to the site, fetch and check the server cert;
	// Then we know the site's cert and RootCa;
	// With that rootCA we fetch our credentials.

	log.Printf("req.URL.Host is: %v\n ", req.URL.Host)
	creds := getLoggedInCreds(req.URL.Host)

	if creds == nil {
		log.Println("Form says to encrypt and sign a message but no user is logged in.\nConfigure server to require login before handing the form.\nHint: Use the ecca.LoggedInHandler.")
		return nil, goproxy.NewResponse(req,
			goproxy.ContentTypeText, http.StatusInternalServerError,
			"Ecca Proxy error: Server says to sign your message but you haven't logged in. Please log in first, then type your message again. Later we might cache your data and redirect you to the login-screen.")
	}
	log.Printf("creds are: %v\n", creds.CN)

	// Second, fetch the recipients public key from where the server tells us to expect it.
	certPEM, err := fetchCertificatePEM( req.Form.Get("certificate_url"))
	check(err)

	// Do the actual signing and encrypting
	cleartext := req.Form.Get("cleartext")
	ciphertext := SignAndEncryptPEM(creds.Priv, creds.Cert, certPEM, cleartext)
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
	// cleartext is the message, for now we ignore the title and other fields in the signature

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
		// TODO: show this to the user and confirm to prevent mistakes.
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


func initiateDirectConnection (req *http.Request) (*http.Request, *http.Response) {
	switch req.Method {
	case "POST":
		// Test the simplest things first, the application parameter :-)
		application := req.Form.Get("application")
		if application != "chat" && application != "voice" {
			log.Printf("Wrong application, only chat/voice allowed, got %#v", application)
			return nil, goproxy.NewResponse(req,
				goproxy.ContentTypeText, http.StatusInternalServerError,
				"Ecca Proxy error: Wrong application, only chat/voice allowed.")
		}

		// get the current logged in account (and private key)
		// TODO: get these from the site
		log.Printf("req.URL.Host is: %v\n ", req.URL.Host)

		ourCreds := getLoggedInCreds(req.URL.Host)
		if ourCreds == nil {
			log.Println("Site says to initiate a direct connection but you are not logged in.\nConfigure server to require login before handing the form.\nHint: Use the ecca.LoggedInHandler.")
			return nil, goproxy.NewResponse(req,
				goproxy.ContentTypeText, http.StatusInternalServerError,
				"Ecca Proxy error: Site says to initiate a direct connection but you haven't logged in. Please log in first, then try again.")
		}
		log.Printf("our creds are: %v\n", ourCreds.CN)

		ourCert, err := eccentric.ParseCertByteA(ourCreds.Cert)
		check(err)

		// get the one who signed our cert.
		ourFPCACert, err := eccentric.FetchCN(ourCert.Issuer.CommonName)
		check(err)

		// Fetch certificate of addressee
		// First, fetch the recipients public key from where the server tells us to expect it.
		recipCertURL := req.Form.Get("certificate_url")
		recipCertPEM, err := fetchCertificatePEM(recipCertURL)
		check(err)
		recipCert, err := eccentric.ParseCertByteA(recipCertPEM)
		check(err)

		// TODO: Check it for unicity/MitM at the registry-of-honesty.eccentric-authentication.org
		// TODO: Store the results for later

		// Create (and start) a Tor-Listener for this recipient
		listener := createTorListener(ourCreds, recipCert, application)
		// Store listening address in database to listen again at restart of the proxy.
		// I.E. make these listening endpoints permanent.
		listener.Store()

		hostname := getHostname(ourCreds.Hostname)
		invitation := DCInvitation{
			Application: application,
			InviteeCN: recipCert.Subject.CommonName,
			Endpoint: listener.OnionAddress,
			ListenerCN: ourCreds.CN + "@@" + hostname,
			ListenerFPCAPEM: eccentric.PEMEncode(ourFPCACert),
		}
		log.Printf("Make invitation from %v, at %v to %v", invitation.ListenerCN, invitation.Endpoint, invitation.InviteeCN)

		var message = encodeInvitation(invitation)
		ciphertext := SignAndEncryptPEM(ourCreds.Priv, ourCreds.Cert, recipCertPEM, message)
		req.Form.Set("ciphertext", string(ciphertext))
		// Send the invitation to site for delivery to the recipient
		// TODO: refactor this duplicate code from encryptMessage
		client2, err := makeClient(req.URL.Host)
		if err != nil {
			log.Println("error is ", err)
			return nil, nil
		}
		log.Printf("Client to send invitation to: %#v\n", client2)

		resp, err := client2.PostForm(req.URL.String(), req.Form)
		if err != nil {
			log.Println("error is ", err)
			return nil, nil
		}
		return nil, resp
	}

	log.Printf("Unexpected method: %#v", req)
	return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadRequest, "Unexpected method.")
}


// makeCertConfig creates a new Client Config struct with the given CA-Cert in PEM format.
// Set the TLS-SNI to servername to those who have shared ipv4-addressess
func makeCertConfig (servername string, caCert *x509.Certificate) (*http.Transport) {
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	tr := &http.Transport{ TLSClientConfig: &tls.Config{
		RootCAs: pool,
		ServerName: servername,
		// TODO: enable DisableKeepAlives when your golang supports it.
		//DisableKeepAlives: true,
	}}
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
		caCert, err = unbound.Ctx.GetCACert(getHostname("_443._tcp." + host))
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
	ctx.Logf("OldRequestURI is %s", req.RequestURI)
	req.RequestURI=""

	client, err := makeClient(req.URL.Host)
	if err != nil { return nil, err }

	ctx.Logf("Connecting to: %s", req.URL.String())
	resp, err := client.Do(req)
	if err != nil { return nil, err }

// The rest of this function should go in a separate Response handler..
	// test if we need to authenticate.
	if resp.StatusCode != 401 {
		// nope, we're done. Exit here.
		return resp, nil
	}
	ctx.Logf("status code is 401")

	// We have an 401-authorization failed
	// Test for a WWW-Authenticate: Ecca .... header.

	auth := ParseWWWAuthHeader(resp.Header.Get("Www-Authenticate"))
	if auth == nil {
		// No Ecca-authentication required. We're done. Exit here.
		log.Printf("No WWW-Authenticate: Ecca header, sending 401 response to client")
		return resp, nil
	}
	ctx.Logf("WWW-Authenticate: Ecca header found: %#v", auth)

	// remember registerURL for the signup-phase
	registerURLmap[req.Host] = auth["register"]

	// redirect to Ecca-Proxy user agent (ourself) to log in or sign up
	resp.Body.Close()
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
		// decode = true // peg at true to always decode messages. it's easier at testing.

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
		resp.Body.Close();

		list := doc.SelectNodes("", "ecca_message")
		for _, message := range list {
			// log.Printf("Message is %#v\n", message)
			ciphertextNode := message.SelectNode("", "ciphertext")
			cleartextNode  := message.SelectNode("", "cleartext")
			senderNode     := message.SelectNode("", "from")

			if decode == true {
				// replace cleartext with decrypted ciphertext
				ciphertext := ciphertextNode.GetValue()
				cleartext, senderCert, err := DecryptAndVerify([]byte(ciphertext), cred.Priv)
				check(err)
				l := len(cleartext)
				log.Printf("cleartext (%v) is: %v", l, cleartext[:min(l,50)])
				log.Printf("Identity from message is %s\n", senderCert.Subject.CommonName)
				sender := senderCert.Subject.CommonName
				if senderNode.GetValue() != sender {
					senderNode.SetValue(senderNode.GetValue() + " is actually from: " + sender)
				}

				// Check for eccadirect URLs and replace these with a button to click.
				invitationButton := findDirectConnectionInvitation(cleartext, senderCert)
				if invitationButton != nil {
					cleartextNode.SetValue("") // clear
					cleartextNode.AddChild(invitationButton)
					ciphertextNode.SetValue("Here is the decoded invitation:")
				} else {
					// No invitation, show the cleartext message
					cleartextNode.SetValue(template.HTMLEscapeString(cleartext))
					ciphertextNode.SetValue("Here is the decoded message:")
				}
			} else {
				// tell user how to get decoded output
				cleartextNode.SetValue("")

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

// findDirectConnectionInvitation checks the received cleartext for a valid invitation.
// It will be replaced by a form with a button to create the connection
// Returns either the button for an invitation, or nil to signal the original cleartext to be shown
func findDirectConnectionInvitation(cleartext string, senderCert *x509.Certificate) *xmlx.Node {
	// for now, the whole message must be the base64 gob encoded DCInvitation
	log.Printf("cleartext is [%#v]", cleartext[:min(len(cleartext),50)])

	// See if we can decode it into a invitation-struct
	invitation := parseInvitation(cleartext)
	if invitation == nil {
		// it's not an invitation, signal that.
		return nil
	}

	log.Printf("Received Invitation from: %v, at %v, to %v", invitation.ListenerCN, invitation.Endpoint, invitation.InviteeCN)

	// Create a button to connect to inviter
	// Save the invitation in a table under a random token
	// to prevent sites from creating dial-buttons themselves.
	token := storeInvitation(invitation)

	// Create a form to dial that token.
	form := makeNode("form", map[string]string{
		"method": "POST",
		"action": "http://ecca.handler" + eccaDialDirectConnectionPath})
	connID := makeNode("input", map[string]string{
		"type": "hidden",
		"name": "connectionID",
		"value": token})
	submit := makeNode("input", map[string]string{
		"type": "submit",
		"value": fmt.Sprintf("Connect me to %s for %s", senderCert.Subject.CommonName, invitation.Application)})
	form.AddChild(connID)
	form.AddChild(submit)

	return form
}


// makeNode makes an xmlx.Node with the given attributes
func makeNode(name string, attrs map[string]string) *xmlx.Node {
	node := xmlx.NewNode(xmlx.NT_ELEMENT)
	node.Name = xml.Name{"", name}
	for key, value := range attrs {
		node.Attributes = append(node.Attributes,
			&xmlx.Attr{xml.Name{"", key}, value})
	}
	return node
}

var directConnectionTemplate = template.Must(template.New("directConnection").Parse(
`<form action="/ecca.handler/connect-direct" method="POST">
   <input type="hidden" name="connectionID" value="{{ .connectionID }}">
   <input type="submit" name="submit" value="Connect me to {{ .remoteParty }}">
</form>`))

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
		resp.Body.Close()

		list := doc.SelectNodes("", "ecca_signed_message")
		// log.Printf("list is: %#v\n", list)

		for _, blog := range list {
			// log.Printf("Message is %#v\n", blog)
			// log.Printf("Children are: ")
			// for _, child := range blog.Children {
			//	log.Printf("\t%#v\n", child.Name)
			// }
			textNode := blog.SelectNode("", "ecca_text")
			signatureNode  := blog.SelectNode("", "ecca_signature")
			validationNode := blog.SelectNode("", "ecca_validation")
			// log.Printf("textNode is %#v\b", textNode)
			// log.Printf("Children are: ")
			// for _, child := range textNode.Children {
			//	log.Printf("\t%#v\n", child)
			// }

			//if verify == true {
			messageText := textNode.GetValue()
			signature := signatureNode.GetValue()
			// log.Printf("message is %#v\n", messageText)
			// log.Printf("signature is %#v\n", signature)

			if len(signature) > 0 {
				idCert := FetchIdentity(signature)
				log.Printf("Identity from message is %s\n", idCert.Subject.CommonName)

				// get our rootCert from the connection credentials
				host := ctx.Req.URL.Host
				serverCred, haveIt := getServerCreds(host)
				if haveIt == false {
					// We should have it as we are connected to the server via TLS
					panic("We don't have serverCreds that we expect.")
				}
				rootCert := serverCred.caCert

				// Fetch the chain (and validate that our idCert is a valid Eccentric cert)
				chain, err := eccentric.ValidateEccentricCertificateChain(idCert, rootCert)
				check(err)

				// Let OpenSSL validate the message signature and return the signed message
				valid, message := Verify(messageText, signature, chain)

				textNode.SetValue(template.HTMLEscapeString(message))
				signatureNode.SetValue("")
				validationNode.SetValue(fmt.Sprintf("Signature valid: %v", valid))
			} else {
				// no signature.
				validationNode.SetValue(fmt.Sprintf("No signature found: Don't trust this message"))

				// Disable all XML-elements with an ecca_id_ref that matches the ecca_id of the signed message
				// This is to disable the send-private-message buttons.
				id := blog.As("*", "ecca_id")
				if id != "" {
					refs := doc.SelectNodesNameAttr("*", "*", "ecca_id_ref")
					for _, ref := range refs {
						idAttr := ref.SelectAttr("*", "ecca_id_ref")
						if idAttr.Value == id {
							classAttr := ref.SelectAttr("*", "class")
							if classAttr != nil {
								ref.SetAttr("class", classAttr.Value + " ecca_disabled")
							}
							ref.RemoveAttr("href")
						}
					}
				}
			}

			// } else {
			// 	// tell user how to get decoded output
			// 	cleartextNode.SetValue("")

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

func min(a, b int) int {
  if a <= b {
    return a
  } else {
    return b
  }
}