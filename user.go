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
	"errors"
	"bytes"
	"net"
	"net/http"
	"net/url"
	"io"
	"io/ioutil"
	"html/template"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os/exec"
	"strconv"
	"regexp"
	CryptoRand "crypto/rand"
	MathRand   "math/rand"
	"github.com/gwitmond/eccentric-authentication" // package eccentric
	"github.com/gwitmond/socks4a"
)

// Global config
var eccaHandlerHost = "ecca.handler"
var eccaHandlerPath = "/select"
var eccaManagerPath = "/manage"
var eccaShowCertPath= "/showcert"
//var eccaDirectConnectionPath= "/direct-connection"
var eccaDialDirectConnectionPath= "/dial-direct-connection"

func redirectToSelector(req *http.Request) (*http.Response) {
	redirectURL := url.URL{Scheme: "http", Host: eccaHandlerHost, Path: eccaHandlerPath}
	query := redirectURL.Query()
	query.Set("originalRequest", req.URL.String())
	redirectURL.RawQuery = query.Encode()
	resp := makeRedirect(req, &redirectURL)
	return resp
}

//-------------------- Selector
// Handle the user interaction to choose a certificate or create new ones.
// We show a simple form with the available credentials and allow the option to
// create a new one.

var selectTemplate = template.Must(template.New("select").Parse(
`<html>
<body>
<h1>401 - Eccentric Authentication required</h1>
<form method="POST" >
<p>Please select one of these identies {{ range . }} <input type="submit" name="login" value="{{ .CN }}">{{ else }} -none- {{ end }}<br>
<p>Or create a new one</p>
<input type="text" name="cn"><input type="submit" name="register" value="Register this name"></p><br>
<p>Or register anonymously: <input type="submit" name="anonymous" value="Anonymous"></p>
</form>
</body>
</html>`))

var embedTemplate = template.Must(template.New("embed").Parse(
`<html>

<body>
  <p>Ecca Proxy. You are logged in {{ .Hostname }} with {{ .CN }}.
     Press here to logout:
      <form method="POST" action="/manage">
        <input type="hidden" name="logout" value="{{ .Hostname }}">
        <input type="submit" name="button" value="Log out of {{ .Hostname }}">
      </form></p>
<p>Click here to go to the <a href="/manage">management page</a> of the proxy</p>
<hr>
  <iframe src="{{ .URL }}" width="100%" height="100%">
    [Your user agent does not support frames or is currently configured
     not to display frames.
     However, you may visit <a href="{{ .URL }}">{{ .URL }}</a>.
     <br>
     To log out:
      <form method="POST" action="/manage">
        <input type="hidden" name="logout" value="{{ .Hostname }}">
        <input type="submit" name="button" value="Log out of {{ .Hostname }}">
       </form>]
  </iframe>
</body>
</html>`))

// eccaHandler: learn the users' selected account and set it as logged in.
// then redirect to original request (where the user want to go to)/
func eccaHandler (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	log.Println("\n\n\nRequest is ", req.Method, req.URL.String())

	switch req.URL.Path {
	case eccaHandlerPath:
		return handleSelect(req, ctx)
	case eccaManagerPath:
		return handleManager(req, ctx)
	//case eccaDirectConnectionPath:
	//	return handleDirectConnections(req, ctx)
	case eccaDialDirectConnectionPath:
		return handleDialDirectConnection(req, ctx)
	// case eccaShowCertPath:
	// 	return handleShowCert(req, ctx)
	}
	log.Printf("Unexpected request: %#v\n", req)
	return nil, nil
}


func handleSelect (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	var originalURL *url.URL
	var err error
	req.ParseForm()
	log.Printf("Form parameters are: %v\n", req.Form)
	var originalRequest = req.Form.Get("originalRequest")
	originalURL, err = url.Parse(originalRequest)
	if err != nil {
		log.Fatal("Error parsing originalRequest parameter: ", err)
	}
	log.Println("got param (originalRequest): ", originalRequest)

	switch req.Method {
	case "GET":
		// User has no active logins.
		// Show available client certificates for URI.Host
		creds := getCreds(originalURL.Host)
		buf := execTemplate(selectTemplate, "select", creds)
		resp := makeResponse(req, 200, "text/html", buf)
		return nil, resp
	case "POST":
		var cred *credentials
		if req.Form.Get("anonymous") != "" {
			// register with random cn
			cred, err = registerAnonymous(originalURL.Host)
		}

		if req.Form.Get("register") != "" {
			// register with given cn
			cn := req.Form.Get("cn")
			cred, err = registerCN(originalURL.Host, cn)
		}

		if cn := req.Form.Get("login"); cn != "" {
			cred = getCred(originalURL.Host, cn)
		}

		if err != nil {
			resp := goproxy.NewResponse(req, "text/plain", 500, fmt.Sprintf("Error: %#v\n", err))
			return nil, resp
		}
		//TODO: make sure at least on of these actions above has success
		if (cred == nil) {
			log.Fatal("cred should not be nil")
		}
		login(originalURL.Host, *cred)

		// embed the original site in an iframe in our management frame.

		originalURL.Scheme = "http" // send users follow up requests back to us
		var data = map[string]string {
			"Hostname": originalURL.Host,
			"CN": cred.CN,
			"URL": originalURL.String(),
		}
		buf := execTemplate(embedTemplate, "embed", data)
		resp := makeResponse(req, 200, "text/html", buf)
		return nil, resp
	}
	log.Fatal("Unexpected method: ", req.Method)
	return nil, nil
}


// Register an anonymous account at the registerURL in the serverCredentials for hostname.
// Set serverCAcert from the caPEM field.
func registerAnonymous(hostname string) (*credentials, error) {
	// create a unique userid
	cn := "anon-" + strconv.Itoa(int(MathRand.Int31()))
	return registerCN(hostname, cn)
}


// Strip the portnumber from the net.URL.Host string to get the hostname
//var hostnameRE = regexp.MustCompile("^([^:]+):[0-9]+$")
var hostnameRE = regexp.MustCompile("^([^:]+)")

func getHostname(host string) (string) {
	hostname := getFirst(hostnameRE.FindStringSubmatch(host))
	if hostname == "" {
		panic("no hostname in " + host)
	}
	return hostname
}

// Strip the hostname and return the port from the hostname:port or IP-address:port
var portnrRE = regexp.MustCompile(":([0-9]+)$")

func getPort(address string) (string) {
	port := getFirst(portnrRE.FindStringSubmatch(address))
	if port == "" {
		panic("no port number in " + address)
	}
	return port
}

// Register the named accountname at the sites' CA. Uses a new private key.
func registerCN(hostname string, cn string) (*credentials, error) {
	log.Println("registering cn: ", cn, " for: ", hostname)

	priv, err := rsa.GenerateKey(CryptoRand.Reader, 1024)
	if err != nil {
		panic("cannot generate private key")
	}

	serverCred, exists := getServerCreds(hostname)
	if exists == false { panic("We don't have any server credentials for <hostname>") }
	regURL, err := url.Parse(registerURLmap[hostname])
	check(err)

	servername := getHostname(regURL.Host)

	tr := makeCertConfig(servername, serverCred.caCert)
	client := &http.Client{Transport: tr}

	cert, err := signupPubkey(client, regURL.String(), cn, priv.PublicKey)
	if err != nil { return nil, err }

	var privPEM  bytes.Buffer
	pem.Encode(&privPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	creds := credentials{
		Hostname: hostname,
		Realm: "",
		CN: cn,
		Cert: cert,
		Priv: privPEM.Bytes(),
	}
	// Register the data and set it as login certificate
	// It's what the user would expect from signup.
	setCredentials(creds)
	return &creds, nil
}


// Signup at the registerURL with the Public key and cn for username
// expect a 201-Created with a PEM certificate or
// a 403-forbidden when the cn is already in use
func signupPubkey(client *http.Client, registerURL string, cn string, pub rsa.PublicKey) ([]byte, error) {
	pubkey := publicKeyToPEM(pub)
	resp, err := client.PostForm(registerURL, url.Values{"cn": {cn}, "pubkey": {pubkey}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("error reading response.body")
	}

	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("Username '%s' is already taken. Please choose another", cn)
	}

	if resp.StatusCode == 201 {
		_ =  pemDecodeCertificate(body) // decode and panic if it fails to decode properly.
		return body, nil
	}

	log.Printf("SignPubKey got response: %#v\n", resp)

	return nil, errors.New(fmt.Sprintf("Some error happened: %s ", body))
}

//------------------ Manager
// show current logins and allow for logouts.

var showLoginTemplate = template.Must(template.New("showLogins").Parse(
`<html>
<head>
  <style>
    td { border-bottom: 1px solid gray;}
  </style>
</head>
<body>
 <h1>Manage your Eccentric Authentication logins</h1>
 <h3>Current logins</h3>
  {{ if .current }}
  <p>These are your current logins.
   <table>
      <tr><th>Host</th><th>Account</th><th>Action</th></tr>
    {{range $hostname, $cred := .current }}
      <tr><td>{{ $hostname }}</td>
          <td>{{ $cred.CN }}</td>
          <td>
            <form method="POST">
              <input type="hidden" name="logout" value="{{ .Hostname }}">
              <input type="submit" name="button" value="Log out of {{ .Hostname }}">
            </form>
          </td>
      </tr>
    {{ end }}
   </table>
 {{ else }}
   <p><em>You are not logged in anywhere.</em></p>
 {{ end }}

 <h3>All your accounts at hosts</h3>
   <p>These are all your accounts we have private keys for.
     <br>You can log in to any. Just click on the host name to get there anonymously.
     <br>You'll get to choose the account when the sites asks for one.
     <table>
      <tr><th>Host</th><th>Accounts</th><!-- <th>Show full certificate</th> -->
      {{range $hostname, $creds := .allCreds }}
         <tr>
          <td><a href="http://{{ $hostname }}/">{{ $hostname }}</a></td>
         <td>{{ range $creds }} {{ .CN }} <br> {{ end }}</td>
         <!-- <td>{{ range $creds }} <a href="/showcert?cn={{.CN}}@@{{.Hostname}}">show {{.CN}} </a><br> {{ end }}</td> -->
        </tr>

    {{ else }}
      <tr><td colspan="2">You have no accounts anywhere. </td></tr>
    {{ end }}
    </table>
 </body>
</html>`))


func handleManager (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	req.ParseForm()
	log.Printf("Form parameters are: %v\n", req.Form)

	switch req.Method {
	case "GET":
		creds := mapAllCreds(getAllCreds())
		buf  := execTemplate(showLoginTemplate, "showLogins", map[string]interface{}{
			"current": logins,
			"allCreds": creds,
		})
		resp := makeResponse(req, 200, "text/html", buf)
		log.Println("Show logins")
		return nil, resp
	case "POST":
		if hostname := req.Form.Get("logout"); hostname != "" {
			// log out from hostname
			logout(hostname)
			log.Println("Logged out of ", hostname)
		}

		// redirect back to ourself
		resp := makeRedirect(req, req.URL)
		return nil, resp
	}

	log.Fatal("Unexpected method: ", req.Method)
	return nil, nil
}


func handleDirectConnections(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	return nil, goproxy.NewResponse(req,
		goproxy.ContentTypeText, http.StatusOK,
		"Ecca Proxy message: Expect a list of your open ports to others to connect to you.")
}


func handleDialDirectConnection(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// see who we're gonna call
	req.ParseForm()
	switch req.Method {
	case "POST":
		connectionID := req.Form.Get("connectionID")
		if connectionID == "" {
			log.Fatal("Missing connectionID")
		}
		log.Printf("handleDirectConnection has connectionID: %s", connectionID)

		invitation := getInvitation(connectionID)
		if invitation == nil {
			log.Fatal("Wrong connectionID")
		}

		//log.Printf("invitation is: %#v", invitation)

		inviteeName, inviteeHost, err := eccentric.ParseCN(invitation.InviteeCN)
		check(err)
		log.Printf("invitee is: %v, %v", inviteeName, inviteeHost)

		// fetch our own identity
		ourCreds := getLoggedInCreds(inviteeHost)
		if ourCreds == nil {
			// should not happen, as we need to be logged in to get the dial-button, but anyway
			log.Println("Site says to dial a direct connection but you are not logged in.")
			return nil, goproxy.NewResponse(req,
				goproxy.ContentTypeText, http.StatusInternalServerError,
				"Ecca Proxy error: Site says to dial a direct connection but you haven't logged in. Please log in first, then try again.")
		}

		log.Printf("our creds are: %v\n", ourCreds.CN)
		ourCert, err := tls.X509KeyPair(ourCreds.Cert, ourCreds.Priv)
		check(err)
		//log.Printf("ourCert is: %#v", ourCert)

		// call out and show the response
		response := dialDirectConnection(invitation, ourCert)
		return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusOK, response)
	}

	log.Fatal("Unexpected method: ", req.Method)
	return nil, nil
}


// dial the direct connection and start a conversation
func dialDirectConnection(invitation *DCInvitation, ourCert tls.Certificate) string {
	fpca, err := eccentric.ParseCertByteA(invitation.ListenerFPCAPEM)
	check(err)
	log.Printf("FPCA is %v", fpca.Subject.CommonName)

	pool := x509.NewCertPool()
	pool.AddCert(fpca)

	log.Printf("calling: %v at %v", invitation.ListenerCN, invitation.Endpoint)
	clientConfig := tls.Config{
		ServerName: invitation.ListenerCN,
		Certificates: []tls.Certificate{ourCert},
		RootCAs: pool,
	}
	// direct ip endpoint
	//conn , err := tls.Dial("tcp", invitation.Endpoint, &clientConfig)
	//check(err)

	// Connect to the onion endpoint
	socks := &socks4a.Socks4a {
		Network: "tcp",
		Address: "127.0.0.1:9050",
	}
	conn, err := socks.Dial(invitation.Endpoint)
	check(err)

	// start TLS over the onion connection
	tlsconn := tls.Client(conn, &clientConfig)
	err = tlsconn.Handshake()
	check(err)

	go startPayload(tlsconn)
	return "Started Simple Chat app."
}

// Start the simple chat app on the encrypted channel.
func startPayload(tlsconn *tls.Conn){
	// Create listener socket for the simple chat
	socket, err := net.Listen("tcp", "[::1]:0")
	check (err)
	port := getPort(socket.Addr().String())

	// start the chat app and point it to our socket
	cmd := exec.Command("uxterm", "-e", "nc", "-6", "::1", port)

	err = cmd.Start() // start asynchronously
	check(err)

	// wait for it to connect
	app, err := socket.Accept()
	check(err)

	// show a welcome message
	app.Write([]byte("Connected, chat away!\n---------------------\n"))

	// copy the TLS-connection to the chat app and back
	go io.Copy(app, tlsconn)
	go io.Copy(tlsconn, app)

	// wait for it to finish
	err = cmd.Wait()
	check(err)

	// Close all, including the socket and the TLS channel.
	// We run this only once.
	app.Close()
	socket.Close()
	tlsconn.Close()
}

// var handleInitiateDirectConnectionTemplate = template.Must(template.New("initiateDirectConnection").Parse(
// `<html>
// <body>
//  <h1>Creating a direct connection</h1>
//   <h3>Awaiting</h3>
//    <p>Activity log:
//    <ul>
//    <li>creating a listening port at {{ .port }}.</li>
//    <li>sent inviation to {{ .addressee }}.</li>
//    <li>awaiting connection...</li>
//    </ul></p>
//    <hr/>
//    <p>This listening port stays up until you close the Ecca-proxy. You can browse to other pages or site.
//       Don't worry closing this page, when the addresse connects you'll get a new window.</p>
//  </body>
// </html>`))



// func handleShowCert (req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
// 	cn := req.FormValue("cn")

// 	switch req.Method {
// 	case "GET":
// 		username, hostname, err := eccentric.ParseCN(cn)
// 		check(err)
//  		creds := getCred(hostname, username)
// // TODO: map the binary cred.Cert into a x509.Certificate
// 		certs := mapCredsToCerts(creds)
// 		buf  := execTemplate(showFullCertTemplate, "showFullCert", map[string]interface{}{
// 			"certs": certs,
// 		})
// 		resp := makeResponse(req, 200, "text/html", buf)
// 		log.Println("Show full certificate")
// 		return nil, resp
// 	}

// 	log.Fatal("Unexpected method: ", req.Method)
// 	return nil, nil
// }

// var showFullCertTemplate = template.Must(template.New("showFullCert").Parse(
// `<html>
// <body>
//  <h1>Manage your Eccentric Authentication logins</h1>
//  <h3><Full Certificate/h3>
//    <p>This is the certificate

//     <table>
//       <tr><th>Key</th><th>Value</th></tr>
//       {{range $cert := .certs }}
//          <tr> <td> CN </td> <td> {{ $cert.CN }}</td> </tr>
//     {{ else }}
//       <tr><td colspan="2">Wrong cn</td></tr>
//     {{ end }}
//     </table>
//  </body>
// </html>`))

// func mapCredsToCerts(cred *credentials) (certs []x509.Certificate) {
// 	if cred == nil { return }
// 	cert, err := eccentric.ParseCertByteA(cred.Cert)
// 	check(err)
// 	certs = append(certs, *cert)
// 	return
// }

func mapAllCreds(allCreds []credentials) (map[string][]credentials) {
	creds := map[string][]credentials{}
	for _, cred := range allCreds {
		hostname := cred.Hostname
		creds[hostname] = append(creds[hostname], cred)
	}
	return creds
}

//-- utils

func makeRedirect(req *http.Request, redirectURL *url.URL) (*http.Response) {
	log.Println("redirecting to ", redirectURL.String())
	resp := &http.Response{}
	resp.Request = req
	resp.TransferEncoding = req.TransferEncoding
	resp.Header = make(http.Header)
	resp.Header.Add("Content-Type", "text/html")
	resp.Header.Add("Location", redirectURL.String())
	resp.StatusCode = 302

	body := "Redirect to " + redirectURL.String()
	buf := bytes.NewBufferString(body)
        resp.ContentLength = int64(buf.Len())
        resp.Body = ioutil.NopCloser(buf)
        return resp
}


func makeResponse(req *http.Request, code int, contType string, buf *bytes.Buffer ) (*http.Response) {
	resp := &http.Response{}
	resp.Request = req
	resp.StatusCode = code
	resp.TransferEncoding = req.TransferEncoding
	resp.Header = make(http.Header)
	resp.Header.Add("Content-Type", contType)
	resp.Body = ioutil.NopCloser(buf)
	return resp
}


func execTemplate(template *template.Template, name string, data interface{}) (*bytes.Buffer) {
	buf := new(bytes.Buffer)
	err := template.ExecuteTemplate(buf, name, data)
	if err != nil {
		log.Fatal("error executing template: ", err)
	}
	return buf
}
