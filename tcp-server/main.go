// package main

// import (
// 	"fmt"
// 	"io"
// 	"os"
// 	"strings"

// 	"log"

// 	"net"
// )

// func main() {
// 	arguments := os.Args
// 	if len(arguments) == 1 {
// 		fmt.Println("Please provide a port number!")
// 		return
// 	}

// 	PORT := ":" + arguments[1]
// 	l, err := net.Listen("tcp4", PORT)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer l.Close()

// 	for {
// 		c, err := l.Accept()
// 		if err != nil {
// 			fmt.Println(err)
// 			return
// 		}
// 		go handleConnection(c)
// 	}
// }

// func handleConnection(c net.Conn) {
// 	fmt.Printf("Serving %s\n", c.RemoteAddr().String())
// 	packet := make([]byte, 4096)
// 	tmp := make([]byte, 4096)
// 	defer c.Close()
// 	for {
// 		_, err := c.Read(tmp)
// 		if err != nil {
// 			if err != io.EOF {
// 				fmt.Println("read error:", err)
// 			}
// 			println("END OF FILE")
// 			break
// 		}
// 		packet = append(packet, tmp...)
// 		if strings.Split(string(tmp), " ")[0] == "CONNECT" {
// 			fmt.Println("connect")
// 			packet = []byte("HTTP/1.1 200 OK\n\n")
// 			num, _ := c.Write(packet)
// 			fmt.Printf("Wrote back %d bytes, the payload is %s\n", num, string(packet))
// 			packet = make([]byte, 4096)
// 			continue
// 		} else {
// 			fmt.Printf("Not Connect, %s\n", strings.Split(string(tmp), " ")[0])
// 		}
// 	}
// 	num, _ := c.Write(packet)

// 	fmt.Printf("Wrote back %d bytes, the payload is %s\n", num, string(packet))

// }

// package main

// import (
// 	"fmt"
// 	"io"
// 	"net"
// 	"net/http"
// 	"time"
// )

// func handleTunneling(w http.ResponseWriter, req *http.Request) {
// 	fmt.Printf("%+v\n\n", req)
// 	if req.Method != http.MethodConnect {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	// Establish connection to the target host
// 	destConn, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusServiceUnavailable)
// 		return
// 	}
// 	defer destConn.Close()

// 	// Respond to the client that connection is established
// 	w.WriteHeader(http.StatusOK)
// 	hijacker, ok := w.(http.Hijacker)
// 	if !ok {
// 		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
// 		return
// 	}
// 	clientConn, bufrw, err := hijacker.Hijack()
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	defer clientConn.Close()

// 	// Tunnel traffic between client and target
// 	go transfer(destConn, bufrw)
// 	go transfer(clientConn, destConn)
// }

// func transfer(destination io.WriteCloser, source io.Reader) {
// 	defer destination.Close()
// 	// defer source.
// 	io.Copy(destination, source)
// }

// func main() {
// 	// Set up handler for CONNECT requests
// 	http.HandleFunc("/", handleTunneling)

// 	// Start the server
// 	fmt.Println("Server started on :8080")
// 	err := http.ListenAndServe(":8080", nil)
// 	if err != nil {
// 		panic(err)
// 	}
// }

// package main

// import (
// 	"bufio"
// 	"encoding/base64"
// 	"flag"
// 	"io"
// 	"log"
// 	"net"
// 	"net/http"
// 	"strings"
// 	"time"
// )

// func transfer(destination io.WriteCloser, source io.ReadCloser) {
// 	defer destination.Close()
// 	defer source.Close()
// 	io.Copy(destination, source)
// }

// func main() {
// 	host := flag.String("host", ":8080", "host proxy server")
// 	auth := flag.String("auth", "", "authentication to for client to connect proxy, ex: username:password")

// 	flag.Parse()

// 	listener, err := net.Listen("tcp", *host)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer listener.Close()

// 	for {
// 		conn, err := listener.Accept()
// 		if err != nil {
// 			log.Fatal(err)
// 		}

// 		go func(c net.Conn) {
// 			br := bufio.NewReader(c)
// 			req, err := http.ReadRequest(br)
// 			if err != nil {
// 				log.Println("buffer: ", err)
// 				return
// 			}

// 			if req.Method == http.MethodConnect {
// 				if *auth != "" {
// 					clientAuth := req.Header.Get("Proxy-Authorization")
// 					if clientAuth == "" {
// 						response := &http.Response{
// 							StatusCode: http.StatusProxyAuthRequired,
// 							ProtoMajor: 1,
// 							ProtoMinor: 1,
// 						}
// 						response.Write(c)
// 						c.Close()
// 						return
// 					}

// 					serverAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(*auth))
// 					if clientAuth != serverAuth {
// 						response := &http.Response{
// 							StatusCode: http.StatusUnauthorized,
// 							ProtoMajor: 1,
// 							ProtoMinor: 1,
// 						}
// 						response.Write(c)
// 						c.Close()
// 						return
// 					}
// 				}

// 				response := &http.Response{
// 					StatusCode: 200,
// 					ProtoMajor: 1,
// 					ProtoMinor: 1,
// 				}
// 				response.Write(c)

// 				destConn, err := net.DialTimeout("tcp", req.URL.Host, 10*time.Second)
// 				if err != nil {
// 					response := &http.Response{
// 						StatusCode: http.StatusRequestTimeout,
// 						ProtoMajor: 1,
// 						ProtoMinor: 1,
// 					}
// 					response.Write(c)
// 					return
// 				}

// 				go transfer(destConn, c)
// 				go transfer(c, destConn)

// 			} else {
// 				response := &http.Response{
// 					StatusCode: http.StatusRequestTimeout,
// 					ProtoMajor: 1,
// 					ProtoMinor: 1,
// 					Body:       io.NopCloser(strings.NewReader("hello world")),
// 				}
// 				response.Write(c)
// 				c.Close()
// 				return
// 			}
// 		}(conn)
// 	}
// }

package main

import (
	// "crypto/ecdsa"
	// "crypto/ecdsa"
	// "crypto/elliptic"
	// "crypto/sha256"

	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"strconv"
	"strings"

	// "crypto/ecdsa"
	// "crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"time"

	// "log"
	"net"
	"net/http"
	// "net/http/httputil"
	// "net/url"
)

type ProxyHandler struct{}

// var proxy *httputil.ReverseProxy

func (p ProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	// fmt.Printf("%+v\n\n", req)
	if req.Method == http.MethodConnect {
		p.handleConnect(w, req)
		return
	}
	// http.DefaultServeMux.ServeHTTP(w, req) // Handle other requests as usual
	p.handleRequest(w, req)
}

func (p ProxyHandler) handleRequest(w http.ResponseWriter, req *http.Request) {
	//proxy.ServeHTTP(w, req)
}

func (p ProxyHandler) handleConnect(w http.ResponseWriter, req *http.Request) {
	// destConn, err := net.Dial("tcp", req.URL.Host)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusServiceUnavailable)
	// 	return
	// }
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	if req.URL.Host != "emanor-oie.oktapreview.com:443" {
		fmt.Printf("Not Inspecting %s\n", req.URL.Host)
		destConn, err := net.Dial("tcp", req.URL.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		go transfer(destConn, clientConn)
		go transfer(clientConn, destConn)
		return
	}

	// fmt.Printf("readerWriter: %+v\n", readerWriter)
	// go transfer(destConn, clientConn)
	// go transfer(clientConn, destConn)

	// testing

	// cert, err := tls.LoadX509KeyPair("/Users/erikmanor/SSL/test_proxy/proxy.crt", "/Users/erikmanor/SSL/test_proxy/proxy.key")
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}

	fmt.Printf("req.URL.Host: %v\n\n", req.URL.Host)
	//go processInspectedOrigin(clientConn, destConn, "emanor-oie.oktapreview.com:443")
	go processInspectedOrigin(clientConn, req.URL.Host)
	////// REMOVE Start
	// rootCert, rootKey, rootErr := loadRootCert("/Users/erikmanor/SSL/origin/9.2024/rootCA.crt", "/Users/erikmanor/SSL/origin/9.2024/rootCA.key")
	// if rootErr != nil {
	// 	fmt.Printf("Error loadRootCert(): %+v\n", rootErr)
	// }
	// leafCert, _, leafKey, leafErr := generateLeafCertificate(rootCert, rootKey.(*rsa.PrivateKey))
	// if leafErr != nil {
	// 	fmt.Printf("Error generateLeafCertificate(): %+v\n", leafErr)
	// }

	// tlsCert := tls.Certificate{
	// 	Certificate: [][]byte{leafCert.Raw},
	// 	PrivateKey:  leafKey,
	// 	Leaf:        leafCert,
	// }
	// tlsConfig := tls.Config{
	// 	Certificates: []tls.Certificate{tlsCert},
	// 	MaxVersion:   tls.VersionTLS12,
	// }

	// tlsConn := tls.Server(clientConn, &tlsConfig)
	// // fmt.Printf("tlsConn: %+v\n", tlsConn)
	// err = tlsConn.Handshake()
	// if err != nil {
	// 	fmt.Printf("Handshake Error: %+v\n", err)
	// 	return
	// }

	// fmt.Printf("%+v\n", destConn)

	// httpMsg := readFromConnection(tlsConn)
	// b := httpMsg.RawMessage
	// read := httpMsg.RawMessageLen
	// // httpMsg = parseRequestMessage(b)
	// parseRequestMessage(&httpMsg)
	// httpMsg.RawMessage = b
	// httpMsg.RawMessageLen = read

	// fmt.Printf("\n\nStartLine: %v %v %v\n", httpMsg.Method, httpMsg.Uri, httpMsg.Version)

	// // REAL WAY kind of
	// originTlsConn, originErr := tls.Dial("tcp", "emanor-oie.oktapreview.com:443", nil)
	// // originTlsConn, originErr := tls.Dial("tcp", "gw.oktamanor.net:443", nil)
	// if originErr != nil {
	// 	fmt.Printf("originErr: %+v\n", originErr)
	// }
	// originTlsConn.SetReadDeadline(time.Now().Add(time.Minute))
	// originTlsConn.Write(b[0:read])

	// httpMsg = readFromConnection(originTlsConn)
	// // b = httpMsg.RawMessage
	// // originRead := httpMsg.RawMessageLen
	// // httpMsg = parseResponseMessage(b)
	// // httpMsg.RawMessage = b
	// // httpMsg.RawMessageLen = originRead
	// parseResponseMessage(&httpMsg)

	// fmt.Printf("\n\nStatusLine: %v %v %v\n", httpMsg.Version, httpMsg.StatusCode, httpMsg.ReasonPhrase)

	// // clientWritten, clientWriteErr := tlsConn.Write(b[0:originRead])
	// clientWritten, clientWriteErr := tlsConn.Write(httpMsg.RawMessage[0:httpMsg.RawMessageLen])
	// fmt.Printf("clientWritten: %v, clientWriteErr: %v\n", clientWritten, clientWriteErr)

	// // check for last chunk
	// originRead, originReadErr := originTlsConn.Read(b)
	// fmt.Printf("\nCHK LAST CHUNKoriginRead: %v, originReadErr: %v\n", originRead, originReadErr)
	// fmt.Printf("%+v\n", string(b[0:originRead]))

	// // clientWritten, clientWriteErr = tlsConn.Write([]byte("0\r\n\r\n"))
	// clientWritten, clientWriteErr = tlsConn.Write(b[0:originRead])
	// fmt.Printf("clientWritten END: %v, clientWriteErr END: %v\n", clientWritten, clientWriteErr)

	// for {

	// 	httpMsg := readFromConnection(tlsConn)
	// 	// b := httpMsg.RawMessage
	// 	// clientRead := httpMsg.RawMessageLen
	// 	// httpMsg = parseRequestMessage(b)
	// 	fmt.Printf("\n\nLENGTH 1: %v\n\n", httpMsg.RawMessageLen)
	// 	parseRequestMessage(&httpMsg)
	// 	fmt.Printf("\n\nLENGTH 2: %v\n\n", httpMsg.RawMessageLen)
	// 	// httpMsg.RawMessage = b
	// 	// httpMsg.RawMessageLen = clientRead

	// 	fmt.Printf("\n\nhttps:\n%+v\n", httpMsg)

	// 	// originWritten, originWriteError := originTlsConn.Write(b[0:clientRead])
	// 	originWritten, originWriteError := originTlsConn.Write(httpMsg.RawMessage[0:httpMsg.RawMessageLen])
	// 	fmt.Printf("originWritten: %v, originWriteError: %v\n", originWritten, originWriteError)
	// 	// fmt.Printf("%+v\n", string(b[0:originWritten]))
	// 	fmt.Printf("%+v\n", string(httpMsg.RawMessage[0:httpMsg.RawMessageLen]))
	// 	if originWriteError != nil && !strings.Contains(originWriteError.Error(), "remote error: tls: user canceledBAD") {
	// 		break
	// 	}

	// 	// var originRead int
	// 	// var originReadErr error
	// 	for i := 0; i < 4; i++ {

	// 		httpMsg = readFromConnection(originTlsConn)
	// 		// b = httpMsg.RawMessage
	// 		// originRead = httpMsg.RawMessageLen

	// 		// if hex.EncodeToString(b[0:originRead]) == "300d0a0d0a" {
	// 		if hex.EncodeToString(httpMsg.RawMessage[0:httpMsg.RawMessageLen]) == "300d0a0d0a" {
	// 			fmt.Printf("\n\nBreaking For 300d0a0d0a\n\n")
	// 			// tlsConn.Write(b[0:originRead])
	// 			tlsConn.Write(httpMsg.RawMessage[0:httpMsg.RawMessageLen])
	// 			break
	// 		}

	// 		// httpMsg = parseResponseMessage(b)
	// 		// httpMsg.RawMessage = b
	// 		// httpMsg.RawMessageLen = originRead
	// 		// // hexString := hex.EncodeToString(b[0:originRead])
	// 		parseResponseMessage(&httpMsg)

	// 		// clientWritten, clientWriteErr := tlsConn.Write(b[0:originRead])
	// 		clientWritten, clientWriteErr := tlsConn.Write(httpMsg.RawMessage[0:httpMsg.RawMessageLen])
	// 		if clientWriteErr != nil {
	// 			fmt.Printf("clientWritten LOOP: %v", clientWriteErr)
	// 			break
	// 		}
	// 		// clientWritten, clientWriteErr := tlsConn.Write(b)
	// 		fmt.Printf("clientWritten LOOP: %v, clientWriteErr: %v\n", clientWritten, clientWriteErr)
	// 		// fmt.Printf("Last bytes: -%v-,-%v-\n", int(b[originRead-2]), int(b[originRead-1]))

	// 		// if hexString == "300d0a0d0a" {
	// 		// 	break
	// 		// }

	// 		// httpMsg = parseResponseMessage(b[0:originRead])
	// 		fmt.Printf("\n\nStatusLine: %v %v %v\n", httpMsg.Version, httpMsg.StatusCode, httpMsg.ReasonPhrase)
	// 		// if originReadErr != nil && !strings.Contains(originReadErr.Error(), "remote error: tls: user canceledBAD") {
	// 		// 	break
	// 		// }

	// 	}
	// }

	////// REMOVE END
	// END REAL WAY
}

func processInspectedOrigin(clientConn /*, originConn*/ net.Conn, origin string) {
	// Connect to Origin
	var originRealx509 *x509.Certificate
	verifyPeerCertificate := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// for i, v := range verifiedChains {
		// 	fmt.Printf("i=%v\n", i)
		// 	for i2, v2 := range v {
		// 		fmt.Printf("  i2=%v\n", i2)
		// 		fmt.Printf("%+v\n", v2)
		// 	}
		// }
		// Not sure if the leaf cert will always be [0][0] -may need to revisit
		originRealx509 = verifiedChains[0][0]
		return nil
	}
	originTlsConfig := tls.Config{
		VerifyPeerCertificate: verifyPeerCertificate,
	}
	// originTlsConn, originErr := tls.Dial("tcp", "emanor-oie.oktapreview.com:443", nil)
	originTlsConn, originErr := tls.Dial("tcp", origin, &originTlsConfig)
	if originErr != nil {
		fmt.Printf("originErr: %+v\n", originErr)
	}
	defer originTlsConn.Close()
	originTlsConn.SetDeadline(time.Now().Add(time.Minute))

	// Handshake with Client
	rootCert, rootKey, rootErr := loadRootCert("/Users/erikmanor/SSL/origin/9.2024/rootCA.crt", "/Users/erikmanor/SSL/origin/9.2024/rootCA.key")
	if rootErr != nil {
		fmt.Printf("Error loadRootCert(): %+v\n", rootErr)
	}
	leafCert, _, leafKey, leafErr := generateLeafCertificate(rootCert, originRealx509, rootKey.(*rsa.PrivateKey))
	if leafErr != nil {
		fmt.Printf("Error generateLeafCertificate(): %+v\n", leafErr)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{leafCert.Raw},
		PrivateKey:  leafKey,
		Leaf:        leafCert,
	}
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MaxVersion:   tls.VersionTLS12,
	}

	tlsConn := tls.Server(clientConn, &tlsConfig)
	defer tlsConn.Close()
	tlsConn.SetDeadline(time.Now().Add(time.Minute))
	err := tlsConn.Handshake()
	if err != nil {
		fmt.Printf("Handshake Error: %+v\n", err)
		return
	}

	// Process Request
	for {
		// 1. Read Client
		// httpMsg := readFromConnection(tlsConn)
		httpMsg := readHttpMessage(tlsConn) // Testing
		if httpMsg.Error != nil {
			if httpMsg.Error.Error() == "EOF" {
				fmt.Printf("Closing client Connection\n")
				break
			}
			fmt.Printf("processInspectedOrigin client read error: %+v\n", httpMsg.Error)
			break
		}
		// parseRequestMessage(&httpMsg)
		fmt.Printf("\n\nStartLine: %v %v %v\n", httpMsg.Method, httpMsg.Uri, httpMsg.Version)

		//
		// 2. Write Origin
		originWritten, originWrittenErr := originTlsConn.Write(httpMsg.RawMessage[0:httpMsg.RawMessageLen])
		if originWrittenErr != nil || originWritten != httpMsg.RawMessageLen {
			fmt.Printf("originTlsConn.Write Error: %v, written: %v:%v\n", originWrittenErr, originWritten, httpMsg.RawMessageLen)
		}
		fmt.Printf("clientWritten: %v, clientWriteErr: %v\n", originWritten, originWrittenErr)
		// 1.5 / 2.5 if chunked continue to read/write
		if httpMsg.ContentType == CHUNKED {
			// TODO
			chunkErr := keepChunking(tlsConn, originTlsConn)
			if chunkErr != nil {
				break
			}
		}

		//
		// 3. Read Origin
		// httpMsg = readFromConnection(originTlsConn)
		// parseResponseMessage(&httpMsg)
		httpMsg = readHttpMessage(originTlsConn) // Testing
		fmt.Printf("\n\nStatusLine 3.0: %v %v %v\n", httpMsg.Version, httpMsg.StatusCode, httpMsg.ReasonPhrase)
		// fmt.Printf("httpMsg.RawMessage[0:100]: %v\n", string(httpMsg.RawMessage[0:100]))
		//
		// 4. Write Client
		clientWritten, clientWriteErr := tlsConn.Write(httpMsg.RawMessage[0:httpMsg.RawMessageLen])
		if clientWriteErr != nil {
			fmt.Printf("clientWritten Error: %v", clientWriteErr)
			//break
		}
		// clientWritten, clientWriteErr := tlsConn.Write(b)
		fmt.Printf("clientWritten: %v, clientWriteErr: %v\n", clientWritten, clientWriteErr)
		// 3.5 / 4.5 if chunked continue to read/write
		if httpMsg.ContentType == CHUNKED {
			// TODO CORRECTLY - see mileage from this
			chunkErr := keepChunking(originTlsConn, tlsConn)
			if chunkErr != nil {
				break
			}
			// for {
			// 	httpMsg = readFromConnection(originTlsConn)
			// 	processNextChunk(&httpMsg)
			// 	if httpMsg.LastChunk {
			// 		clientWritten, clientWriteErr = tlsConn.Write([]byte{ZERO, CR, LF, CR, LF})
			// 		if clientWriteErr != nil {
			// 			fmt.Printf("clientWritten Last Chunk Error: %v", clientWriteErr)
			// 			//break
			// 		}
			// 		fmt.Printf("clientWritten Last Chunk: %v, clientWriteErr: %v\n", clientWritten, clientWriteErr)
			// 		break
			// 	}

			// 	clientWritten, clientWriteErr = tlsConn.Write(httpMsg.RawMessage[0:httpMsg.ContentEnd])
			// 	if clientWriteErr != nil {
			// 		fmt.Printf("client Chunk Written Error: %v", clientWriteErr)
			// 		//break
			// 	}
			// 	fmt.Printf("client Chunk Written: %v, clientWriteErr: %v\n", clientWritten, clientWriteErr)
			// }
		}
	}
}

type contentType int

const (
	NONE contentType = iota
	LENGTH
	CHUNKED
)

const (
	LF    byte = 10 // 0x0A
	CR    byte = 13 // 0x0D
	SP    byte = 32 // 0x20
	HTAB  byte = 9  // 0x09
	VT    byte = 11 // 0x0B
	FF    byte = 12 // 0x0C
	COLON byte = 58 // 0x3A

	ZERO    byte = 0x30
	NINE    byte = 0x39
	UPPER_A byte = 0x41
	UPPER_F byte = 0x46
	LOWER_A byte = 0x61
	LOWER_F byte = 0x66

	BUFFER_INC int = 16384 // 16k
)

func test() {
	b := []byte("\r\n\r\n")
	fmt.Printf("== \\r = %v\n", b[0] == CR)
	fmt.Printf("== \\n = %v\n", b[1] == CR)
	fmt.Printf("== \\r = %v\n", b[0] == LF)
	fmt.Printf("== \\n = %v\n", b[1] == LF)
	// CRLF
}

type httpMessage struct {
	// req / stat line
	Method,
	Uri,
	Version,
	StatusCode,
	ReasonPhrase string

	Headers map[string]string

	ContentType contentType
	ContentStart,
	ContentEnd,
	HeaderEnd int

	RawMessage    []byte
	RawMessageLen int

	LastChunk bool

	Error error
}

// func continueReadFromConnection(tlsConn *tls.Conn, httpMsg *httpMessage) {
// 	//con
// }

func readHttpMessage(tlsConn *tls.Conn) httpMessage {
	// Max tcp packet size is 65k, typical network equipment restrict MTU to 1500 bytes
	// use 2048, if greater copy to bytebuffer as needed
	b := make([]byte, BUFFER_INC)
	buffer := bytes.Buffer{}
	httpMsg := httpMessage{}
	headersEnd := -1
	read := 0

	for headersEnd == -1 {
		// until all headers read
		r, readErr := tlsConn.Read(b)
		buffer.Write(b[0:r])
		fmt.Printf("readHttpHeaders: %v, ReadErr: %v\n", r, readErr)
		// fmt.Printf("%+v\n", string(b))
		if readErr != nil {
			httpMsg.Error = readErr
			return httpMsg
		}
		headersEnd = bytes.Index(b[0:r], []byte{CR, LF, CR, LF})
		if headersEnd != -1 {
			headersEnd += read + 4 // +4 headersEnd should point to first byte after double CRLF
		}
		read += r

	}

	// Parse Headers
	httpMsg.Headers = map[string]string{}
	b = buffer.Bytes()
	// index := 0
	index := processStartLine(b[0:headersEnd], &httpMsg)
	if httpMsg.Error != nil {
		log.Fatalf("readRequestStartLine: %v, index: %v\n\n", httpMsg.Error, index)
		return httpMsg
	}

	// Headers
	index += parseHeaders(b[index:headersEnd], &httpMsg)
	if httpMsg.Error != nil {
		log.Fatalf("parseHeaders: %v, index: %v\n\n", httpMsg.Error, index)
		return httpMsg
	}
	fmt.Println(index)

	// Body
	// verify b[index] doesn't need another read
	if httpMsg.ContentType == CHUNKED {
		chunkSize := getHexDigit(b[index:])
		if chunkSize == -1 {
			log.Fatal("Need to do another read to get chunk size")
			// handle error
		}
		bodyStart, err := readNextLine(b[index:])
		if err != nil {
			//handle error
		}
		bodyStart++
		httpMsg.ContentStart = index + bodyStart
		httpMsg.ContentEnd = httpMsg.ContentStart + chunkSize

		// fmt.Printf("\n\n--%+v--\n\n\n", string(b[httpMsg.ContentStart:httpMsg.ContentEnd]))
	} else if httpMsg.ContentType == LENGTH {
		// bodyStart, err := readNextLine(msg[index:])
		// if err != nil {
		// 	//handle error
		// }
		// bodyStart++
		httpMsg.ContentStart = index
		httpMsg.ContentEnd = httpMsg.ContentStart + httpMsg.ContentEnd
		// fmt.Printf("\n\n--%+v--\n\n\n", string(b[httpMsg.ContentStart:httpMsg.ContentEnd]))
	}

	// need more reads?
	fmt.Printf("ContentEnd: %v, Read: %v\n", httpMsg.ContentEnd, read)
	if httpMsg.ContentType != NONE && httpMsg.ContentEnd > read {
		b := make([]byte, BUFFER_INC)
		bytesNeeded := httpMsg.ContentEnd - read
		for bytesNeeded > 0 {
			r, readErr := tlsConn.Read(b)
			if readErr != nil {
				httpMsg.Error = readErr
				return httpMsg
			}
			buffer.Write(b[0:r])
			// fmt.Printf("Extra readHttpHeaders: %v, ReadErr: %v\n", r, readErr)
			bytesNeeded -= r
		}
	}

	httpMsg.RawMessage = buffer.Bytes()
	httpMsg.RawMessageLen = len(httpMsg.RawMessage)

	// fmt.Printf("\n\n--%+v--\n\n\n", string(httpMsg.RawMessage[httpMsg.ContentStart:httpMsg.ContentEnd]))
	return httpMsg
}

func readFromConnection(tlsConn *tls.Conn) httpMessage {
	// Max tcp packet size is 65k, typical network equipment restrict MTU to 1500 bytes
	// use 2048, if greater copy to bytebuffer as needed
	b := make([]byte, BUFFER_INC)
	httpMsg := httpMessage{}

	read, readErr := tlsConn.Read(b)
	// fmt.Printf("Read: %v, ReadErr: %v\n", read, readErr)
	// fmt.Printf("%+v\n", string(b))
	if readErr != nil {
		httpMsg.Error = readErr
		return httpMsg
	}

	if read >= len(b) {
		buffer := bytes.Buffer{}
		buffer.Write(b)
		for {
			innerRead, readErr := tlsConn.Read(b)
			fmt.Printf("Read Extra: %v, ReadErr: %v\n", innerRead, readErr)
			// fmt.Printf("%+v\n", string(b))
			if readErr != nil {
				httpMsg.Error = readErr
				return httpMsg
			}
			buffer.Write(b[0:innerRead])
			read += innerRead
			if innerRead < BUFFER_INC {
				//b = buffer.Bytes()
				break
			}
		}
		fmt.Printf("\nFinal []byte size: %v\n", len(b))
		b = buffer.Bytes()
	}
	httpMsg.RawMessage = b
	httpMsg.RawMessageLen = read

	return httpMsg
}

// func parseRequestMessage(httpMsg *httpMessage) {
// 	// func parseRequestMessage(msg []byte) httpMessage { //, msgL int) httpMessage {
// 	// Start Line
// 	// httpMsg := httpMessage{}
// 	msg := httpMsg.RawMessage
// 	httpMsg.Headers = map[string]string{}
// 	index := 0
// 	if msg[1] == LF {
// 		if msg[0] == CR {
// 			index = 2
// 		} else {
// 			httpMsg.Error = fmt.Errorf("invalid start line, LF not followed by CR")
// 			return //httpMsg
// 		}
// 	}
// 	index = readRequestStartLine(msg, index, httpMsg)
// 	if httpMsg.Error != nil {
// 		log.Fatalf("readRequestStartLine: %v, index: %v\n\n", httpMsg.Error, index)
// 		return //httpMsg
// 	}

// 	// Headers
// 	index += parseHeaders(msg[index:], httpMsg)
// 	if httpMsg.Error != nil {
// 		log.Fatalf("parseHeaders: %v, index: %v\n\n", httpMsg.Error, index)
// 		return //httpMsg
// 	}
// 	fmt.Println(index)

// 	// Body
// 	parseBody(msg, index, httpMsg)

// 	// fmt.Printf("\n\n%+v\n\n", httpMsg)

// 	//return httpMsg
// }

// // func parseResponseMessage(msg []byte) httpMessage {
// func parseResponseMessage(httpMsg *httpMessage) {
// 	// Status Line
// 	//httpMsg := httpMessage{}
// 	httpMsg.Headers = map[string]string{}
// 	msg := httpMsg.RawMessage
// 	index := 0
// 	if msg[1] == LF {
// 		if msg[0] == CR {
// 			index = 2
// 		} else {
// 			httpMsg.Error = fmt.Errorf("invalid status-line, LF not followed by CR")
// 			return //httpMsg
// 		}
// 	}
// 	index = processStartLine(msg, httpMsg)
// 	if httpMsg.Error != nil {
// 		log.Fatalf("readRequestStartLine: %v, index: %v\n\n", httpMsg.Error, index)
// 		return //httpMsg
// 	}

// 	// Headers
// 	index += parseHeaders(msg[index:], httpMsg)
// 	if httpMsg.Error != nil {
// 		log.Fatalf("parseHeaders: %v, index: %v\n\n", httpMsg.Error, index)
// 		return //httpMsg
// 	}
// 	fmt.Println(index)

// 	parseBody(msg, index, httpMsg)

// 	// fmt.Printf("\n\n%+v\n\n", httpMsg)
// 	// return httpMsg
// }

// func parseBody(msg []byte, index int, httpMsg *httpMessage) {
// 	if httpMsg.ContentType == CHUNKED {
// 		chunkSize := getHexDigit(msg[index:])
// 		if chunkSize == -1 {
// 			// handle error
// 		}
// 		bodyStart, err := readNextLine(msg[index:])
// 		if err != nil {
// 			//handle error
// 		}
// 		bodyStart++
// 		httpMsg.ContentStart = index + bodyStart
// 		httpMsg.ContentEnd = httpMsg.ContentStart + chunkSize
// 		fmt.Printf("\n\n--%+v--\n\n\n", string(msg[httpMsg.ContentStart:httpMsg.ContentEnd]))
// 	} else if httpMsg.ContentType == LENGTH {
// 		// bodyStart, err := readNextLine(msg[index:])
// 		// if err != nil {
// 		// 	//handle error
// 		// }
// 		// bodyStart++
// 		httpMsg.ContentStart = index
// 		httpMsg.ContentEnd = httpMsg.ContentStart + httpMsg.ContentEnd
// 		fmt.Printf("\n\n--%+v--\n\n\n", string(msg[httpMsg.ContentStart:httpMsg.ContentEnd]))
// 	}
// 	httpMsg.RawMessage = msg
// }

func keepChunking(readTlsConn, writeTlsConn *tls.Conn) error {
	// TODO CORRECTLY - see mileage from this
	for {
		httpMsg := readFromConnection(readTlsConn)
		processNextChunk(&httpMsg)
		if httpMsg.LastChunk {
			clientWritten, clientWriteErr := writeTlsConn.Write([]byte{ZERO, CR, LF, CR, LF})
			if clientWriteErr != nil {
				fmt.Printf("keepChunking.clientWritten Last Chunk Error: %v", clientWriteErr)
				return clientWriteErr
			}
			fmt.Printf("keepChunking.clientWritten Last Chunk: %v, clientWriteErr: %v\n", clientWritten, clientWriteErr)
			break
		}

		clientWritten, clientWriteErr := writeTlsConn.Write(httpMsg.RawMessage[0:httpMsg.ContentEnd])
		if clientWriteErr != nil {
			fmt.Printf("keepChunking client Chunk Written Error: %v", clientWriteErr)
			return clientWriteErr
		}
		fmt.Printf("keepChunking client Chunk Written: %v, clientWriteErr: %v\n", clientWritten, clientWriteErr)
	}
	return nil
}

func processNextChunk(httpMsg *httpMessage) {
	/*
				chunked-body   = *chunk
								last-chunk
								trailer-section
								CRLF

				chunk          = chunk-size [ chunk-ext ] CRLF
								chunk-data CRLF
				chunk-size     = 1*HEXDIG
				last-chunk     = 1*("0") [ chunk-ext ] CRLF

				chunk-data     = 1*OCTET ; a sequence of chunk-size octets

		    	chunk-ext      = *( BWS ";" BWS chunk-ext-name
		        	              [ BWS "=" BWS chunk-ext-val ] )

				chunk-ext-name = token
				chunk-ext-val  = token / quoted-string

				trailer-section   = *( field-line CRLF )
	*/
	if isLastChunk(httpMsg.RawMessage) {
		httpMsg.LastChunk = true
		return
	}

	chunkSize := getHexDigit(httpMsg.RawMessage[0:httpMsg.RawMessageLen])
	if chunkSize == -1 {
		// TODO handle error, most likely either
		// trailer-section which ignoring for now
		// or last chunk 2 x CRLF sent in 2 different writes
		fmt.Printf("processNextChunk: Unexpect chunk size, data: %+v\n", string(httpMsg.RawMessage[0:httpMsg.RawMessageLen]))
		return
	}
	bodyStart, err := readNextLine(httpMsg.RawMessage[0:httpMsg.RawMessageLen])
	if err != nil {
		//handle error
	}
	bodyStart++
	httpMsg.ContentStart = bodyStart
	httpMsg.ContentEnd = httpMsg.ContentStart + chunkSize + 2 // add CRLF with +2
	fmt.Printf("\n\n--%+v--\n\n\n", string(httpMsg.RawMessage[httpMsg.ContentStart:httpMsg.ContentEnd]))
}

func isLastChunk(b []byte) bool {
	// TODO - Really Should check for just ZERO, CR, LF by itself as well, server may send ending CR, LF
	//        sperate write
	if len(b) > 4 && b[0] == ZERO {
		if bytes.Equal(b[0:5], []byte{ZERO, CR, LF, CR, LF}) {
			return true
		}
		// ignore chunk-ext check for CR, LF, CR, LF
		if bytes.Contains(b, []byte{CR, LF, CR, LF}) {
			fmt.Printf("isLastChunk: Chunk Contains chunk-ext(?): %s\n", string(b))
			return true
		}
	}
	return false
}

// func readRequestStartLine(msg []byte, index int, httpMsg *httpMessage) int {
// 	newIndex := bytes.IndexByte(msg[index:], LF)
// 	if msg[newIndex-1] != CR {
// 		httpMsg.Error = fmt.Errorf("invalid header, LF not followed by CR")
// 		return -1
// 	}

// 	// Using strict SP https://httpwg.org/specs/rfc9112.html#request.line
// 	parts := bytes.Split(msg[index:newIndex], []byte{SP})
// 	if len(parts) != 3 {
// 		httpMsg.Error = fmt.Errorf("invalid start line, %s", string(msg[index:newIndex]))
// 		return -1
// 	}

// 	// only support specific methods
// 	method := string(parts[0])
// 	switch method {
// 	case "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS":
// 		httpMsg.Method = method
// 	default:
// 		httpMsg.Error = fmt.Errorf("invalide method: %s", method)
// 		return -1
// 	}

// 	// not checking target / version for now
// 	httpMsg.Uri = string(parts[1])
// 	httpMsg.Version = string(parts[2])

// 	return newIndex + 1
// }

func processStartLine(msg []byte, httpMsg *httpMessage) int {
	newIndex := bytes.IndexByte(msg, LF)
	if newIndex > 0 && msg[newIndex-1] != CR {
		httpMsg.Error = fmt.Errorf("invalid start-line, LF not followed by CR")
		return -1
	}

	// Using strict SP https://httpwg.org/specs/rfc9112.html#request.line
	// Using strict SP https://httpwg.org/specs/rfc9112.html#status.line
	parts := bytes.Split(msg[:newIndex], []byte{SP})
	if len(parts) < 3 {
		httpMsg.Error = fmt.Errorf("invalid start-line, %s", string(msg[:newIndex]))
		return -1
	}

	msgType := string(parts[0])
	if strings.Index(msgType, "HTTP/") == 0 {
		httpMsg.Version = msgType
		httpMsg.StatusCode = string(parts[1])
		httpMsg.ReasonPhrase = string(parts[2])
	} else if msgType == "GET" || msgType == "POST" || msgType == "PUT" || msgType == "OPTIONS" || msgType == "HEAD" || msgType == "DELETE" {
		httpMsg.Method = msgType
		httpMsg.Uri = string(parts[1])
		httpMsg.Version = string(parts[2])
	} else {
		httpMsg.Error = fmt.Errorf("invalide method: %s", msgType)
		return -1
	}

	return newIndex + 1
}

func parseHeaders(msg []byte, httpMsg *httpMessage) int {
	fmt.Printf("\n\n~%v~\n\n", string(msg))
	curIndex := 0
	for {
		newIndex, err := readNextLine(msg[curIndex:])
		if err != nil {
			httpMsg.Error = err
			return -1
		}
		newIndex += curIndex
		// fmt.Printf("curIndex=%v ,newIndex=%v, isNewLine(msg[curIndex], msg[newIndex])=%v\n", curIndex, newIndex, isNewLine(msg[curIndex], msg[newIndex]))
		if isNewLine(msg[curIndex], msg[newIndex]) {
			break
		}
		colon := bytes.IndexByte(msg[curIndex:newIndex], COLON)
		if colon == -1 {
			httpMsg.Error = fmt.Errorf("invalid header, no colon: %s", string(msg[curIndex:newIndex]))
			return -1
		}
		colon += curIndex
		/*
		 * MIGHT CHANGE SO httpMessage keeps everything as []byte instead of string
		 */
		key := string(msg[curIndex:colon])
		valStart := colon + 1
		valEnd := newIndex - 2
		if isOWS(msg[valStart]) {
			valStart++
		}
		if isOWS(msg[valEnd]) {
			valEnd--
		}
		// TODO - check for bare CR
		val := string(msg[valStart : valEnd+1])
		// fmt.Printf("-%s-%s-\n", key, val)
		// TODO Headers should be [][] to handle multiple set-cookie in response
		httpMsg.Headers[key] = val

		if strings.ToLower(key) == "content-length" {
			httpMsg.ContentEnd, _ = strconv.Atoi(val)
			httpMsg.ContentType = LENGTH
		} else if strings.ToLower(key) == "transfer-encoding" {
			httpMsg.ContentType = CHUNKED
		}

		curIndex = newIndex + 1
	}

	return curIndex + 2
}

func readNextLine(msg []byte) (int, error) {
	// field-line   = field-name ":" OWS field-value OWS
	if isNewLine(msg[0], msg[1]) {
		return 1, nil
	}
	if isOWS(msg[0]) {
		error := fmt.Errorf("invalid header, starts with whitespace")
		return -1, error
	}
	newIndex := bytes.IndexByte(msg, LF)
	if newIndex == -1 || newIndex == 0 || msg[newIndex-1] != CR {
		error := fmt.Errorf("invalid header, LF not proceeded by CR")
		fmt.Printf("\n\nindex: %v, newIndex: %v\n", 0, newIndex)
		// fmt.Printf("%v\n\n", string(msg[0:newIndex]))
		return -1, error
	}

	return newIndex, nil
}

func getHexDigit(b []byte) int {
	for i := 0; i < len(b); i++ {
		if (b[i] >= ZERO && b[i] <= NINE) || (b[i] >= LOWER_A && b[i] <= LOWER_F) || (b[i] >= UPPER_A && b[i] <= UPPER_F) {
			continue
		}
		if i == 0 {
			return -1
		}
		hexVal, err := strconv.ParseInt(string(b[0:i]), 16, 64)
		if err != nil {
			return -1
		}
		return int(hexVal)
	}
	return -1
}

func isOWS(b byte) bool {
	// SP, HTAB, VT (%x0B), FF (%x0C), or bare CR
	if b == SP || b == HTAB || b == VT || b == FF || b == CR {
		return true
	}
	return false
}

func isNewLine(cr, lf byte) bool {
	if cr == CR && lf == LF {
		return true
	} else {
		return false
	}
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	_, err := io.Copy(destination, source)
	if err != nil {
		// fmt.Println(err)
	}
}

func main() {
	test()
	proxyHandler := ProxyHandler{}
	server := &http.Server{
		Addr:    ":8080",
		Handler: proxyHandler,
	}
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

// Function to load the root certificate and key
func loadRootCert(certPath, keyPath string) (*x509.Certificate, interface{}, error) {
	// Load root certificate
	certFile, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open root certificate: %w", err)
	}
	block, _ := pem.Decode(certFile)
	if block == nil || block.Type != "CERTIFICATE" {
		fmt.Printf("Error: pem.Decode(): block: %+v\n", block)
	}
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse root certificate: %w", err)
	}

	// Load root key
	keyFile, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open root key: %w", err)
	}
	block, _ = pem.Decode(keyFile)
	if block == nil || block.Type != "PRIVATE KEY" {
		fmt.Printf("Error: pem.Decode(): block: %+v\n", block)
	}
	// fmt.Printf("Bloick Type: %+v\n", block.Type)
	rootKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse root private key: %w", err)
	}

	return rootCert, rootKey, nil
}

// Generate a new leaf certificate signed by the root certificate
func generateLeafCertificate(rootCert, originRealCert *x509.Certificate, rootKey *rsa.PrivateKey) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	// Generate a new key pair for the leaf certificate
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate leaf key pair: %w", err)
	}

	fmt.Printf("originRealCert.SignatureAlgorithm: %v\n", originRealCert.SignatureAlgorithm)
	var leafCertBytes []byte

	// Create the leaf certificate by signing it with the root private key
	if originRealCert.SignatureAlgorithm != x509.SHA256WithRSA {
		// Create a new leaf certificate template
		leafTemplate := x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			//"ST=California, CN=*.oktapreview.com, O="Okta, Inc.", L=San Francisco, C=US"
			// Subject: pkix.Name{
			// 	Country:      []string{"US"},
			// 	Organization: []string{"Okta, Inc."},
			// 	Province:     []string{"California"},
			// 	Locality:     []string{"San Francisco"},
			// 	CommonName:   "*.oktapreview.com",
			// 	// CommonName: "gw.oktamanor.net",
			// },
			Subject: pkix.Name{
				Country:      originRealCert.Subject.Country,      // []string{"US"},
				Organization: originRealCert.Subject.Organization, //[]string{"Microsoft Corporation"},
				Province:     originRealCert.Subject.Province,     //[]string{"WA"},
				Locality:     originRealCert.Subject.Locality,     //[]string{"Seattle"},
				CommonName:   originRealCert.Subject.CommonName,   //"*.azurewebsites.net",
				// CommonName: "gw.oktamanor.net",
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(365 * 24 * time.Hour), // valid for 1 year
			KeyUsage:    originRealCert.KeyUsage,              // x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
			ExtKeyUsage: originRealCert.ExtKeyUsage,           // []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			DNSNames:    originRealCert.DNSNames,              // []string{"*.azurewebsites.net"},
			// DNSNames:              []string{"gw.oktamanor.net"},
			BasicConstraintsValid: true,
		}
		leafCertBytes, err = x509.CreateCertificate(rand.Reader, &leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	} else {
		leafCertBytes, err = x509.CreateCertificate(rand.Reader, originRealCert, rootCert, &leafKey.PublicKey, rootKey)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create leaf certificate: %w", err)
	}

	// pkcs12.
	// Parse the generated certificate
	leafCert, err := x509.ParseCertificate(leafCertBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	return leafCert, leafCertBytes, leafKey, nil
}
