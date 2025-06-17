package main

import (
	"bytes"
	"compress/gzip"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"

	"net"
	"net/http"
)

// TODO - when reading chunks server might send a single chunk that spans multiple socket reads ???
type ProxyHandler struct {
	Port             string
	InspectedOrigins map[string]string
}

func (p ProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// fmt.Printf("%+v\n\n", req)
	if req.Method == http.MethodConnect {
		p.handleConnect(w, req)
		return
	}
	p.handleRequest(w, req)
}

func (p ProxyHandler) handleRequest(_ http.ResponseWriter, req *http.Request) {
	//proxy.ServeHTTP(w, req)
	log.Printf("\n\nShould never get here (?): %+v\n\n", req)
}

func (p ProxyHandler) handleConnect(w http.ResponseWriter, req *http.Request) {
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

	// if req.URL.Host != "emanor-oie.oktapreview.com:443" {
	if _, ok := p.InspectedOrigins[req.URL.Host]; !ok {
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

	fmt.Printf("req.URL.Host: %v\n\n", req.URL.Host)
	go processInspectedOrigin(clientConn, req.URL.Host)
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
		//
		// Read from Client
		//
		httpMsg := httpMessage{SrcConn: tlsConn, DstConn: originTlsConn}
		readRequest(&httpMsg)
		if httpMsg.Error != nil {
			if httpMsg.Error.Error() == "EOF" {
				log.Println("client readRequest EOF..")
				break
			} else {
				log.Fatal(httpMsg.Error)
			}
		}

		fmt.Printf("\n\nStatusLine 1.0: %v %v %v\n", httpMsg.Version, httpMsg.StatusCode, httpMsg.ReasonPhrase)
		printHttpMessage(&httpMsg)

		//
		// Write to Origin
		//
		writeRequest(&httpMsg)
		if httpMsg.Error != nil {
			log.Fatalf("origin writeRequest error, %s\n", httpMsg.Error.Error())
		}

		//
		// Read from Origin
		//
		httpMsg = httpMessage{SrcConn: originTlsConn, DstConn: tlsConn}
		readRequest(&httpMsg) // REALLY Testing
		if httpMsg.Error != nil {
			if httpMsg.Error.Error() == "EOF" {
				log.Println("origin readRequest EOF..")
				break
			} else {
				log.Fatal(httpMsg.Error)
			}
		}

		fmt.Printf("\n\nStatusLine 3.0: %v %v %v\n", httpMsg.Version, httpMsg.StatusCode, httpMsg.ReasonPhrase)
		printHttpMessage(&httpMsg)

		//
		// Write from Client
		//
		writeRequest(&httpMsg)
		if httpMsg.Error != nil {
			log.Fatalf("client writeRequest error, %s\n", httpMsg.Error.Error())
		}

	}
}

func printHttpMessage(httpMsg *httpMessage) {
	var body string
	// fmt.Printf("\n\nhttpMsg.ContentEncoding = %s\n\n", httpMsg.ContentEncoding)

	if httpMsg.ContentEncoding == "gzip" {
		reader := bytes.NewReader(httpMsg.BodyBytesBuffer.Bytes())
		compressionReader, err := gzip.NewReader(reader)
		if err != nil {
			fmt.Printf("Error Getting gzip Reader: %s\n", err)
		}
		bytesBody, _ := io.ReadAll(compressionReader)
		body = string(bytesBody)
	} else {
		body = httpMsg.BodyBytesBuffer.String()
	}
	fmt.Printf("~~~~\n%s\n\n%s\n~~~~", httpMsg.HeadersBytesBuffer.String(), body) //httpMsg.BodyBytesBuffer.String())
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

	BUFFER_INC int = 116384 // 16k
)

// 0x42 = CR or COLON or LF
// 0x01 = hex
// 0x02 = space (SP / HTAB)

var PARSE_FLAGS []byte = []byte{
	//0 - F
	0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0x42, 0, 0, 0x42, 0, 0, // 15 (0F)
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, // 31 (1F)
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 47 (2F)
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0x42, 0, 0, 0, 0, 0, // 63 (3F)
	0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 79 (4F)
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 95 (5F)
	0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 111 (6F)
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 127 (7F)

	// 128-255
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

type processingStage int

const (
	START_LINE processingStage = iota
	HEADERS
	CHUNKED_DATA
	CHUNKED_DATA_END
	CONTENT_DATA
	CHUNK_SIZE
	SINGLE_CRLF
	FINAL_CHUNK
	DONE
)

type processingState struct {
	// still processing
	Processing bool
	// what is being looked for
	FindToken byte
	// last byte
	LastToken byte
	// current token
	Buffer bytes.Buffer
	// bytes to process
	SrcBytes []byte
	// SrcBytes Read
	// SrcBytesRead int
	// require another socket read
	NeedSrcBytes bool
	// bits needed
	NeededSrcBytes int
	// // part of http message being processed
	// Stage processingStage
	ProcessingHeaderKey,
	ProcessingHeaderVal bool
}

type httpMessage struct {
	// req / stat line
	Method,
	Uri,
	Version,
	StatusCode,
	ReasonPhrase string

	Method2,
	Uri2,
	Version2,
	StatusCode2,
	ReasonPhrase2,
	StartStatusLine []byte

	Headers map[string]string

	ContentType contentType
	ContentStart,
	ContentEnd,
	HeaderEnd,
	ContentLength,
	ChunkSize int

	ContentEncoding string

	RawMessage      []byte
	RawMessageLen   int
	RawBytesBuffer, // remove later?
	StartLine,
	HeadersBytesBuffer,
	BodyBytesBuffer,
	ChunkSizeBytesBuffer bytes.Buffer

	LastChunk,
	IsChunkPart bool

	ProcessingState processingState
	// part of http message being processed
	Stage processingStage

	SrcConn,
	DstConn *tls.Conn

	Error error
}

func writeRequest(httpMsg *httpMessage) {
	// fmt.Printf("\n\n\n\n Message:\n\n")

	httpMsg.DstConn.Write(httpMsg.StartStatusLine)
	httpMsg.HeadersBytesBuffer.Write([]byte{CR, LF, CR, LF})
	httpMsg.DstConn.Write(httpMsg.HeadersBytesBuffer.Bytes())

	// fmt.Printf("%s", string(httpMsg.StartStatusLine))
	// fmt.Printf("%s", httpMsg.HeadersBytesBuffer.String())
	// fmt.Println(httpMsg.ContentType)

	if httpMsg.ContentType == CHUNKED {
		/*
		 * there is no real reason to chunk response since inspected messages need to be fully digested.
		 * maybe add gaurdrail for  messages > then some size to not run into memory issues if a giant file
		 * is inspected, etc. Not worry for now and sending as a single chunk.
		 * Technically could also just send as content-length instead, but what client to received same
		 * transfer encoding as origin sent.
		 */
		httpMsg.DstConn.Write([]byte(fmt.Sprintf("%x", httpMsg.BodyBytesBuffer.Len())))
		httpMsg.DstConn.Write([]byte{CR, LF})
		httpMsg.DstConn.Write(httpMsg.BodyBytesBuffer.Bytes())
		httpMsg.DstConn.Write([]byte{CR, LF})
		httpMsg.DstConn.Write([]byte{ZERO, CR, LF, CR, LF})
		// fmt.Printf("=-%s-=\n", httpMsg.BodyBytesBuffer.String())
	} else if httpMsg.ContentType == LENGTH {
		httpMsg.DstConn.Write(httpMsg.BodyBytesBuffer.Bytes())
		// fmt.Printf("=-%s-=\n", httpMsg.BodyBytesBuffer.String())
	}
}

func readMoreSrcBytes(httpMsg *httpMessage) {
	var srcBytes []byte
	var err error
	var read int
	if httpMsg.Stage == CHUNKED_DATA || httpMsg.Stage == CONTENT_DATA {
		srcBytes = make([]byte, httpMsg.ProcessingState.NeededSrcBytes)
		for i := 0; i < httpMsg.ProcessingState.NeededSrcBytes; {
			// fmt.Printf("\\nnreadMoreSrcBytes - NeededSrcBytes: %v\n", httpMsg.ProcessingState.NeededSrcBytes)
			j, err := httpMsg.SrcConn.Read(srcBytes[i:])
			// fmt.Printf("readMoreSrcBytes - j: %v, i: %v\n\n", j, j+i)
			i += j
			read = i
			if err != nil {
				break
			}
		}
	} else {
		srcBytes = make([]byte, BUFFER_INC)
		read, err = httpMsg.SrcConn.Read(srcBytes)
	}

	if err != nil {
		httpMsg.Error = err
	}
	httpMsg.ProcessingState.SrcBytes = srcBytes[0:read]
	// fmt.Print(string(httpMsg.ProcessingState.SrcBytes))
}

func readRequest(httpMsg *httpMessage) {
	httpMsg.Headers = map[string]string{}
	headerKey := bytes.Buffer{}
	headerVal := bytes.Buffer{}

	httpMsg.ProcessingState.Processing = true
	httpMsg.ContentType = NONE
	httpMsg.Stage = START_LINE

	readMoreSrcBytes(httpMsg)
	if httpMsg.Error != nil {
		return
	}

	for httpMsg.ProcessingState.Processing {

		for i, b := range httpMsg.ProcessingState.SrcBytes {
			// fmt.Printf("%v - string: %v - stage: %v - byte: %v\n", i, string(b), httpMsg.Stage, b)
			switch httpMsg.Stage {
			case START_LINE:
				// TODO - Inline like Headers, remove processStartLine2
				if b == CR {
					httpMsg.ProcessingState.FindToken = LF
				} else if b == LF {
					if httpMsg.ProcessingState.LastToken == CR {
						// done processing start/status line
						processStartLine2(httpMsg.ProcessingState.SrcBytes[0:i-1], httpMsg)
						if httpMsg.Error != nil {
							return
						}
						httpMsg.Stage = HEADERS
						// httpMsg.ProcessingState.FindToken = CR
						httpMsg.ProcessingState.ProcessingHeaderKey = true
						httpMsg.ProcessingState.FindToken = 0x42 //COLON
					} else {
						httpMsg.Error = fmt.Errorf("error: start-line LF not preceeded by CR")
						return
					}
				}
				// }

			case FINAL_CHUNK:
				// first CRLF should have been procrssed in CHUNK_SIZE, ignore chunk-ext and stop at next CRLF
				httpMsg.ProcessingState.Buffer.WriteByte(b)
				if bytes.Contains(httpMsg.ProcessingState.Buffer.Bytes(), []byte{CR, LF}) {
					httpMsg.Stage = DONE
					httpMsg.ProcessingState.Processing = false
				}

			case CHUNK_SIZE:
				if httpMsg.ProcessingState.FindToken == LF {
					chunkSize, err := strconv.ParseInt(httpMsg.ChunkSizeBytesBuffer.String(), 16, 64)
					if err != nil {
						httpMsg.Error = fmt.Errorf("error: getting chunk size for: %v, %v", httpMsg.ChunkSizeBytesBuffer.String(), err)
						return
					}
					httpMsg.ChunkSize = int(chunkSize)
					httpMsg.ProcessingState.NeededSrcBytes = int(chunkSize)
					if chunkSize == 0 {
						httpMsg.Stage = FINAL_CHUNK
						httpMsg.ProcessingState.Buffer = bytes.Buffer{}
					} else {
						httpMsg.Stage = CHUNKED_DATA
					}
					// fmt.Printf("-- ChunkAize: %v\n", chunkSize)
				} else if b == CR {
					httpMsg.ProcessingState.FindToken = LF
				} else {
					if PARSE_FLAGS[b] != httpMsg.ProcessingState.FindToken {
						// expected Hex
						httpMsg.Error = fmt.Errorf("error: expected hex digit reading chunk size, found: %v", string(b))
						return
					}
					httpMsg.ChunkSizeBytesBuffer.WriteByte(b)
				}

			case CHUNKED_DATA:
				httpMsg.BodyBytesBuffer.WriteByte(b)
				httpMsg.ProcessingState.NeededSrcBytes--
				if httpMsg.ProcessingState.NeededSrcBytes <= 0 {
					httpMsg.Stage = CHUNKED_DATA_END
				}

			case CHUNKED_DATA_END:
				// fmt.Printf("CHUHNK %v:%v\n", httpMsg.ProcessingState.LastToken, b)
				if b == LF {
					if httpMsg.ProcessingState.LastToken != CR {
						httpMsg.Error = fmt.Errorf("error: expected CRLF eng of chunk, found: %v%v", httpMsg.ProcessingState.LastToken, b)
						return
					}
					httpMsg.Stage = CHUNK_SIZE
					httpMsg.ChunkSizeBytesBuffer.Reset()
					httpMsg.ProcessingState.FindToken = 0x01
					// fmt.Printf("i=%v, srcBytes Size: %v\n", i, len(httpMsg.ProcessingState.SrcBytes))
				} else if b == CR {
					httpMsg.ProcessingState.FindToken = LF
				} else {
					httpMsg.Error = fmt.Errorf("error: expected CRLF, found: %v - %v", httpMsg.ProcessingState.LastToken, b)
					return
				}

			case CONTENT_DATA:
				httpMsg.BodyBytesBuffer.Write(httpMsg.ProcessingState.SrcBytes[i:])
				if httpMsg.BodyBytesBuffer.Len() < httpMsg.ContentLength {
					httpMsg.ProcessingState.NeededSrcBytes = httpMsg.ContentLength - httpMsg.BodyBytesBuffer.Len()
					readMoreSrcBytes(httpMsg)
					if httpMsg.Error != nil {
						return
					}
					httpMsg.BodyBytesBuffer.Write(httpMsg.ProcessingState.SrcBytes)
				}
				return

			case HEADERS:
				// looking for end of headers
				// if b == httpMsg.ProcessingState.FindToken {
				if PARSE_FLAGS[b] == httpMsg.ProcessingState.FindToken {
					if b == CR {
						httpMsg.ProcessingState.FindToken = 0x42 //LF
					} else if b == LF {
						if httpMsg.ProcessingState.LastToken == CR {
							// check if this is the second
							l := httpMsg.HeadersBytesBuffer.Len()
							if l > 2 {
								lastThree := httpMsg.HeadersBytesBuffer.Bytes()
								if bytes.Contains(lastThree[l-3:], []byte{CR, LF, CR}) {
									httpMsg.HeadersBytesBuffer.Truncate(l - 3)
									httpMsg.ProcessingState.ProcessingHeaderKey = false
									httpMsg.ProcessingState.ProcessingHeaderVal = false
									// fmt.Printf("ContentType: %v, ContentLength: %v\n", httpMsg.ContentType, httpMsg.ContentLength)
									if httpMsg.ContentType == CHUNKED {
										httpMsg.ProcessingState.FindToken = 0x01
										httpMsg.Stage = CHUNK_SIZE
										httpMsg.ProcessingState.NeedSrcBytes = true
										httpMsg.ChunkSizeBytesBuffer = bytes.Buffer{}
									} else if httpMsg.ContentType == LENGTH && httpMsg.ContentLength > 0 {
										httpMsg.Stage = CONTENT_DATA
										httpMsg.ProcessingState.NeededSrcBytes = httpMsg.ContentLength
										httpMsg.ProcessingState.NeedSrcBytes = true
									} else {
										httpMsg.ProcessingState.Processing = false
										httpMsg.Stage = DONE
									}

									continue
								} else {
									// assume is not end of headers, just end of header
									// not white space checking (TODO)
									key := string(bytes.TrimSpace(headerKey.Bytes()))
									val := string(bytes.TrimSpace(headerVal.Bytes()))
									httpMsg.Headers[key] = val
									httpMsg.ProcessingState.ProcessingHeaderKey = true
									httpMsg.ProcessingState.ProcessingHeaderVal = false
									lowerKey := strings.ToLower(key)
									if lowerKey == "content-length" {
										httpMsg.ContentLength, _ = strconv.Atoi(val)
										httpMsg.ContentType = LENGTH
									} else if lowerKey == "transfer-encoding" {
										httpMsg.ContentType = CHUNKED
									} else if lowerKey == "content-encoding" {
										httpMsg.ContentEncoding = strings.ToLower(val)
									}
									headerKey.Reset()
									headerVal.Reset()
									httpMsg.ProcessingState.FindToken = 0x42 //COLON
									// fmt.Printf("@@-%s : %s-@@\n", key, val)
								}
							}
						} else {
							httpMsg.Error = fmt.Errorf("error: http header LF not preceeded by CR:\n%s\n", httpMsg.HeadersBytesBuffer.String())
							return
						}
					} else if b == COLON {
						httpMsg.ProcessingState.ProcessingHeaderKey = false
						httpMsg.ProcessingState.ProcessingHeaderVal = true
						httpMsg.ProcessingState.FindToken = 0x42 //CR
					}
				} else if httpMsg.ProcessingState.ProcessingHeaderKey {
					headerKey.WriteByte(b)
				} else if httpMsg.ProcessingState.ProcessingHeaderVal {
					headerVal.WriteByte(b)
				}
				httpMsg.HeadersBytesBuffer.WriteByte(b)

			case SINGLE_CRLF:

			case DONE:
				httpMsg.ProcessingState.Processing = false
				httpMsg.ProcessingState.NeedSrcBytes = false
				return
			}

			httpMsg.ProcessingState.LastToken = b
		}
		// fmt.Printf("\n\nONE\n\n")
		if httpMsg.ProcessingState.Processing { //&& httpMsg.ProcessingState.NeedSrcBytes {
			readMoreSrcBytes(httpMsg)
			// fmt.Printf("\n\nTWO\n\n")
			if httpMsg.Error != nil {
				return
			}
		}
	}
}

func processStartLine2(startLine []byte, httpMsg *httpMessage) {
	httpMsg.StartLine.Write(startLine)
	// Using strict SP https://httpwg.org/specs/rfc9112.html#request.line
	// Using strict SP https://httpwg.org/specs/rfc9112.html#status.line
	parts := bytes.Split(startLine, []byte{SP})
	if len(parts) < 3 {
		httpMsg.Error = fmt.Errorf("invalid start-line, %s", string(startLine))
		return
	}

	msgType := string(parts[0])
	if strings.Index(msgType, "HTTP/") == 0 {
		httpMsg.Version2 = parts[0]
		httpMsg.StatusCode2 = parts[1]
		httpMsg.ReasonPhrase2 = parts[2]
	} else if msgType == "GET" || msgType == "POST" || msgType == "PUT" || msgType == "OPTIONS" || msgType == "HEAD" || msgType == "DELETE" {
		httpMsg.Method2 = parts[0]
		httpMsg.Uri2 = parts[1]
		httpMsg.Version2 = parts[2]
	} else {
		httpMsg.Error = fmt.Errorf("invalide method: %s", msgType)
	}
	// httpMsg.StartLine.
	// parts = append(parts, []byte{CR, LF})
	httpMsg.StartStatusLine = bytes.Join(parts, []byte{SP})
	httpMsg.StartStatusLine = append(httpMsg.StartStatusLine, CR)
	httpMsg.StartStatusLine = append(httpMsg.StartStatusLine, LF)
}

func main() {

	// test()
	if len(os.Args) < 2 {
		log.Fatal("No port specified.")
	}
	proxyPort := fmt.Sprintf(":%s", os.Args[1])
	origins := map[string]string{}
	if len(os.Args) > 2 {
		for _, host := range os.Args[2:] {
			parts := strings.Split(host, ":")
			port := "443"
			if len(parts) > 1 {
				port = parts[1]
			}
			origins[fmt.Sprintf("%s:%s", parts[0], port)] = port
		}
	}

	proxyHandler := ProxyHandler{
		Port:             proxyPort,
		InspectedOrigins: origins,
	}
	server := &http.Server{
		Addr:    proxyPort,
		Handler: proxyHandler,
	}

	log.Printf("Starting simple-proxy, listening on %s\n", proxyPort)
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
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
