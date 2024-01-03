package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type TLS struct {
	Country    []string
	Org        []string
	CommonName string
}

type Config struct {
	Remotehost     string   `json:"remotehost"`
	Localhost      string   `json:"localhost"`
	Localport      int      `json:"localport"`
	TLS            *TLS     `json:"TLS"`
	CACertFile     string   `json:"CACertFile"`
	CAKeyFile      string   `json:"CAKeyFile"`
	ClientCertFile string   `json:"ClientCertFile"` // client cert for mTLS
	ClientKeyFile  string   `json:"ClientKeyFile"`  // client priv key for mTLS
	ListenerMTLS   bool     `json:"ListenerMTLS"`   // use the ClientKeyFile to set mTLS on the listener
	RichRaw        bool     `json:"RichRaw"`
	IPS            []string // IPAddress for the child cert
	Names          []string // DNSNames for the child cert
	Raw            bool     `json:"Raw"`
	ToFile         string   `json:"ToFile"`
	Quiet          bool     `json:"Quiet"`
}

var config Config
var ids = 0
var sessionFile *os.File

func genCert() ([]byte, *rsa.PrivateKey) {
	s, _ := rand.Prime(rand.Reader, 128)
	ca := &x509.Certificate{
		SerialNumber: s,
		Subject: pkix.Name{
			Country:      config.TLS.Country,
			Organization: config.TLS.Org,
			CommonName:   config.TLS.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		fmt.Println("create ca failed", err)
	}
	return ca_b, priv
}

func genChildCert(cert tls.Certificate, ips, names []string) []byte {

	parent, err := x509.ParseCertificate(cert.Certificate[0])

	if err != nil {
		fmt.Println("create child cert failed")
		return nil
	}

	s, _ := rand.Prime(rand.Reader, 128)

	template := &x509.Certificate{
		SerialNumber:          s,
		Subject:               pkix.Name{Organization: []string{"Argo Incorporated"}},
		Issuer:                pkix.Name{Organization: []string{"Argo Incorporated"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if ips != nil {
		is := make([]net.IP, 0)
		for _, i := range ips {
			is = append(is, net.ParseIP(i))
		}
		template.IPAddresses = is
	}
	if names != nil {
		template.DNSNames = names
	}

	private := cert.PrivateKey.(*rsa.PrivateKey)

	certP, _ := x509.ParseCertificate(cert.Certificate[0])
	public := certP.PublicKey.(*rsa.PublicKey)

	cab, err := x509.CreateCertificate(rand.Reader, template, parent, public, private)
	if err != nil {
		fmt.Println("create ca failed", err)
		os.Exit(1)
	}

	fmt.Println("[*] Child Certificate files generated")
	return cab
}

func dumpData(r io.Reader, source string, id int) {

	if config.Raw && config.ToFile != "" {
		io.Copy(sessionFile, r)
	} else {

		var fw *bufio.Writer         // used to write to file
		var outDumper io.WriteCloser // used to write hex dump to file
		if config.ToFile != "" {
			fw = bufio.NewWriter(sessionFile)
			if !config.Raw {
				outDumper = hex.Dumper(fw)
				defer outDumper.Close()
			}
		}

		data := make([]byte, 512)
		for {
			n, err := r.Read(data)
			if n > 0 {
				// hex.Dump + screen output slows things down badly, up to a 5x slow-down
				// best to dump to file and view with tail -f
				// best yet is to only view the file after the transfer completes
				if !config.Raw {
					if config.ToFile != "" {
						fw.WriteString(fmt.Sprintf("From %s [%d]:\n", source, id))
						// doing this is using hex.Dumper(fw) is slightly faster than
						// using `fw.WriteString(hex.Dump(data[:n]))`
						// even though the code is debatable uglier
						if config.RichRaw { // don't hex dump, this is basically enriched raw
							fw.Write(data[:n])
						} else {
							outDumper.Write(data[:n])
						}
						fw.WriteByte('\n')
						fw.Flush()
					} else {
						fmt.Printf("From %s [%d]:\n", source, id)
						fmt.Println(hex.Dump(data[:n]))
					}
				}
			}
			if err != nil && err != io.EOF {
				fmt.Printf("unable to read data %v", err)
				break
			}
			if n == 0 {
				break
			}
		}
	}

}

func handleServerMessage(connR, connL net.Conn, id int, closer *sync.Once) {
	// see comments in handleConnection
	// this is the same, just inverse, reads from server, writes to client
	closeFunc := func() {
		fmt.Println("[*] Connections closed.")
		_ = connL.Close()
		_ = connR.Close()
	}

	r, w := io.Pipe()
	tee := io.MultiWriter(connL, w)
	go dumpData(r, "SERVER", id)
	_, e := io.Copy(tee, connR)

	if e != nil && e != io.EOF {
		// check if error is about the closed connection
		// this is expected in most cases, so don't make a noise about it
		netOpError, ok := e.(*net.OpError)
		if ok && netOpError.Err.Error() != "use of closed network connection" {
			fmt.Printf("bad io.Copy [handleServerMessage]: %v", e)
		}
	}

	// ensure connections are closed. With the sync, this will either happen here
	// or in the handleConnection function
	closer.Do(closeFunc)
}

func handleConnection(connL net.Conn, isTLS bool) {
	var err error
	var connR net.Conn
	var closer sync.Once

	// make sure connections get closed
	closeFunc := func() {
		fmt.Println("[*] Connections closed")
		_ = connL.Close()
		_ = connR.Close()
	}

	if isTLS {
		conf := tls.Config{InsecureSkipVerify: true}

		if config.ClientKeyFile != "" { //use mtls
			cert, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
			if err != nil {
				fmt.Printf("couldn't load cert, %v", err)
				return
			}
			conf.Certificates = []tls.Certificate{cert}
		}

		connR, err = tls.Dial("tcp", config.Remotehost, &conf)
	} else {
		connR, err = net.Dial("tcp", config.Remotehost)
	}

	if err != nil {
		fmt.Printf("[x] Couldn't connect: %v", err)
		return
	}

	fmt.Printf("[*][%d] Connected to server: %s\n", ids, connR.RemoteAddr())

	// setup handler to read from server and print to screen
	go handleServerMessage(connR, connL, ids, &closer)

	// setup a pipe that will allow writing to the output (stdout) writer, without
	// consuming the data
	r, w := io.Pipe()

	// create a MultiWriter which allows writing to multiple writers at once.
	// this means each read from the client, will result in a write to both the server writer and the pipe writer,
	// which then gets sent to the "dumpData" reader, which will output it to the screen
	// directly pass connR (server) into the multiwriter. There is no need to allocate a new io.Writer(connR)
	tee := io.MultiWriter(connR, w)

	// background the dumping of data to screen
	go dumpData(r, "CLIENT", ids)
	ids++

	// consume all data and forward between connections in memory
	// directly pass connL (client) into the io.Copy as the reader. There is no need to create a new io.Reader(connL)
	_, e := io.Copy(tee, connL)
	if e != nil && e != io.EOF {
		fmt.Printf("bad io.Copy [handleConnection]: %v", e)
	}

	// ensure connections are closed. With the sync, this will either happen here
	// or in the handleServerMessage function
	closer.Do(closeFunc)

}

func startListener(isTLS bool) {

	conn, err := net.Listen("tcp", fmt.Sprint(config.Localhost, ":", config.Localport))
	if err != nil {
		panic("failed to start listener: " + err.Error())
	}

	if isTLS {
		var cert tls.Certificate
		if config.CACertFile != "" {
			cert, _ = tls.LoadX509KeyPair(config.CACertFile, config.CAKeyFile)
		} else {
			fmt.Println("[*] Generating cert")
			cab, priv := genCert()
			cert = tls.Certificate{
				Certificate: [][]byte{cab},
				PrivateKey:  priv,
			}
		}

		if config.IPS != nil || config.Names != nil {
			newCert := genChildCert(cert, config.IPS, config.Names)
			cert.Certificate = [][]byte{newCert}
		}

		// we don't have to set mTLS on the listener, it will simply accept connection with or
		// without the client supplying a cert. The mTLS part happens with the connection to the
		// upstream host
		conf := tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		// optional to add mTLS on the listener side
		if config.ListenerMTLS && config.ClientKeyFile != "" {
			caCert, err := os.ReadFile(config.ClientKeyFile)
			if err != nil {
				panic("failed to start listener: " + err.Error())
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			conf.ClientCAs = caCertPool
			conf.ClientAuth = tls.RequireAndVerifyClientCert
		}

		conf.Rand = rand.Reader
		// wrap conn into a TLS listener
		conn = tls.NewListener(conn, &conf)
	}

	fmt.Println("[*] Listening...")
	defer conn.Close()

	for {
		cl, err := conn.Accept()
		if err != nil {
			fmt.Printf("server: accept: %v", err)
			break
		}
		fmt.Printf("[*] Accepted from: %s\n", cl.RemoteAddr())
		go handleConnection(cl, isTLS)
	}
}

func setConfig(configFile string, localPort int, localHost, remoteHost string, caCertFile, caKeyFile string, clientCertFile, clientKeyFile, outFile string) {
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			fmt.Println("[-] Not a valid config file: ", err)
			os.Exit(1)
		}
		err = json.Unmarshal(data, &config)
		if err != nil {
			fmt.Println("[-] Not a valid config file: ", err)
			os.Exit(1)
		}
	} else {
		config = Config{TLS: &TLS{}}
	}

	if caCertFile != "" {
		config.CACertFile = caCertFile
		config.CAKeyFile = caKeyFile
	}

	if clientCertFile != "" {
		config.ClientCertFile = clientCertFile
		config.ClientKeyFile = clientKeyFile
	}

	if localPort != 0 {
		config.Localport = localPort
	}
	if localHost != "" {
		config.Localhost = localHost
	}
	if remoteHost != "" {
		config.Remotehost = remoteHost
	}

	if outFile != "" {
		config.ToFile = outFile
	}
}

func main() {
	localPort := flag.Int("p", 0, "Local Port to listen on")
	localHost := flag.String("l", "", "Local address to listen on")
	remoteHostPtr := flag.String("r", "", "Remote Server address host:port")
	configPtr := flag.String("c", "", "Use a config file (set TLS ect) - Commandline params overwrite config file")
	tlsPtr := flag.Bool("s", false, "Create a TLS Proxy")
	listenerMTLSPtr := flag.Bool("lmtls", false, "Enable mTLS on the listener. Requires clientKey")
	caCertFilePtr := flag.String("cert", "", "Use a specific ca cert file")
	caKeyFilePtr := flag.String("key", "", "Use a specific ca key file (must be set if --cert is set")
	clientCertPtr := flag.String("clientCert", "", "A public client cert to use for mTLS")
	clientKeyPtr := flag.String("clientKey", "", "A public client key to use for mTLS")
	quietPtr := flag.Bool("q", false, "Hide app messages and just show the data stream")
	rawPtr := flag.Bool("raw", false, "Don't use hex.dump to pretty format output")
	richRawPtr := flag.Bool("richraw", false, "Slightly enrich the raw output, don't use hex.dump to pretty format output")
	outFilePtr := flag.String("o", "", "Write output to file")

	flag.Parse()

	if *caCertFilePtr != "" && *caKeyFilePtr == "" {
		fmt.Println("[x] -key is required when -cert is set")
		os.Exit(1)
	}

	if *clientCertPtr != "" && *clientKeyPtr == "" {
		fmt.Println("[x] -clientKey is required when -clientCert is set")
		os.Exit(1)
	}

	setConfig(*configPtr, *localPort, *localHost, *remoteHostPtr, *caCertFilePtr, *caKeyFilePtr, *clientCertPtr, *clientKeyPtr, *outFilePtr)

	config.ListenerMTLS = *listenerMTLSPtr
	if config.ListenerMTLS {
		fmt.Println("[-] ClientCertFile must be set when using listener mTLS")
		os.Exit(1)
	}
	config.Quiet = *quietPtr
	config.Raw = *rawPtr
	config.RichRaw = *richRawPtr

	if config.Raw && config.RichRaw {
		fmt.Println("[-] Conflicting configuration, -raw and -richraw can't be used together.")
		os.Exit(1)
	}

	if config.Raw && config.ToFile == "" {
		fmt.Println("[-] Raw mode specified but no output file supplied. There won't be any output!")
	}

	if config.ToFile != "" {
		var e error
		sessionFile, e = os.Create(config.ToFile)
		if e != nil {
			fmt.Println("[x] Couldn't open file for writing")
			os.Exit(1)
		}
		defer sessionFile.Close()
	}

	if config.Remotehost == "" {
		fmt.Println("[x] Remote host required")
		flag.PrintDefaults()
		os.Exit(1)
	}

	startListener(*tlsPtr)
}
