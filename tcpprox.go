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
	"io/ioutil"
	"log"
	"net"
	"os"
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
	IPS            []string // IPAddress for the child cert
	Names          []string // DNSNames for the child cert
}

var config Config
var ids = 0

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

	for {
		data := make([]byte, 1024)
		n, err := r.Read(data)
		if n > 0 {
			fmt.Printf("From %s [%d]:\n", source, id)
			fmt.Printf("%s\n", hex.Dump(data[:n]))
		}
		if err != nil {
			break
		}
	}

}

func handleServerMessage(connR, connC net.Conn, id int) {
	// see comments in handleConnection
	// this is the same, just inverse, reads from server, writes to client
	reader := bufio.NewReader(connR)
	writer := io.Writer(connC)

	r, w := io.Pipe()
	tee := io.TeeReader(reader, w)
	go dumpData(r, "SERVER", id)
	io.Copy(writer, tee)
}

func handleConnection(conn net.Conn, isTLS bool) {
	var err error
	var connR net.Conn

	if isTLS {
		conf := tls.Config{InsecureSkipVerify: true}

		if config.ClientKeyFile != "" { //use mtls
			cert, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
			if err != nil {
				log.Fatal(err)
			}
			conf.Certificates = []tls.Certificate{cert}
		}

		connR, err = tls.Dial("tcp", config.Remotehost, &conf)
	} else {
		connR, err = net.Dial("tcp", config.Remotehost)
	}

	if err != nil {
		log.Printf("[x] Couldn't connect: %s", err)
		return
	}

	fmt.Printf("[*][%d] Connected to server: %s\n", ids, connR.RemoteAddr())

	// setup handler to read from server and print to screen
	go handleServerMessage(connR, conn, ids)
	ids++

	// new reader to read from the client connection
	reader := io.Reader(conn)
	// new writer to write to the server connection
	writer := io.Writer(connR)

	// setup a pipe that will allow writing to the output (stdout) writer, without
	// consuming the data
	r, w := io.Pipe()

	// create a TeeReader which will write everything it reads to the supplied writer
	// this means each read from the client, will result in a write to the pipe,
	// which then gets sent to the "dumpData" reader, which will output it to the screen
	tee := io.TeeReader(reader, w)

	// background the dumping of data to screen
	go dumpData(r, "CLIENT", ids)

	// consume all data and forward between connections in memory
	io.Copy(writer, tee)

	connR.Close()
	conn.Close()
}

func startListener(isTLS bool) {

	var err error
	var conn net.Listener
	var cert tls.Certificate

	if isTLS {
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

		/* optional to add mTLS on the listener side
		if config.ClientKeyFile != "" {
			caCert, err := ioutil.ReadFile(config.ClientKeyFile)
			if err != nil {
				log.Fatal(err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			conf.ClientCAs = caCertPool
			conf.ClientAuth = tls.RequireAndVerifyClientCert
		} */

		conf.Rand = rand.Reader

		conn, err = tls.Listen("tcp", fmt.Sprint(config.Localhost, ":", config.Localport), &conf)

	} else {
		conn, err = net.Listen("tcp", fmt.Sprint(config.Localhost, ":", config.Localport))
	}

	if err != nil {
		panic("failed to connect: " + err.Error())
	}

	fmt.Println("[*] Listening...")

	for {
		cl, err := conn.Accept()
		if err != nil {
			fmt.Printf("server: accept: %s", err)
			break
		}
		fmt.Printf("[*] Accepted from: %s\n", cl.RemoteAddr())
		go handleConnection(cl, isTLS)
	}
	conn.Close()
}

func setConfig(configFile string, localPort int, localHost, remoteHost string, caCertFile, caKeyFile string, clientCertFile, clientKeyFile string) {
	if configFile != "" {
		data, err := ioutil.ReadFile(configFile)
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
}

func main() {
	localPort := flag.Int("p", 0, "Local Port to listen on")
	localHost := flag.String("l", "", "Local address to listen on")
	remoteHostPtr := flag.String("r", "", "Remote Server address host:port")
	configPtr := flag.String("c", "", "Use a config file (set TLS ect) - Commandline params overwrite config file")
	tlsPtr := flag.Bool("s", false, "Create a TLS Proxy")
	caCertFilePtr := flag.String("cert", "", "Use a specific ca cert file")
	caKeyFilePtr := flag.String("key", "", "Use a specific ca key file (must be set if --cert is set")
	clientCertPtr := flag.String("clientCert", "", "A public client cert to use for mTLS")
	clientKeyPtr := flag.String("clientKey", "", "A public client key to use for mTLS")

	flag.Parse()

	if *caCertFilePtr != "" && *caKeyFilePtr == "" {
		fmt.Println("[x] -key is required when -cert is set")
		os.Exit(1)
	}

	if *clientCertPtr != "" && *clientKeyPtr == "" {
		fmt.Println("[x] -clientKey is required when -clientCert is set")
		os.Exit(1)
	}

	setConfig(*configPtr, *localPort, *localHost, *remoteHostPtr, *caCertFilePtr, *caKeyFilePtr, *clientCertPtr, *clientKeyPtr)

	if config.Remotehost == "" {
		fmt.Println("[x] Remote host required")
		flag.PrintDefaults()
		os.Exit(1)
	}

	startListener(*tlsPtr)
}
