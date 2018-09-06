package main

import (
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
	"math/big"
	"net"
	"os"
	"time"
)

type TLS struct {
	Country    []string "GB"
	Org        []string ""
	CommonName string   "*.domain.com"
}

type Config struct {
	Remotehost string
	Localhost  string
	Localport  int
	TLS        *TLS
	CertFile   string ""
}

var config Config
var ids = 0

func genCert() ([]byte, *rsa.PrivateKey) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Country:      config.TLS.Country,
			Organization: config.TLS.Org,
			CommonName:   config.TLS.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pub := &priv.PublicKey
	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		fmt.Println("create ca failed", err)
	}
	return ca_b, priv
}

func handleServerMessage(connR, connC net.Conn, id int) {
	for {
		data := make([]byte, 2048)
		n, err := connR.Read(data)
		if n > 0 {
			connC.Write(data[:n])
			fmt.Printf("From Server [%d]:\n%s\n", id, hex.Dump(data[:n]))
			//fmt.Printf("From Server:\n%s\n",hex.EncodeToString(data[:n]))
		}
		if err != nil && err != io.EOF {
			fmt.Println(err)
			break
		}
	}
}

func handleConnection(conn net.Conn, isTLS bool) {
	var err error
	var connR net.Conn

	if isTLS == true {
		conf := tls.Config{InsecureSkipVerify: true}
		connR, err = tls.Dial("tcp", config.Remotehost, &conf)
	} else {
		connR, err = net.Dial("tcp", config.Remotehost)
	}

	if err != nil {
		return
	}

	fmt.Printf("[*][%d] Connected to server: %s\n", ids, connR.RemoteAddr())
	id := ids
	ids++
	go handleServerMessage(connR, conn, id)
	for {
		data := make([]byte, 2048)
		n, err := conn.Read(data)
		if n > 0 {
			fmt.Printf("From Client [%d]:\n%s\n", id, hex.Dump(data[:n]))
			//fmt.Printf("From Client:\n%s\n",hex.EncodeToString(data[:n]))
			connR.Write(data[:n])
			_ = hex.Dump(data[:n])
		}
		if err != nil && err == io.EOF {
			fmt.Println(err)
			break
		}
	}
	connR.Close()
	conn.Close()
}

func startListener(isTLS bool) {

	var err error
	var conn net.Listener
	var cert tls.Certificate

	if isTLS == true {
		if config.CertFile != "" {
			cert, _ = tls.LoadX509KeyPair(fmt.Sprint(config.CertFile, ".pem"), fmt.Sprint(config.CertFile, ".key"))
		} else {
			ca_b, priv := genCert()
			cert = tls.Certificate{
				Certificate: [][]byte{ca_b},
				PrivateKey:  priv,
			}
		}

		conf := tls.Config{
			Certificates: []tls.Certificate{cert},
		}
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

func setConfig(configFile string, localPort int, localHost, remoteHost string, certFile string) {
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

	if certFile != "" {
		config.CertFile = certFile
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
	certFilePtr := flag.String("cert", "", "Use a specific certificate file")

	flag.Parse()

	setConfig(*configPtr, *localPort, *localHost, *remoteHostPtr, *certFilePtr)

	if config.Remotehost == "" {
		fmt.Println("[x] Remote host required")
		flag.PrintDefaults()
		os.Exit(1)
	}

	startListener(*tlsPtr)
}
