# tcpprox


A simple TCP proxy written in GO. Allows for proxy-ing TCP connections as well as TLS wrapped TCP connections.

Can be run simply from the command-line using arguments. Or supplying a config file. Or both.
_The command line arguments have precidence and override the config file_

# Usage

To create a TLS proxy using the supplied config file:

`tcpprox -s -c config.json -r 172.16.0.12:4550`

To create a normal TCP proxy,  no config file:

`tcpprox -l 0.0.0.0 -p 8081 -r 172.16.0.12:8081`

To specify a custom certificate to use (PEM format) you can use the -cert option:

`tcpprox -s -c config.json -cert server`

Where server is the prefix to server.pem and server.key (I'm lazy...)
To generate valid certificate and key:

`
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.pem -days 3650
`
To convert the certificate to DER format:

`openssl x509 -in server.pem -out server.crt -outform der`


# Using Docker

_note_: ensure you are running 'real' Docker [docker-ce](https://docs.docker.com/install/#supported-platforms)

**To build locally with Docker:**

```
docker build . -t staaldraad/tcpprox:latest
```

Or, even better, just get it directly off of Docker Hub

**Get from Docker Hub**

```
docker pull staaldraad/tcpprox:latest
```

**Run the container:**

```
docker run -it --rm -p 8000:8000 staaldraad/tcpprox:latest -p 8000 -s -r google.com:443
```

This will create a TLS enabled listener on port 8000 and proxy traffic to google.com:443

