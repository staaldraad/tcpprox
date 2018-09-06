FROM golang

COPY . $GOPATH/src/github.com/staaldraad/tcpprox/
WORKDIR $GOPATH/src/github.com/staaldraad/tcpprox/

RUN go build -v

ENTRYPOINT [ "./tcpprox", "-l", "0.0.0.0" ]
