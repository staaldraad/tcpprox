FROM golang:1.7.3 as builder

#COPY . $GOPATH/src/github.com/staaldraad/tcpprox/
RUN go get github.com/staaldraad/tcpprox
WORKDIR $GOPATH/src/github.com/staaldraad/tcpprox/

#RUN go build -o /go/bin/tcpprox
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/tcpprox

FROM scratch
COPY --from=builder /go/bin/tcpprox /go/bin/tcpprox
ENTRYPOINT [ "/go/bin/tcpprox" ]

