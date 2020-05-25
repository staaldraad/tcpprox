build:
	go build -o tcpprox tcpprox.go

run:
	go run tcpprox.go
	
build all:
	# 32-bit
	# Linux
	GOOS=linux GOARCH=386 go build -o tcpprox-linux86
	sha256sum  tcpprox-linux86 
	# Windows
	GOOS=windows GOARCH=386 go build -o tcpprox-win86.exe 
	sha256sum  tcpprox-win86.exe 
	# OSX
	GOOS=darwin GOARCH=386 go build -o tcpprox-osx86
	sha256sum  tcpprox-osx86

	# 64-bit
	# Linux
	GOOS=linux GOARCH=amd64 go build -o tcpprox-linux64
	sha256sum  tcpprox-linux64      
	# Windows
	GOOS=windows GOARCH=amd64 go build -o tcpprox-win64.exe  
	sha256sum  tcpprox-win64.exe
 	# OSX
	GOOS=darwin GOARCH=amd64 go build -o tcpprox-osx64
	sha256sum  tcpprox-osx64
