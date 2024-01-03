build:
	go build -o tcpprox tcpprox.go

run:
	go run tcpprox.go

compile:
	# 32-bit
	# Linux
	GOOS=linux GOARCH=386 go build -o tcpprox-linux86
	sha256sum  tcpprox-linux86 > tcpprox-linux86.sha256sum
	# Windows
	GOOS=windows GOARCH=386 go build -o tcpprox-win86.exe 
	sha256sum  tcpprox-win86.exe > tcpprox-win86.sha256sum

	# 64-bit
	# Linux
	GOOS=linux GOARCH=amd64 go build -o tcpprox-linux64
	sha256sum  tcpprox-linux64 > tcpprox-linux64.sha256sum
	# Windows
	GOOS=windows GOARCH=amd64 go build -o tcpprox-win64.exe  
	sha256sum  tcpprox-win64.exe > tcpprox-win64.sha256sum
 	# OSX
	GOOS=darwin GOARCH=arm64 go build -o tcpprox-osxarm64
	sha256sum  tcpprox-osxarm64 > tcpprox-osxarm64.sha256sum
	GOOS=darwin GOARCH=amd64 go build -o tcpprox-osx64
	sha256sum  tcpprox-osx64 > tcpprox-osx64.sha256sum
