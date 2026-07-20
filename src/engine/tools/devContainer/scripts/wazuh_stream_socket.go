package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
)

func main() {

	var sockPath string // Path to unix socket
	var sockAddr string // Path to unix socket
	var message string  //  message
	var proto string
	var response string
	var secure bool

	var conn net.Conn

	flag.StringVar(&sockPath, "f", "", "Unix socket path")
	flag.StringVar(&sockAddr, "s", "", "socket IP:PORT")
	flag.StringVar(&message, "m", "#ping", "raw message to send socket")
	flag.StringVar(&proto, "p", "tcp", "protocol: tcp or udp")
	flag.BoolVar(&secure, "h", true, "inser header")
	flag.Parse()

	if sockAddr != "" {
		conn = connectSockIP(sockAddr, proto)
	} else if sockPath != "" {
		conn = connectSockunix(sockPath)
	} else {
		fmt.Printf("dame un socket pa")
		os.Exit(1)
	}
	defer conn.Close()

	response = sockQuery(conn, message, secure);

	fmt.Printf("Response: %s\n", response)

}

// Un handshake de mensajes
func sockQuery(conn net.Conn, message string, secure bool) string {
	response := make([]byte, 65000)
	var sizeBuf int32 = 0
	var  payload []byte

	if secure {
		payload = secureMessage(message);	
	} else {
		payload = []byte(message)
	}

	if _, err := conn.Write(payload); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if !secure {
		if _, err := conn.Read(response[0:]); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		return  string(response);
	}

	if _, err := conn.Read(response[0:4]); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	} else {
		sizeBuf = int32(binary.LittleEndian.Uint32(response))
	}

	if sizeBuf > 0 {
		if _, err := conn.Read(response[:sizeBuf]); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("Header error: 0 bytes to recv")
		os.Exit(1)
	}

	return string(response[:sizeBuf])

}

// mete cabecera con tamaño del payload
func secureMessage(message string) []byte {

	secMsg := new(bytes.Buffer)
	payload := []byte(message)
	err := binary.Write(secMsg, binary.LittleEndian, int32(len(payload)))

	if err != nil {
		fmt.Println("binary.Write failed:", err)
		os.Exit(1)
	}

	payload = append(secMsg.Bytes(), payload...)
	return payload
}

// Exit on fail
func connectSockIP(socket string, proto string) net.Conn {

	conn, err := net.Dial(proto, socket)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	return conn
}

// Exit on fail

func connectSockunix(socket string) net.Conn {

	// Resolver and conect to socket
	addr, err := net.ResolveUnixAddr("unix", socket)
	if err != nil {
		fmt.Printf("Failed to resolve: %v\n", err)
		os.Exit(1)
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		fmt.Printf("Failed to dial: %v\n", err)
		os.Exit(1)
	}

	return conn
}
