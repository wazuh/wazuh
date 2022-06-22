package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Exit on fail
func sendLogSock(conn net.Conn, header bool, message string, queue int, location string) {
	var payload []byte

	payload = []byte(strconv.Itoa(queue) + ":" + location + ":" + message)

	if header {
		secMsg := new(bytes.Buffer)
		err := binary.Write(secMsg, binary.LittleEndian, int32(len(payload)))
		if err != nil {
			fmt.Println("binary.Write failed:", err)
			os.Exit(1)
		}
		payload = append(secMsg.Bytes(), payload...)
	}

	if _, err := conn.Write(payload); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	return
}

func main() {

	/*   Arguments	*/
	// Path to the output file
	var watchedFile string
	// Path/Adress to the sockets
	var sockPath string
	// Path/Adress to the sockets
	var sockProto string
	// Queue
	var queue int
	// Location
	var location string

	// Parser arguments
	flag.StringVar(&watchedFile, "o", "/var/ossec/logs/alerts/alerts.json", "Watched file. The Output file")
	flag.StringVar(&sockPath, "s", "/var/ossec/queue/sockets/queue", "Path/Adress to the sockets")
	flag.StringVar(&sockProto, "p", "unixgram", `Known networks are "tcp", "tcp4" (IPv4-only), `+
		`"tcp6" (IPv6-only), "udp", "udp4" (IPv4-only), `+
		`"udp6" (IPv6-only), "ip", "ip4" (IPv4-only),`+
		`"ip6" (IPv6-only), "unix", "unixgram" and "unixpacket". `)
	flag.IntVar(&queue, "q", 0, "Queue")
	flag.StringVar(&location, "l", "[123] (hostname_test_bench) any->/var/some_location", "Location")
	flag.Parse()
	var inputs []string
	var input string
	if flag.NArg() == 0 {
		reader := bufio.NewReader(os.Stdin)
		var err error
		for err == nil {
			input, err = reader.ReadString('\n')
			if err == nil {
				input = strings.TrimSuffix(input, "\n")
				inputs = append(inputs, input)
			}
		}

	} else {
		for i := range flag.Args() {
			inputs = append(inputs, flag.Arg(i))
		}
	}

	for i := range inputs {
		fmt.Println(inputs[i])
	}

	// Connect to the socket
	conn, err := net.Dial(sockProto, sockPath)
	if err != nil {
		fmt.Printf("Failed to dial: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Send the messages
	for i := range inputs {
		sendLogSock(conn, true, inputs[i], queue, location)
	}
}
