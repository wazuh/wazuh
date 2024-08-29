package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
)

func main() {

	var sockPath string = "/var/ossec/queue/sockets/queue" // Path to unix socket
	var conn net.Conn
	var logFile string
	var logMessage string
	var isRawMessage bool
	var loops uint

	flag.StringVar(&logFile, "f", "test_logs_base.txt", "Path to dataset of logs")
	flag.StringVar(&logMessage, "m", "", "Only log")
	flag.BoolVar(&isRawMessage, "r", false, "Use raw message")
	flag.UintVar(&loops, "l", 1, "Number of times we send all the logs of the file")
	flag.Parse()

	conn = connectSockunix(sockPath)
	defer conn.Close()

	if logMessage == "" {
		lines, err := readLines(logFile)
		if err != nil {
			log.Fatalf("readLines: %s", err)
		}
		for i := uint(0); i < loops; i++ {
			j := 1000 * int(i+1)
			for _, line := range lines {
				sockQuery(conn, line, j, isRawMessage)
				j++
			}
		}
	} else {
		sockQuery(conn, logMessage, 000, isRawMessage)
	}

}

// Exit on fail
func sockQuery(conn net.Conn, message string, agentid int, is_raw bool) {
	var payload []byte

	if is_raw {
		payload = []byte(message)
	} else {
		agentStr := strconv.Itoa(agentid)
		payload = []byte("2:[" + agentStr + "] (hostname" + agentStr + ") any->/var/cosas:" + message)
	}

	if _, err := conn.Write(payload); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	return
}

// Exit on fail
func connectSockunix(socket string) net.Conn {

	conn, err := net.Dial("unixgram", socket)
	if err != nil {
		fmt.Printf("Failed to dial: %v\n", err)
		os.Exit(1)
	}

	return conn
}

// Exit on fail
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Failed on read: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
