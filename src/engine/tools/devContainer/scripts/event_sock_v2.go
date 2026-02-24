package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {

	var sockPath string = "/var/wazuh-manager/queue/sockets/queue-http.sock" // Path to HTTP unix socket
	var logFile string
	var logMessage string
	var isRawMessage bool
	var loops uint
	var contentType string

	flag.StringVar(&logFile, "f", "test_logs_base.txt", "Path to dataset of logs")
	flag.StringVar(&logMessage, "m", "", "Only log")
	flag.BoolVar(&isRawMessage, "r", false, "Use raw message (send as-is without wrapping in H/E format)")
	flag.UintVar(&loops, "l", 1, "Number of times we send all the logs of the file")
	flag.StringVar(&contentType, "c", "application/x-ndjson", "Content-Type header (default: application/x-ndjson)")
	flag.StringVar(&sockPath, "s", sockPath, "Path to HTTP unix socket")
	flag.Parse()

	// Create HTTP client with Unix socket transport
	client := createHTTPClient(sockPath)

	if logMessage == "" {
		lines, err := readLines(logFile)
		if err != nil {
			log.Fatalf("readLines: %s", err)
		}
		for i := uint(0); i < loops; i++ {
			j := 1000 * int(i+1)
			for _, line := range lines {
				sendEvent(client, line, j, isRawMessage, contentType)
				j++
			}
		}
	} else {
		sendEvent(client, logMessage, 123, isRawMessage, contentType)
	}

}

// createHTTPClient creates an HTTP client configured to use Unix socket
func createHTTPClient(socket string) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socket)
			},
		},
	}
}

// sendEvent sends an event via HTTP POST to the engine
func sendEvent(client *http.Client, message string, agentid int, isRaw bool, contentType string) {
	var payload string

	if isRaw {
		// Send message as-is (should be in H/E format already)
		payload = message
	} else {
		// Build H/E protocol format:
		// Line 1: H <JSON header with agent info>
		// Line 2: E <queue:location:message in OSSEC format>

		// Header line (JSON)
		header := map[string]interface{}{
			"wazuh": map[string]interface{}{
				"agent": map[string]interface{}{
					"id":   strconv.Itoa(agentid),
					"name": fmt.Sprintf("hostname%d", agentid),
				},
			},
		}
		headerBytes, err := json.Marshal(header)
		if err != nil {
			fmt.Printf("Error marshaling header JSON: %v\n", err)
			os.Exit(1)
		}

		// Event line (OSSEC format: queue_id:location:actual_message)
		eventLine := fmt.Sprintf("1:/var/random/loc:%s", message)

		// Combine in H/E format
		payload = fmt.Sprintf("H %s\nE %s\n", string(headerBytes), eventLine)
	}

	// Ensure payload ends with newline
	if len(payload) > 0 && payload[len(payload)-1] != '\n' {
		payload += "\n"
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", "http://localhost/events/enriched", bytes.NewBufferString(payload))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		os.Exit(1)
	}

	req.Header.Set("Content-Type", contentType)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Unexpected status code: %d\n", resp.StatusCode)
		os.Exit(1)
	}

	// Sent
	fmt.Printf("Sent: %s", payload)
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
