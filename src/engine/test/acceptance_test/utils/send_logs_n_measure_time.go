package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	var srcLogsFilePath string = "./test_logs.txt"
	var archivesFilePath string = "/var/wazuh-manager/logs/archives/archives.json"
	var sockPath string = "/var/wazuh-manager/queue/sockets/queue-http.sock" // Path to unix socket
	var logFile string
	var logMessage string
	var loops int
	var s_num int
	var t_i time.Time
	var t_g time.Time
	var t_o time.Time
	var acc int = 0
	var err error
	var agentId int
	var contentType string
	var skipArchiveWait bool

	flag.StringVar(&logFile, "f", srcLogsFilePath, "Path to dataset of logs")
	flag.StringVar(&logMessage, "m", "", "Only log")
	flag.IntVar(&loops, "l", 1, "Number of times we send all the logs of the file")
	flag.IntVar(&agentId, "a", 1, "Agent ID to use with single log message, defaults to 1")
	flag.StringVar(&contentType, "c", "application/x-ndjson", "Content-Type header (default: application/x-ndjson)")
	flag.StringVar(&sockPath, "s", sockPath, "Path to HTTP unix socket")
	flag.BoolVar(&skipArchiveWait, "skip-wait", false, "Skip waiting for events in archives (just send and exit)")
	flag.Parse()

	fmt.Printf("Sending to socket: %s\n", sockPath)
	if !skipArchiveWait {
		fmt.Printf("Archives file: %s\n", archivesFilePath)
	}

	// Create HTTP client with Unix socket transport
	client := createHTTPClient(sockPath)

	{
		os.Truncate(archivesFilePath, 0)
	}

	if logMessage == "" {
		r, _ := os.Open(srcLogsFilePath)
		s_num, err = lineCounter(r)
		if err != nil {
			log.Fatalf("os.Open(%s): %s", srcLogsFilePath, err)
		}
		s_num *= loops

		lines, err := readLines(logFile)
		if err != nil {
			log.Fatalf("readLines: %s", err)
		}
		t_i = time.Now()

		for i := int(0); i < loops; i++ {
			j := 1000 * int(i+1)
			for _, line := range lines {
				sendEvent(client, line, j, contentType)
				j++
			}
		}

		t_g = time.Now()

	} else {
		// Single message mode
		s_num = 1
		t_i = time.Now()
		fmt.Printf("Sending single message (agent %d): %s\n", agentId, logMessage)
		sendEvent(client, logMessage, agentId, contentType)
		t_g = time.Now()
		fmt.Printf("Message sent successfully. Waiting for it to appear in archives...\n")
	}

	if skipArchiveWait {
		fmt.Printf("Skipping archive wait. Events sent successfully.\n")
		fmt.Printf("Send ingestion elapsed time: %dus\n", t_g.Sub(t_i).Microseconds())
		return
	}

	t_lc := time.Now()
	acc = 0
	timeout := time.After(30 * time.Second) // 30 second timeout
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for acc != s_num {
		select {
		case <-timeout:
			log.Fatalf("Timeout waiting for events in archives file. Expected: %d, Got: %d", s_num, acc)
		case <-ticker.C:
			// Open and count lines from the beginning each time
			r, err := os.Open(archivesFilePath)
			if err != nil {
				log.Fatalf("os.Open(%s): %s", archivesFilePath, err)
			}
			// Count lines and divide by 2 since each event produces 2 lines (H and E)
			lineCount, err := lineCounter(r)
			r.Close()
			if err != nil {
				log.Fatalf("lineCounter: %s", err)
			}
			// Each event produces 2 lines in archives (H line and E line)
			acc = lineCount / 2
			if acc > 0 {
				fmt.Printf("Found %d events in archives (%d lines)...\n", acc, lineCount)
			}
		}
	}
	t_o = time.Now()

	t_diff := t_o.Sub(t_i)
	t_inge := t_g.Sub(t_i)
	t_read := t_o.Sub(t_lc)
	t_per_log := t_diff.Microseconds() / int64(acc)

	fmt.Printf("Processing time per log: %dus\n", t_per_log)
	fmt.Printf("Send ingestion elapsed time: %dus\n", t_inge.Microseconds())
	fmt.Printf("Read output elapsed time: %dus\n", t_read.Microseconds())
	fmt.Printf("Send-to-output elapsed time: %dus\n", t_diff.Microseconds())

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
func sendEvent(client *http.Client, message string, agentid int, contentType string) {
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
	// Add \r at the end like the original did
	eventLine := fmt.Sprintf("1:/var/some_location:%s\r", message)

	// Combine in H/E format
	payload := fmt.Sprintf("H %s\nE %s\n", string(headerBytes), eventLine)

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
		// Read response body for error details
		bodyBytes, _ := io.ReadAll(resp.Body)
		if len(bodyBytes) > 0 {
			fmt.Printf("Response body: %s\n", string(bodyBytes))
		}
		os.Exit(1)
	}
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

// Counts the lines of a file ('\n')
func lineCounter(r io.Reader) (int, error) {
	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := r.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			return count, nil

		case err != nil:
			return count, err
		}
	}
}
