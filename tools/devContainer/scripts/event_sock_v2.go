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
	"strings"
	"time"
)

func main() {

	var sockPath string = "/var/wazuh-manager/queue/sockets/engine-ingest-http.sock" // Path to HTTP unix socket
	var logFile string
	var logMessage string
	var isRawMessage bool
	var loops uint
	var agentid uint
	var contentType string

	flag.StringVar(&logFile, "f", "test_logs_base.txt", "Path to dataset of logs")
	flag.StringVar(&logMessage, "m", "", "Only log")
	flag.BoolVar(&isRawMessage, "r", false, "Use raw H/E batches; -f preserves batches and -m sends one batch")
	flag.UintVar(&loops, "l", 1, "Number of times we send all the logs of the file")
	flag.StringVar(&contentType, "c", "application/x-ndjson", "Content-Type header (default: application/x-ndjson)")
	flag.StringVar(&sockPath, "s", sockPath, "Path to HTTP unix socket")
	flag.UintVar(&agentid, "a", 123, "Agent ID for a generated single message; in raw mode, optionally require this ID in every H line")
	flag.Parse()
	expectedID := ""
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "a" {
			expectedID = fmt.Sprintf("%03d", agentid)
		}
	})

	// Create HTTP client with Unix socket transport
	client := createHTTPClient(sockPath)

	if logMessage == "" {
		lines, err := readMessages(logFile, isRawMessage)
		if err != nil {
			log.Fatalf("readMessages: %s", err)
		}
		for i := uint(0); i < loops; i++ {
			j := 1000 * int(i+1)
			for _, line := range lines {
				if err := sendEvent(client, line, j, isRawMessage, contentType, expectedID); err != nil {
					log.Fatal(err)
				}
				j++
			}
		}
	} else {
		if err := sendEvent(client, logMessage, int(agentid), isRawMessage, contentType, expectedID); err != nil {
			log.Fatal(err)
		}
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

// rawAgentID reads the batch identity without rewriting the producer's metadata.
// The engine remains responsible for full framing, duplicate-member and identity validation.
func rawAgentID(payload string) (string, error) {
	if !strings.HasPrefix(payload, "H ") {
		return "", fmt.Errorf("raw batch must start with 'H '")
	}
	end := strings.IndexByte(payload, '\n')
	if end < 0 {
		end = len(payload)
	}
	if strings.Contains(payload[end:], "\nH ") {
		return "", fmt.Errorf("raw message contains multiple batches; use -f for batch files")
	}
	var header struct {
		Wazuh struct {
			Agent struct {
				ID string `json:"id"`
			} `json:"agent"`
		} `json:"wazuh"`
	}
	if err := json.Unmarshal([]byte(payload[2:end]), &header); err != nil {
		return "", fmt.Errorf("invalid raw H-line JSON: %w", err)
	}
	id := header.Wazuh.Agent.ID
	n, err := strconv.ParseUint(id, 10, 32)
	if err != nil || id != fmt.Sprintf("%03d", n) {
		return "", fmt.Errorf("raw H-line wazuh.agent.id must be a canonical uint32 string, got %q", id)
	}
	return id, nil
}

// eventRequest binds the carrier to the raw identity, or authors both for a generated message.
func eventRequest(message string, agentID int, raw bool, contentType, expectedID string) (*http.Request, error) {
	var payload, id string
	if raw {
		var err error
		id, err = rawAgentID(message)
		if err != nil {
			return nil, err
		}
		if expectedID != "" && id != expectedID {
			return nil, fmt.Errorf("raw H-line agent ID %q does not match -a %q", id, expectedID)
		}
		payload = message
	} else {
		if agentID < 0 || uint64(agentID) > (1<<32)-1 {
			return nil, fmt.Errorf("agent ID is outside uint32 range")
		}
		id = fmt.Sprintf("%03d", agentID)
		header := map[string]interface{}{
			"wazuh": map[string]interface{}{
				"agent": map[string]interface{}{"id": id, "name": fmt.Sprintf("hostname%d", agentID)},
			},
		}
		encoded, err := json.Marshal(header)
		if err != nil {
			return nil, fmt.Errorf("marshal header: %w", err)
		}
		payload = fmt.Sprintf("H %s\nE 1:/var/random/loc:%s\n", encoded, message)
	}
	if len(payload) > 0 && payload[len(payload)-1] != '\n' {
		payload += "\n"
	}
	req, err := http.NewRequest(http.MethodPost, "http://localhost/events/enriched", bytes.NewBufferString(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Wazuh-Agent-Id", id)
	return req, nil
}

func sendEvent(client *http.Client, message string, agentID int, raw bool, contentType, expectedID string) error {
	req, err := eventRequest(message, agentID, raw, contentType, expectedID)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("engine returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	payload, err := req.GetBody()
	if err != nil {
		return err
	}
	defer payload.Close()
	fmt.Print("Sent: ")
	if _, err := io.Copy(os.Stdout, payload); err != nil {
		return err
	}
	return nil
}

// Raw files contain complete H/E batches. Each unindented H line starts the next batch;
// indented continuation lines remain part of the current event. Ordinary datasets remain line-based.
func readMessages(path string, raw bool) ([]string, error) {
	if raw {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("raw batch file is empty")
		}
		payload := string(data)
		var batches []string
		start := 0
		for {
			next := strings.Index(payload[start:], "\nH ")
			if next < 0 {
				batches = append(batches, payload[start:])
				break
			}
			end := start + next + 1
			batches = append(batches, payload[start:end])
			start = end
		}
		for i, batch := range batches {
			if _, err := rawAgentID(batch); err != nil {
				return nil, fmt.Errorf("raw batch %d: %w", i+1, err)
			}
		}
		return batches, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
