package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	var srcLogsFilePath string = "./test_logs.txt"
	var archivesFilePath string = "/var/ossec/logs/archives/archives.json"
	var sockPath string = "/var/ossec/queue/sockets/queue" // Path to unix socket
	var conn net.Conn
	var logFile string
	var logMessage string
	var loops int
	var s_num int
	var d_num int
	var t_i time.Time
	var t_g time.Time
	var t_o time.Time
	var acc int = 0
	var err error

	flag.StringVar(&logFile, "f", srcLogsFilePath, "Path to dataset of logs")
	flag.StringVar(&logMessage, "m", "", "Only log")
	flag.IntVar(&loops, "l", 1, "Number of times we send all the logs of the file")
	flag.Parse()

	conn = connectSockunix(sockPath)
	defer conn.Close()

	{
		os.Truncate(archivesFilePath, 0)
	}

	{
		r, _ := os.Open(srcLogsFilePath)
		s_num, err = lineCounter(r)
		if err != nil {
			log.Fatalf("os.Open(%s): %s", srcLogsFilePath, err)
		}
		s_num *= loops
	}

	if logMessage == "" {

		lines, err := readLines(logFile)
		if err != nil {
			log.Fatalf("readLines: %s", err)
		}
		t_i = time.Now()

		for i := int(0); i < loops; i++ {
			j := 1000 * int(i+1)
			for _, line := range lines {
				sockQuery(conn, line, j)
				j++
			}
		}

		t_g = time.Now()

	} else {
		sockQuery(conn, logMessage, 000)
	}

	r, err := os.Open(archivesFilePath)
	if err != nil {
		log.Fatalf("os.Open(%s): %s", archivesFilePath, err)
	}

	t_lc := time.Now()
	acc = 0
	for acc != s_num {
		d_num, err = lineCounter(r)
		acc += d_num
		if err != nil {
			log.Fatalf("lineCounter: %s", err)
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

// Exit on fail
func sockQuery(conn net.Conn, message string, agentid int) {
	var payload []byte

	agentStr := strconv.Itoa(agentid)
	ret := '\r'
	payload = []byte("1:[" + agentStr + "] (hostname" + agentStr + ") any->/var/some_location:" + message + string(ret))

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

//Counts the lines of a file ('\n')
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
