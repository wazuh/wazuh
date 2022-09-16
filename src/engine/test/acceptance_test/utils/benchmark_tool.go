package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

// Struct config for rate benchmark
type rateConfig struct {
	rate       int    // Rate (Events/sec) of the benchmark
	timeTest   int    // Time duration of the benchmark
	srcFile    string // Path to dataset of event (1 event per line)
	dstFile    string // Path to the output file
	truncFile  bool   // Truncate the output file
	concurrent int    // Number of concurrent connections
	fullFormat bool   // Use full format msg. Dont preppend  1:[123] agent->server: log
}

// Report of rate benchmark
type rateReport struct {
	startTime      time.Time // Starting time
	endTime        time.Time // Ending time
	totalEvents    int       // Total events send
	proccessEvents int       // Total events proccessed
	// Burst info
	repeat int // How many times the batch is sent per burst
	rest   int // How many events are partially sent (to reach the rate) per burst
}

// #TODO Add a function/test/benchmark to measure the latency of log process in high load
func main() {

	/*   Arguments	*/
	// Path to dataset of logs
	var datasetFile string
	// Time duration of the benchmark
	var timeTest int
	// Rate (Events/sec) of the benchmark
	var rate int
	// Number of concurrent connections
	var concurrent int
	// Path to the output file
	var watchedFile string
	var truncateWatched bool
	// Path/Adress to the sockets
	var sockPath string
	// Path/Adress to the sockets
	var sockProto string
	// header size in message
	var header bool
	// Full format msg
	var fullFormat bool

	// Parcer arguments
	// Bench
	flag.IntVar(&timeTest, "t", 5, "Time of the benchmark")
	flag.IntVar(&rate, "r", 35, "Rate (Events/sec) of the benchmark. 0 for infinite")
	flag.IntVar(&concurrent, "c", 1, "Number of concurrent connections")
	// IO Files
	flag.StringVar(&datasetFile, "i", "./test_logs.txt", "Path to dataset of logs. The input File")
	flag.StringVar(&watchedFile, "o", "/var/ossec/logs/alerts/alerts.json", "Watched file. The Output file")
	flag.BoolVar(&truncateWatched, "T", false, "Truncate the output file")
	// Protocol
	flag.StringVar(&sockPath, "s", "/var/ossec/queue/sockets/queue", "Path/Adress to the sockets")
	flag.StringVar(&sockProto, "p", "unixgram", `Known networks are "tcp", "tcp4" (IPv4-only), `+
		`"tcp6" (IPv6-only), "udp", "udp4" (IPv4-only), `+
		`"udp6" (IPv6-only), "ip", "ip4" (IPv4-only),`+
		`"ip6" (IPv6-only), "unix", "unixgram" and "unixpacket". `)
	//flag.BoolVar(&verbose, "v", false, "Verbose mode")
	flag.BoolVar(&header, "b", false, "Use secure msg protocol. Preappend a header with size of logs (int32) before send")
	flag.BoolVar(&fullFormat, "f", false, "Use full format msg. Dont preppend  1:[123] agent->server: log")
	flag.Parse()

	// Validate parameters
	if concurrent < 1 {
		log.Fatalf("Error: concurrent must be greater than 0\n")
	} else if timeTest <= 0 {
		log.Fatalf("Error: timeTest must be greater than 0\n")
	} else if rate < 0 {
		log.Fatalf("Error: rate must be greater than 0\n")
	}

	// Connect to the socket
	conn := connectToSock(sockProto, sockPath)
	defer conn.Close()

	// if benchmark is a rate benchmark
	rateConfig := rateConfig{rate, timeTest, datasetFile, watchedFile, truncateWatched, concurrent, fullFormat}
	tReport := rateTest(rateConfig, conn, header)
	printReport(tReport, rateConfig)

}

// -----------------------------------------------------------------------------
//	 						Test functions
// -----------------------------------------------------------------------------
// Rate test fuctions

// Rate test
func rateTest(config rateConfig, conn net.Conn, header bool) rateReport {

	report := rateReport{}
	//  Clean output before start
	if config.truncFile {
		os.Truncate(config.dstFile, 0)
	}

	// Read input file
	BatchEvents, _ := loadLines(config.srcFile)
	lenBatchEvents := len(BatchEvents)

	if lenBatchEvents == 0 {
		log.Fatalf("Error: File %s is empty\n", config.srcFile)
	}

	var sleepTimeNano time.Duration
	// If not infinite rate
	if config.rate != 0 {
		report.repeat = config.rate / lenBatchEvents
		report.rest = config.rate % lenBatchEvents
		sleepTimeNano = time.Duration(1e9 / config.rate)
		fmt.Printf("sleepTimeNano: %v\n", sleepTimeNano)
	} else {
		report.repeat = 1
		report.rest = 0
		sleepTimeNano = 0
	}

	// Start benchmark
	report.totalEvents = 0
	report.startTime = time.Now()
	timeout := time.After(time.Duration(config.timeTest) * time.Second)
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	var eps int
	for {
		select {

		case <-timeout:
			report.endTime = time.Now()
			fmt.Printf("EPS: %10d\n", eps)
			// Wait a grace period to process the last events and flush the queue
			time.Sleep(time.Second * 5)
			report.proccessEvents = fileLineCounter(config.dstFile)
			return report
		case <-tick.C:
			// Calculate the eps
			fmt.Printf("EPS: %10d\n", eps)
			eps = 0
		default:
			// Send the batch
			for i := int(0); i < report.repeat; i++ {
				for _, line := range BatchEvents {
					until := time.Now().Add(sleepTimeNano)
					sendLogSock(conn, header, line, config.fullFormat)
					eps += 1
					report.totalEvents++
					for time.Now().Before(until) {
							continue
					}

				}
			}
			for i := int(0); i < report.rest; i++ {
				until := time.Now().Add(sleepTimeNano)
				sendLogSock(conn, header, BatchEvents[i], config.fullFormat)
				eps += 1
				report.totalEvents++
				for time.Now().Before(until) {
					continue
				}
			}
		}

	}
}

// print report
func printReport(report rateReport, config rateConfig) {
	fmt.Printf("\n\n")
	fmt.Printf("Benchmark report\n")
	fmt.Printf("----------------\n\n")

	fmt.Printf("Configuration:\n")
	if config.rate != 0 {
		fmt.Printf("Rate:         	  %10d events/sec\n", config.rate)
	} else {
		// Calcular los eps
		fmt.Printf("Rate:         	  %10s events/sec\n", "infinite")
	}
	fmt.Printf("Time:         	  %10d sec\n", config.timeTest)
	fmt.Printf("Concurrent connections: %d\n", config.concurrent)
	fmt.Printf("Dataset: %s\n", config.srcFile)
	fmt.Printf("Output:  %s\n", config.dstFile)
	fmt.Printf("\n")

	fmt.Printf("Results:\n")
	fmt.Printf("Duration:         %10f seconds\n", report.endTime.Sub(report.startTime).Seconds())
	fmt.Printf("Sent events:      %10v\n", report.totalEvents)

	fmt.Printf("Processed events: %10v\n", report.proccessEvents)
	fmt.Printf("Lost events:      %10v\n", report.totalEvents-report.proccessEvents)
	fmt.Printf("\n")

}

// -----------------------------------------------------------------------------
//	 						Sockets functions
// -----------------------------------------------------------------------------

// Exit on fail
func connectToSock(protocol string, address string) net.Conn {

	conn, err := net.Dial(protocol, address)
	if err != nil {
		fmt.Printf("Failed to dial: %v\n", err)
		os.Exit(1)
	}

	return conn
}

// Exit on fail
func sendLogSock(conn net.Conn, header bool, message string, fullFormat bool) {
	var payload []byte

	if fullFormat {
		payload = []byte(message)
	} else {
		payload = []byte("1:[123] (hostname_test_bench) any->/var/some_location:" + message)
	}

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

// -----------------------------------------------------------------------------
//	 							Files funcitions
// -----------------------------------------------------------------------------

/*
 * Load linea of a file in array string
 * Exit on fail
 */
func loadLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed on read: %v\n", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

/*
 * Count lines of a file
 * Exit on fail
 */
func fileLineCounter(fileName string) int {

	r, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("os.Open(%s): %s", fileName, err)
	}

	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := r.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			return count

		case err != nil:
			log.Fatalf("Error to open file: %s\n", err)
		}
	}
}
