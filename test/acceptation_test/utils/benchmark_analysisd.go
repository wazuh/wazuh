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
	"time"
)

// Path to the output file
const AlertsFilePath string = "/var/ossec/logs/alerts/alerts.json"

// Path to the sockets
const SockPath string = "/var/ossec/queue/sockets/queue"

// Struct config for rate benchmark
type rateConfig struct {
	rate     int    // Rate (Events/sec) of the benchmark
	timeTest int    // Time duration of the benchmark
	srcFile  string // Path to dataset of event (1 event per line)
	dstFile  string // Path to the output file
}

// Report of rate benchmark
type rateReport struct {
	startTime   time.Time // Starting time
	endTime     time.Time // Ending time
	totalEvents int       // Total events send
	proccessEvents int    // Total events proccessed
	// Burst info
	repeat int // How many times the batch is sent per burst
	rest   int // How many events are partially sent (to reach the rate) per burst
}

// #TODO Add a function/test/benchmark to measure the latency of log process in high load
func main() {

	/*   Arguments	*/
	// Path to dataset of logs
	var logFile string
	// Time duration of the benchmark
	var timeTest int
	// Rate (Events/sec) of the benchmark
	var rate int

	// Parcer arguments
	flag.StringVar(&logFile, "f", "./test_logs.txt", "Path to dataset of logs")
	flag.IntVar(&timeTest, "t", 10, "Time of the benchmark")
	flag.IntVar(&rate, "r", 35, "Rate (Events/sec) of the benchmark")
	flag.Parse()

	// Validate parameters
	if rate <= 0 || timeTest <= 0 {
		log.Fatalf("Error: -t and -r must be greater than 0")
	}

	// Connect to the socket
	conn := connectToSock(SockPath)
	defer conn.Close()

	// if benchmark is a rate benchmark
	rateConfig := rateConfig{rate, timeTest, logFile, AlertsFilePath}
	tReport := rateTest(rateConfig, conn)
	printReport(tReport, rateConfig)

}

// -----------------------------------------------------------------------------
//	 						Test functions
// -----------------------------------------------------------------------------
// Rate test fuctions

// Rate test
func rateTest(config rateConfig, conn net.Conn) rateReport{

	report := rateReport{}
	//  Clean output before start
	os.Truncate(config.dstFile, 0)

	// Read input file
	BatchEvents, _ := loadLines(config.srcFile)
	lenBatchEvents := len(BatchEvents)

	if lenBatchEvents == 0 {
		log.Fatalf("Error: File %s is empty\n", config.srcFile)
	}

	report.repeat = config.rate / lenBatchEvents
	report.rest = config.rate % lenBatchEvents

	// Start benchmark
	report.startTime = time.Now()
	for sec := 0; sec < config.timeTest; sec++ {
		// Windows time of the burst send
		var ti time.Time = time.Now()
		var tf time.Time

		for i := int(0); i < report.repeat; i++ {
			for _, line := range BatchEvents {
				sendLogSock(conn, line)
			}
		}
		for i := int(0); i < report.rest; i++ {
			sendLogSock(conn, BatchEvents[i])
		}

		tf = time.Now()
		sleepTimeNano := time.Second - tf.Sub(ti) // It shouldn't be more than one second, let's not check it.
		time.Sleep(sleepTimeNano)
	}
	report.endTime = time.Now()

	// Wait a grace period to process the last events and flush the queue
	time.Sleep(time.Millisecond * 500)
	report.proccessEvents = fileLineCounter(AlertsFilePath)
	report.totalEvents = (report.repeat*lenBatchEvents + report.rest) * config.timeTest

	return report
}

// print report
func printReport(report rateReport, config rateConfig) {
	fmt.Printf("\n\n")
	fmt.Printf("Benchmark report\n")
	fmt.Printf("----------------\n\n")

	fmt.Printf("Configuration:\n")
	fmt.Printf("Rate:         	  %10d events/sec\n", config.rate)
	fmt.Printf("Time:         	  %10d sec\n", config.timeTest)
	fmt.Printf("Dataset: %s\n", config.srcFile)
	fmt.Printf("Output:  %s\n", config.dstFile)
	fmt.Printf("\n")

	fmt.Printf("Results:\n")
	fmt.Printf("Duration:         %10f seconds\n", report.endTime.Sub(report.startTime).Seconds())
	fmt.Printf("Sent events:      %10v\n", report.totalEvents)
	fmt.Printf("Processed events: %10v\n", report.proccessEvents)
	fmt.Printf("Lost events:      %10v\n", report.totalEvents - report.proccessEvents)
	fmt.Printf("\n")

}

// -----------------------------------------------------------------------------
//	 						Sockets functions
// -----------------------------------------------------------------------------

// Exit on fail
func connectToSock(socket string) net.Conn {

	conn, err := net.Dial("unixgram", socket)
	if err != nil {
		fmt.Printf("Failed to dial: %v\n", err)
		os.Exit(1)
	}

	return conn
}

// Exit on fail
func sendLogSock(conn net.Conn, message string) {
	var payload []byte

	ret := '\r'
	payload = []byte("1:[123] (hostname_test_bench) any->/var/some_location:" + message + string(ret))

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
