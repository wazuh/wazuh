package main

import (
	"bytes"
	"encoding/binary"
    "fmt"
    "net"
	"net/http"
	"log"
	"flag"
	"io"
	"os"
)

/*****************************************************************************************
 *  API Handler
 *****************************************************************************************/
func apiHandler(path string)  http.HandlerFunc {

	return func (w http.ResponseWriter, req *http.Request) {

		// Conect to unix socket to api
		addr, err := net.ResolveUnixAddr("unix", path)
		if err != nil {
			log.Fatal(fmt.Sprintf("Failed to resolve: %v\n", err))
		}

		conn, err := net.DialUnix("unix", nil, addr)
		if err != nil {
			log.Fatal(fmt.Sprintf("Failed to dial: %v\n", err))
		}


		// Print de json request
		defer req.Body.Close()
		b, err := io.ReadAll(req.Body)
		if err != nil {
			log.Fatal(err)
		}
		reqStr := string(b)

		if(reqStr == "") {
			reqStr = "{}"
		}

		fmt.Println("Request: ", reqStr)

		// Send request to api
		response := sockQuery(conn, reqStr, true)
		fmt.Println("Response: ", response)

		fmt.Fprintf(w, response)
	}
}

/*****************************************************************************************
 *  Auxiliar functions
 *****************************************************************************************/

func sockQuery(conn net.Conn, message string, secure bool) string {
	response := make([]byte, 650000)
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

/*****************************************************************************************
 *  API Handler
 *****************************************************************************************/

func main() {

	var portServer string // port to listen
	var apiSocketPath string // Path to unix socket

	flag.StringVar(&portServer, "p", ":80", "Address to listen")
	flag.StringVar(&apiSocketPath, "a", "/var/ossec/queue/sockets/engine-api", "API engine socket path") // Datagram + header

	flag.Parse()


    http.HandleFunc("/api", apiHandler(apiSocketPath))
    // http.HandleFunc("/events", headers)

    log.Fatal(http.ListenAndServe(portServer, nil))


}
