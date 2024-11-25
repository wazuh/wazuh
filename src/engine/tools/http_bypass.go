package main

import (
    "io"
    "log"
    "net"
    "net/http"
    "flag"
    "bufio"
    "fmt"
)

func proxyRequestToUnixSocket(socketPath string, w http.ResponseWriter, r *http.Request) {
    log.Println("Connecting to UNIX socket")
    conn, err := net.Dial("unix", socketPath)
    if err != nil {
        log.Printf("Error connecting to UNIX socket: %v", err)
        http.Error(w, "Failed to connect to UNIX socket", http.StatusInternalServerError)
        return
    }
    defer conn.Close()
    log.Println("Connected to UNIX socket")

    // Forward the request line and headers
    requestLine := fmt.Sprintf("%s %s HTTP/1.0\r\n", r.Method, r.URL.RequestURI())
    if _, err := conn.Write([]byte(requestLine)); err != nil {
        log.Printf("Error writing request line to UNIX socket: %v", err)
        http.Error(w, "Failed to write request line to UNIX socket", http.StatusInternalServerError)
        return
    }

    if err := r.Header.Write(conn); err != nil {
        log.Printf("Error writing headers to UNIX socket: %v", err)
        http.Error(w, "Failed to write headers to UNIX socket", http.StatusInternalServerError)
        return
    }

    // Terminate headers section
    if _, err := conn.Write([]byte("\r\n")); err != nil {
        log.Printf("Error terminating headers to UNIX socket: %v", err)
        http.Error(w, "Failed to terminate headers to UNIX socket", http.StatusInternalServerError)
        return
    }

    if _, err := io.Copy(conn, r.Body); err != nil {
        log.Printf("Error copying body to UNIX socket: %v", err)
        http.Error(w, "Failed to copy body to UNIX socket", http.StatusInternalServerError)
        return
    }

    log.Println("Request sent to UNIX socket, reading response")
    responseReader := bufio.NewReader(conn)
    response, err := http.ReadResponse(responseReader, r)
    if err != nil {
        log.Printf("Error reading response from UNIX socket: %v", err)
        http.Error(w, "Failed to read response from UNIX socket", http.StatusInternalServerError)
        return
    }
    defer response.Body.Close()

    // Copy the headers from the response
    for k, vv := range response.Header {
        for _, v := range vv {
            w.Header().Add(k, v)
        }
    }
    w.WriteHeader(response.StatusCode)
    _, err = io.Copy(w, response.Body)
    if err != nil {
        log.Printf("Error copying response body to HTTP client: %v", err)
    }
}

func handler(socketPath string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        proxyRequestToUnixSocket(socketPath, w, r)
    }
}

func main() {
    var portServer, apiSocketPath string
    flag.StringVar(&portServer, "p", ":80", "Port to listen on")
    flag.StringVar(&apiSocketPath, "a", "/run/wazuh-server/engine.socket", "Path to API engine socket")

    flag.Parse()

    http.HandleFunc("/", handler(apiSocketPath))
    log.Fatal(http.ListenAndServe(portServer, nil))
}
