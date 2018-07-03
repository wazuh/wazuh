package main

import (
	"./audit"
	"fmt"
)

func main() {
	if audit.AuditValueNeedsEncoding("test") {
		fmt.Printf("Failed test 1\n")
		return
	}
	if !audit.AuditValueNeedsEncoding("test test") {
		fmt.Printf("Failed test 2\n")
		return
	}
	fmt.Printf("Success\n")
}
