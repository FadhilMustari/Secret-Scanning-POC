package main

import (
	"fmt"
)

const (
	awsRegion          = "ap-southeast-1"
)

func main() {
	fmt.Println("Payment integration service starting...")
	fmt.Printf("Connecting to AWS region: %s\n", awsRegion)
}
