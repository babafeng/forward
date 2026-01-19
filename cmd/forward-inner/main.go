package main

import (
	"log"
	"os"

	"forward/inner/app"
)

func main() {
	status := app.Main()
	log.Printf("[INFO] Forward shutdown exiting with status %d", status)
	os.Exit(status)
}
