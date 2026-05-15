package main

import (
	"log"
	"os"

	"forward/base/app"
)

func main() {
	status := app.Main()
	if app.ShouldLogShutdown() {
		log.Printf("[INFO] forward shutdown exiting with status %d", status)
	}
	os.Exit(status)
}
