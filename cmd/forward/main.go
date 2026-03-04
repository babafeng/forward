package main

import (
	"log"
	"os"

	"forward/base/app"
)

func main() {
	status := app.Main()
	log.Printf("[INFO] forward shutdown exiting with status %d", status)
	os.Exit(status)
}
