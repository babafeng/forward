package main

import (
	"log"
	"os"

	"forward/internal/app"
)

func main() {
	status := app.Main()
	log.Printf("[INFO] Forward internal shutdown exiting with status %d", status)
	os.Exit(status)
}
