package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/gorilla/websocket"
)

func main() {
	// Define the WebSocket server URL
	serverURL := "ws://localhost:8080/ws"

	// Connect to the server
	log.Println("Connecting to", serverURL)
	conn, _, err := websocket.DefaultDialer.Dial(serverURL, nil)
	if err != nil {
		log.Fatal("Dial error:", err)
	}
	defer conn.Close()

	// Channel to handle interrupts (Ctrl+C)
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	messages := make(chan string)
	go func() {
		for {
			_, echoedMessage, err := conn.ReadMessage()
			if err != nil {
				log.Println("Read error:", err)
				close(messages)
				return
			}
			messages <- string(echoedMessage)
		}
	}()

	// Wait for interrupt to gracefully shutdown
	for {
		select {
		case <-interrupt:
			log.Println("Interrupt received, shutting down...")
			closeConnection(conn)
			return
		case message, ok := <-messages:
			if !ok {
				closeConnection(conn)
				return
			}
			log.Println("Received message:", message)
		}
	}
}

func closeConnection(conn *websocket.Conn) {
	err := conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		log.Println("Close error:", err)
		return
	}
	time.Sleep(time.Second)
}

func getAndVerifyQuote() {
	// Open TPM device
	rwc, err := tpm2.OpenTPM()
	if err != nil {
		log.Printf("Failed to open TPM device: %v", err)
		return
	}
	defer rwc.Close()
	handle, rsaKey, err := getExistingLuksData("disk.disk", rwc)
	if err != nil {
		log.Println("Creating TPM key")
		handle, rsaKey, err = createKey(rwc)
		if err != nil {
			log.Printf("Failed to create TPM key: %v", err)
			return
		}
		writeLuksData(rwc, handle, rsaKey, "disk.disk")
	}
	defer func() {
		if err := tpm2.FlushContext(rwc, *handle); err != nil {
			panic(err)
		}
	}()
	// Define PCR selection
	pcrs := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{23},
	}

	// Obtain nonce (should be the same nonce used in generateQuote)
	nonce := make([]byte, 20)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Printf("Failed to generate nonce: %v", err)
		return
	}

	// Generate quote
	quote, signature, err := generateQuote(rwc, handle, nonce, pcrs)
	if err != nil {
		log.Printf("Failed to generate quote: %v", err)
	}

	// Verify quote
	err = verifyQuote(rsaKey, quote, signature, pcrs, nonce)
	if err != nil {
		log.Printf("Failed to verify quote: %v", err)
		return
	}
	fmt.Println("Quote verified successfully")
}
