package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/lavalleeale/watchfulbutler/lib"
)

// Define the upgrader with default options
var upgrader = websocket.Upgrader{}

func main() {
	router := gin.Default()

	// WebSocket endpoint
	router.GET("/ws", handleWebSocket)

	// Start the server on port 8080
	log.Println("WebSocket server is running on ws://localhost:8080/ws")
	if err := router.Run(":8080"); err != nil {
		log.Fatal("Failed to run server: ", err)
	}
}

func handleWebSocket(c *gin.Context) {
	// Upgrade the HTTP connection to a WebSocket connection
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer conn.Close()

	log.Println("Client connected")

	conn.WriteJSON(lib.HandshakeMessage)

	log.Println("Client disconnected")
}
