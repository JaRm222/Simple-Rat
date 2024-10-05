import socket
import time
# Define server address and port
server_address = ('localhost', 1234)  # Replace with your server address and port
id = ""

def main():
    global id
    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            # Connect to the server
            sock.connect(server_address)
            print(f"Connected to {server_address}")
            while True:
                if id == "":
                    sock.sendall(bytes("connections\0", 'utf-8'))
                    response = sock.recv(4096)
                    connections_list = response.decode('utf-8')

                    if connections_list == "no connections":
                        print("no conn")
                        continue

                    conn_arr = connections_list.split(" ")



                    print("Choose connection")
                    for i in range(len(conn_arr)):
                        if conn_arr[i] == "":
                            continue
                        print("["+str(i)+"] " + conn_arr[i])
                    
                    user_choice = input(">> ")
                    id = conn_arr[int(user_choice)]
                    print("[*] Connected to " + id)

                while True:
                    cmd = input(">> ")
                    
                    sock.sendall(bytes(id+",,,"+cmd+"\0", 'utf-8'))

                    if cmd == "quit":
                        id=""
                        time.sleep(3)
                        break

                    response = sock.recv(4096)
                    print(response.decode('utf-8'))
        
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()