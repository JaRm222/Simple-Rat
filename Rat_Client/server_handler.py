import socket

class SocketClient:
    def __init__(self):
        self.sck = None

    def connect_to_server(self, server_addr):
        try:
            ip, port = server_addr.split(":")
            port = int(port)
        except ValueError:
            print("Invalid format. Please specify ip:port")
            return False

        server = (ip, port)

        try:
            self.sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sck.connect(server)
            return True
        except socket.error as e:
            print(f"Connection error: {e}")
            return False
        
    def get_connections(self):
        if self.sck == None:
            return False
        
        self.sck.sendall(bytes(b"connections\0"))
        response = self.sck.recv(4096)
        connections_list = response.decode('utf-8')

        if connections_list == "no connections":
            return "No Connections"

        return connections_list.split(" ")
    
    def send_command(self, connection, cmd):
        print(connection)
        self.sck.sendall(bytes(connection+",,,"+cmd+"\0", 'utf-8'))
        response = self.sck.recv(4096)
        return response.decode('utf-8')
