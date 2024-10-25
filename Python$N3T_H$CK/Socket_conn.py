import socket

HOST = '172.19.208.1'
PORT = 8080

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))

server_socket.listen(1)

while True:
    client_socket, client_address = server_socket.accept()
    print(f'Connection from {client_address[0]}:{client_address[1]}')

    request = client_socket.recv(1024).decode('utf-8')
    print(f'Received Request: {request}\n')

     # Your logic to process the request goes here

    response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nHello, World!"
    client_socket.sendall(response.encode('utf-8'))

    client_socket.close()
    
   # server_socket.close()
