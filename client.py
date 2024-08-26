import socket
import ssl

def communicate_with_server(server_host, server_port):
    # Создание контекста SSL для клиента
    ssl_context = ssl.create_default_context()

    with socket.create_connection((server_host, server_port)) as client_socket:
        # Обертка сокета клиента в SSL сокет
        ssl_socket = ssl_context.wrap_socket(client_socket, server_hostname=server_host)

        # Отправка данных серверу
        ssl_socket.sendall(b"Hello from client!")

        # Чтение ответа от сервера
        received_data = b''
        while True:
            data = ssl_socket.recv(4096)
            if not data:
                break
            received_data += data
        
        print(f"Received from server: {received_data.decode('utf-8')}")

if __name__ == "__main__":
    server_host = input("Enter server IP address: ")
    server_port = int(input("Enter server port number: "))
    communicate_with_server(server_host, server_port)
