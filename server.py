import socket
from hmac import hmac_sha1


class Server:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.addr, self.port))
        self.s.listen(1)
        self.conn, self.addr = self.s.accept()
        print("Server running")

    def send(self, msg_bytes: bytes):
        self.conn.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.conn.recv(buffer_size)

        return msg_bytes

    def close(self):
        self.conn.close()


if __name__ == '__main__':
    server = Server('localhost', 9999)

    with open("password.txt", "r") as password_file:
        shared_password = password_file.read().strip()

    with open("Random_number.txt", "r") as random_file:
        random_string = random_file.read().strip()

    try:
        while True:

            # Generate a random number, send it to the client, and display it
            random_number = random_string.encode('utf-8')
            server.send(random_number)
            print("\nSent random number:", random_number.hex())

            msg = input('input random word: ')
            if msg == 'exit':
                break

            server.send(msg.encode('utf-8'))

            # Receive and display the HMAC value from the client
            received_hmac = server.recv(20)
            print("Received HMAC value:", received_hmac.hex())

            # Generate and display the server's own HMAC value for comparison
            server_hmac = hmac_sha1(random_number, shared_password.encode('utf-8'))
            print("Server HMAC value:", server_hmac.hex())

            # Compare the received HMAC value and its own generated HMAC
            if received_hmac == server_hmac:
                print("HMAC Verification: Successful")
            else:
                print("HMAC Verification: Failed")

            print("Shared password:", shared_password)
            print("-----\nAwaiting the next interaction...\n-----")

    except KeyboardInterrupt:
        print("\nServer is shutting down...")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

    finally:
        server.close()
        print("Server has disconnected.")
