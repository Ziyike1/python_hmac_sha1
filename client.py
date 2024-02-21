import socket
from hmac import hmac_sha1


class Client:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.addr, self.port))

    def send(self, msg_bytes: bytes):
        self.s.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.s.recv(self.buffer_size)

        return msg_bytes

    def close(self):
        self.s.close()


if __name__ == '__main__':
    client = Client('localhost', 9999)

    with open("password.txt", "r") as password_file:
        shared_password = password_file.read().strip()

    try:
        while True:
            # Receive the random number from the server
            random_number = client.recv(64)

            print("\nReceived random number:", random_number.hex())

            received_word = client.recv(1024).decode('utf-8')
            if received_word.lower() == 'exit':
                break
            print("Received random word:", received_word)

            # Generate HMAC value and send to the server
            hmac_value = hmac_sha1(random_number, shared_password.encode('utf-8'))
            client.send(hmac_value)

            print("Shared password:", shared_password)
            print("Sent HMAC value:", hmac_value.hex())
            print("-----\nAwaiting the next random number from server...\n-----")

    except KeyboardInterrupt:
        print("\nClient is terminating.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        client.close()
