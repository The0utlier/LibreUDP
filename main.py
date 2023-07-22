import socket
import threading
import time

def generate_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def receive_messages(port):
    UDP_IP = "127.0.0.1"  # Listen on all available interfaces

    sock = generate_socket()
    sock.bind((UDP_IP, port))

    print("Listening for messages...")
    try:
        while True:
            data, addr = sock.recvfrom(1024)
            print("\nReceived Message: {}".format(data.decode()))
    except KeyboardInterrupt:
        print("\nReceiver stopped.")

def send_message(message, destination_ip, port):
    sock = generate_socket()
    sock.sendto(message.encode(), (destination_ip, port))
    sock.close()

def main():
    destination_ip = input("Enter the IP address of the receiver: ")
    port = 12345  # Use a specific port for communication

    # Start the listening thread
    listen_thread = threading.Thread(target=receive_messages, args=(port,))
    listen_thread.start()

    print("Type your message and press Enter. Type 'exit' to quit.")
    while True:
        message = input("Message: ")
        if message.lower() == "exit":
            break

        send_message(message, destination_ip, port)
        time.sleep(1)  # Wait for 1 second before prompting for the next message

if __name__ == "__main__":
    main()
