import socket
import threading
import time


def get_local_ip():
    # Create a temporary socket to get the local IP address
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        temp_sock.connect(("192.168.1.1", 80))  # Use a public IP as a dummy target
        local_ip = temp_sock.getsockname()[0]
    except socket.error:
        local_ip = "127.0.0.1"  # Use localhost as a fallback if getting the local IP fails
    finally:
        temp_sock.close()
    return local_ip

def generate_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def receive_messages(port):
    UDP_IP = get_local_ip()  # Listen on localhost only

    sock = generate_socket()
    sock.bind((UDP_IP, port))

    #print("Listening for messages...")
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
    destination_ip = input("Enter the IP address of the receiver (127.0.0.1 for localhost): ")
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
