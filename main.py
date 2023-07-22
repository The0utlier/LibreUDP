import socket
import threading

# IP and port for server to bind and communicate with clients
UDP_IP = "0.0.0.0"  # Allow communication with any available network interface
UDP_PORT = 5005

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the specified IP and port to receive messages
sock.bind((UDP_IP, UDP_PORT))

def receive_messages():
    while True:
        # Check if there's any data received
        data, addr = sock.recvfrom(1024)
        if data:
            # Print the received message
            print("Received message from {}: {}".format(addr, data.decode("utf-8")))

# Start the thread to receive messages
receive_thread = threading.Thread(target=receive_messages)
receive_thread.daemon = True
receive_thread.start()

# Main loop to send messages
print("UDP server is running on {}:{}".format(UDP_IP, UDP_PORT))
while True:
    # Get a new message from the user to send
    message = input("Enter a message to send: ").encode("utf-8")

    # Send the message to all connected clients
    sock.sendto(message, (UDP_IP, UDP_PORT))
