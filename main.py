import socket
import threading
import time
import rsa

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

def generate_rsa_keys():
    return rsa.newkeys(2048)  # Generate 4096-bit RSA keys

def encrypt_message(message, public_key):
    encrypted_message = rsa.encrypt(message.encode(), public_key)
    return encrypted_message

def decrypt_message(data, private_key):
    try:
        decrypted_message = rsa.decrypt(data, private_key).decode()
        print("\nDecrypted Message: {}".format(decrypted_message))
    except rsa.pkcs1.DecryptionError:
        print("\nFailed to decrypt the message.")

def receive_messages(port, local_ip, private_key):
    UDP_IP = local_ip

    sock = generate_socket()
    sock.bind((UDP_IP, port))

    print("Listening for messages on {}:{}".format(UDP_IP, port))
    try:
        public_key_received = False
        while not public_key_received:
            data, addr = sock.recvfrom(4096)  # Increase buffer size to accommodate larger data
            public_key = rsa.PublicKey.load_pkcs1(data)
            print("\nReceived Public Key: {}".format(public_key))
            public_key_received = True
            sock.sendto("OK".encode(), addr)  # Send acknowledgment to sender

        while True:
            data, addr = sock.recvfrom(4096)  # Increase buffer size to accommodate larger data
            decrypt_message(data, private_key)
    except KeyboardInterrupt:
        print("\nReceiver stopped.")

def send_message(message, destination_ip, port):
    sock = generate_socket()
    sock.sendto(message.encode(), (destination_ip, port))
    sock.close()

def main():
    destination_ip = input("Enter the IP address of the receiver: ")
    port = 12345  # Use a specific port for communication

    local_ip = get_local_ip()
    _, private_key = generate_rsa_keys()
    public_key = rsa.PublicKey(private_key.n, private_key.e)

    # Start the listening thread
    listen_thread = threading.Thread(target=receive_messages, args=(port, local_ip, private_key))
    listen_thread.start()

    # Send public key repeatedly until receiving "OK" acknowledgment
    sock = generate_socket()
    public_key_bytes = public_key.save_pkcs1()
    while True:
        sock.sendto(public_key_bytes, (destination_ip, port))
        data, addr = sock.recvfrom(1024)
        if data.decode() == "OK":
            break
        time.sleep(1)

    # Start sending encrypted messages
    print("Type your message and press Enter. Type 'exit' to quit.")
    while True:
        message = input("Message: ")
        if message.lower() == "exit":
            break

        encrypted_message = encrypt_message(message, public_key)
        send_message(encrypted_message, destination_ip, port)
        time.sleep(1)  # Wait for 1 second before prompting for the next message

if __name__ == "__main__":
    main()
