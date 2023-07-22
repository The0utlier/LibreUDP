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
    return rsa.newkeys(4096)  # Generate 4096-bit RSA keys

def save_public_key(public_key, file_path):
    with open(file_path, "wb") as f:
        f.write(public_key.save_pkcs1())

def load_public_key(file_path):
    with open(file_path, "rb") as f:
        return rsa.PublicKey.load_pkcs1(f.read())

def encrypt_message(message, public_key):
    encrypted_message = rsa.encrypt(message.encode(), public_key)
    return encrypted_message

def decrypt_message(data, private_key):
    try:
        decrypted_message = rsa.decrypt(data, private_key).decode()
        print("\nDecrypted Message: {}".format(decrypted_message))
    except rsa.pkcs1.DecryptionError:
        print("\nFailed to decrypt the message.")

def send_message(message, destination_ip, port):
    sock = generate_socket()
    sock.sendto(message, (destination_ip, port))
    sock.close()

def main():
    destination_ip = input("Enter the IP address of the other party: ")
    port = 12345  # Use a specific port for communication

    local_ip = get_local_ip()
    _, private_key = generate_rsa_keys()
    public_key = rsa.PublicKey(private_key.n, private_key.e)

    # Start the listening thread
    listen_thread = threading.Thread(target=receive_messages, args=(port, local_ip, public_key))
    listen_thread.start()

    # Perform the handshake to exchange public keys
    handshake_successful = False
    sock = generate_socket()
    public_key_bytes = public_key.save_pkcs1()

    while not handshake_successful:
        # Send the public key
        send_message(public_key_bytes, destination_ip, port)

        # Receive the other party's public key
        data, addr = sock.recvfrom(4096)
        other_public_key = rsa.PublicKey.load_pkcs1(data)
        print("\nReceived Public Key from the other party: {}".format(other_public_key))
        sock.sendto(public_key_bytes, addr)

        # Verify that the handshake was successful
        data, addr = sock.recvfrom(1024)
        if data == b"OK":
            handshake_successful = True
            print("\nHandshake successful. Starting encrypted communication.")
        time.sleep(1)

    # Save the received public key
    save_public_key(other_public_key, "other_public_key.pem")

    # Start sending and receiving encrypted messages
    print("Type your message and press Enter. Type 'exit' to quit.")
    while True:
        message = input("Message: ")
        if message.lower() == "exit":
            break

        encrypted_message = encrypt_message(message, other_public_key)
        send_message(encrypted_message, destination_ip, port)
        time.sleep(1)  # Wait for 1 second before prompting for the next message

def receive_messages(port, local_ip, public_key):
    UDP_IP = local_ip

    sock = generate_socket()
    sock.bind((UDP_IP, port))

    print("Listening for messages on {}:{}".format(UDP_IP, port))
    try:
        data, addr = sock.recvfrom(4096)  # Increase buffer size to accommodate larger data
        other_public_key = rsa.PublicKey.load_pkcs1(data)
        print("\nReceived Public Key from the other party: {}".format(other_public_key))
        sock.sendto(data, addr)  # Send acknowledgment to sender

        while True:
            data, addr = sock.recvfrom(4096)  # Increase buffer size to accommodate larger data
            decrypt_message(data, public_key)
    except KeyboardInterrupt:
        print("\nReceiver stopped.")

if __name__ == "__main__":
    main()
