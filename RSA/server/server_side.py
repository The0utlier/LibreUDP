
import rsa
import socket
import os
import threading


def generate_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

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

def load_other_pubkey(pubkey_filename):
    with open(pubkey_filename, "rb") as pub_file:
        pub_data = pub_file.read()
        other_pubkey = rsa.PublicKey.load_pkcs1(pub_data)
    return other_pubkey

def load_privkey(privkey_filename):
    with open(privkey_filename, "rb") as priv_file:
        priv_data = priv_file.read()
        privkey = rsa.PrivateKey.load_pkcs1(priv_data)
    return privkey

def encrypt_message(pubkey, message):
    encrypted_message = rsa.encrypt(message.encode(), pubkey)
    return encrypted_message

def decrypt_message(privkey, encrypted_message):
    decrypted_message = rsa.decrypt(encrypted_message, privkey)
    return decrypted_message.decode()

def receive_messages(sock, privkey, other_pubkey, client_address):
    try:
        while True:
            data, addr = sock.recvfrom(1024)
            decrypted_message = decrypt_message(privkey, data)
            #print("\nReceived Message from Client {}: {}\n".format(client_address, decrypted_message))
            print("Anon: {}".format(decrypted_message))
    except KeyboardInterrupt:
        print("\nServer stopped.")

def main():

    # Load own keys
    privkey = load_privkey("private_key.pem")

    # Load other party's public key
    other_pubkey = load_other_pubkey("other_pub_key.pem")

    UDP_IP = get_local_ip()  # Listen on localhost only
    UDP_PORT = 12345

    # Create a UDP socket
    server_socket = generate_socket()
    server_socket.bind((UDP_IP, UDP_PORT))

    print("Waiting for a client to connect...")

    client_address = None
    while client_address is None:
        data, addr = server_socket.recvfrom(1024)
        client_address = addr

    print("Client connected:", client_address)

    # Start the listening thread
    listen_thread = threading.Thread(target=receive_messages, args=(server_socket, privkey, other_pubkey, client_address))
    listen_thread.start()

    # Main thread continues to send messages to the client
    print("Type your message and press Enter. Type 'exit' to quit.")
    while True:
        message = input("")
        if message.lower() == "exit":
            break

        encrypted_message = encrypt_message(other_pubkey, message)
        server_socket.sendto(encrypted_message, client_address)

    # Clean up and close the socket
    server_socket.close()

if __name__ == "__main__":
    main()
