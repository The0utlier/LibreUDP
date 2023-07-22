import rsa
import socket
import threading
import os

def generate_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

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

def receive_messages(sock, privkey, other_pubkey, server_address):
    try:
        while True:
            data, addr = sock.recvfrom(1024)
            decrypted_message = decrypt_message(privkey, data)
            #print("\nReceived Message from Server {}: {}\n".format(server_address, decrypted_message))
            print("Anon: {}".format(decrypted_message))
    except KeyboardInterrupt:
        print("\nClient stopped.")

def main():
    # Load own keys
    
    privkey = load_privkey("private_key.pem")
    # Load other party's public key
    other_pubkey = load_other_pubkey("other_pub_key.pem")

    UDP_IP = input("What is the address of the server? ") # Connect to localhost
    UDP_PORT = 12345

    # Create a UDP socket
    client_socket = generate_socket()

    # Send a connection request to the server
    client_socket.sendto(b"Connect", (UDP_IP, UDP_PORT))

    # Start the listening thread
    listen_thread = threading.Thread(target=receive_messages, args=(client_socket, privkey, other_pubkey, (UDP_IP, UDP_PORT)))
    listen_thread.start()

    # Main thread continues to send messages to the server
    print("Type your message and press Enter. Type 'exit' to quit.")
    while True:
        message = input("")
        if message.lower() == "exit":
            break

        encrypted_message = encrypt_message(other_pubkey, message)
        client_socket.sendto(encrypted_message, (UDP_IP, UDP_PORT))

    # Clean up and close the socket
    client_socket.close()

if __name__ == "__main__":
    main()
