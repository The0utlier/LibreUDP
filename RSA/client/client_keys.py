import rsa
import socket
import os

def create_keys():
    (pubkey, privkey) = rsa.newkeys(4096)
    return pubkey, privkey

def save_keys_to_files(pubkey, privkey):
    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(pubkey.save_pkcs1())

    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(privkey.save_pkcs1())

def load_keys_from_files():
    with open("public_key.pem", "rb") as pub_file:
        pub_data = pub_file.read()
        pubkey = rsa.PublicKey.load_pkcs1(pub_data)

    with open("private_key.pem", "rb") as priv_file:
        priv_data = priv_file.read()
        privkey = rsa.PrivateKey.load_pkcs1(priv_data)

    return pubkey, privkey

def keys_exist():
    return all(os.path.exists(filename) for filename in ["public_key.pem", "private_key.pem"])

def generate_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def send_pubkey(sock, pubkey, server_address):
    pubkey_bytes = pubkey.save_pkcs1()
    sock.send(pubkey_bytes)

def receive_pubkey_and_save(sock, pubkey_filename):
    data = sock.recv(4096)
    with open(pubkey_filename, "wb") as pub_file:
        pub_file.write(data)
    print("Received and saved the server's public key.")
    sock.close()

def main():
    if keys_exist():
        print("Keys already exist. Loading...")
        pubkey, privkey = load_keys_from_files()
    else:
        print("Keys do not exist. Generating new keys...")
        pubkey, privkey = create_keys()
        save_keys_to_files(pubkey, privkey)

    destination_ip = input("Enter the IP address of the server (127.0.0.1 for localhost): ")
    port = 12345  # Use the same port for communication as the server

    # Create a TCP socket and connect to the server
    client_socket = generate_socket()
    client_socket.connect((destination_ip, port))

    # Send your public key to the server
    send_pubkey(client_socket, pubkey, (destination_ip, port))

    # Receive the server's public key and save it
    receive_pubkey_and_save(client_socket, "other_pub_key.pem")

    client_socket.close()

if __name__ == "__main__":
    main()
