import rsa
import socket
import threading
import os

def create_keys():
    (pubkey, privkey) = rsa.newkeys(4096)
    return pubkey, privkey

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
    return os.path.exists("public_key.pem") and os.path.exists("private_key.pem")

def receive_messages(port, privkey):
    UDP_IP = get_local_ip()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, port))

    try:
        while True:  # Keep receiving messages indefinitely
            data, addr = sock.recvfrom(4096)
            decrypted_message = rsa.decrypt(data, privkey)
            print("\nReceived Message: {}\n".format(decrypted_message.decode()))
    except KeyboardInterrupt:
        print("\nReceiver stopped.")

# Check if keys already exist
if keys_exist():
    print("Keys already exist. Loading...")
    pubkey, privkey = load_keys_from_files()
else:
    print("Keys do not exist. Generating new keys...")
    pubkey, privkey = create_keys()
    save_keys_to_files(pubkey, privkey)

print("Public Key:", pubkey)
print("Private Key:", privkey)

# Create a new thread for receiving messages
port = 12345  # Use a specific port for communication
listen_thread = threading.Thread(target=receive_messages, args=(port, privkey))
listen_thread.start()

# Create TCP socket
TCP_IP = "127.0.0.1"
TCP_PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((TCP_IP, TCP_PORT))
server_socket.listen(1)

print("Waiting for a client to connect...")

client_socket, client_address = server_socket.accept()
print("Client connected:", client_address)

# Send the public key to the client
pubkey_bytes = pubkey.save_pkcs1()
client_socket.send(pubkey_bytes)

# Receive the other party's public key
data = client_socket.recv(4096)
other_pubkey = rsa.PublicKey.load_pkcs1(data)

print("Received Public Key from the client:", other_pubkey)

# Save the other party's public key
with open("other_pub_key.pem", "wb") as other_pub_file:
    other_pub_file.write(data)

# Start sending and receiving encrypted messages
print("Type your message and press Enter. Type 'exit' to quit.")
while True:
    data = client_socket.recv(4096)
    decrypted_message = rsa.decrypt(data, privkey)
    print("Received Message:", decrypted_message.decode())
    message = input("Message: ")
    if message.lower() == "exit":
        break

    encrypted_message = rsa.encrypt(message.encode('utf-8'), other_pubkey)
    client_socket.send(encrypted_message)

client_socket.close()
server_socket.close()


def receive_messages(server_port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((get_local_ip(), server_port))

    while True:
        data, addr = server_socket.recvfrom(1024)
        print("Client:", data.decode())

def main():
    server_port = 12345

    # Start the thread to receive messages
    receive_thread = threading.Thread(target=receive_messages, args=(server_port,))
    receive_thread.start()

    while True:
        response = input("Response: ")
        if response.lower() == "exit":
            break
