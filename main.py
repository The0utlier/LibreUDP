import rsa
import socket

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
    return os.path.exists("public_key.pem") and os.path.exists("private_key.pem")

# Check if keys already exist
if keys_exist():
    print("Keys already exist. Loading...")
    pubkey, privkey = load_keys_from_files()
else:
    print("Keys do not exist. Generating new keys...")
    pubkey, privkey = create_keys()
    save_keys_to_files(pubkey, privkey)

# Create TCP socket
TCP_IP = "127.0.0.1"
TCP_PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((TCP_IP, TCP_PORT))
server_socket.listen(1)

print("Waiting for a client to connect...")

client_socket, client_address = server_socket.accept()
print("Client connected. IP address:", client_address[0])

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

client_socket.close()
server_socket.close()
