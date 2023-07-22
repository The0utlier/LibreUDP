import rsa
import socket

def create_keys():
    (pubkey, privkey) = rsa.newkeys(4096)
    return pubkey, privkey

def get_local_ip():
    # Create a temporary socket to get the local IP address
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        temp_sock.connect(("8.8.8.8", 80))  # Use a public IP as a dummy target
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

# Check if keys already exist
if keys_exist():
    print("Keys already exist. Loading...")
    pubkey, privkey = load_keys_from_files()
else:
    print("Keys do not exist. Generating new keys...")
    pubkey, privkey = create_keys()
    save_keys_to_files(pubkey, privkey)

# Create TCP socket
TCP_IP = get_local_ip()  # Bind to all available network interfaces
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

client_socket.close()
server_socket.close()
