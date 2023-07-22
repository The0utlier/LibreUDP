import socket
import threading
import time
import rsa

def create_keys():
    (pubkey, privkey) = rsa.newkeys(4096)
    return pubkey, privkey

def encrypt_message(pubkey, message):
    encrypted_message = rsa.encrypt(message.encode('utf-8'), pubkey)
    return encrypted_message

def decrypt_message(privkey, encrypted_message):
    plain = rsa.decrypt(encrypted_message, privkey)
    return plain

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

def receive_messages(port, pubkey, received_flag, privkey):
    UDP_IP = get_local_ip()  # Listen on localhost only

    sock = generate_socket()
    sock.bind((UDP_IP, port))

    try:
        while not received_flag[0]:
            data, addr = sock.recvfrom(1024)
            if data.startswith(b"-----BEGIN RSA PUBLIC KEY-----"):
                # Received a public key from the other party
                other_public_key = rsa.PublicKey.load_pkcs1(data)
                print("\nReceived Public Key from the other party: {}".format(other_public_key))
                # Send our public key in response
                send_message(pubkey.save_pkcs1(), addr[0], port)
                received_flag[0] = True
    except KeyboardInterrupt:
        print("\nReceiver stopped.")

    while True:
        data, addr = sock.recvfrom(1024)
        decrypted_message = decrypt_message(privkey, data)
        print("\nReceived Message: {}\n".format(decrypted_message.decode()))


def send_message(message, destination_ip, port):
    sock = generate_socket()
    sock.sendto(message, (destination_ip, port))
    sock.close()

def main():
    destination_ip = input("Enter the IP address of the receiver (127.0.0.1 for localhost): ")
    port = 12345  # Use a specific port for communication

    # Start the listening thread
    pubkey, privkey = create_keys()
    received_flag = [False]  # Flag to indicate whether the public key has been received
    listen_thread = threading.Thread(target=receive_messages, args=(port, pubkey, received_flag, privkey))
    listen_thread.start()

    # Continuously send the public key until it receives an acknowledgement
    while not received_flag[0]:
        try:
            send_message(pubkey.save_pkcs1(), destination_ip, port)
            print("Sent Public Key to the receiver.")
            time.sleep(1)  # Wait for 1 second before retrying
        except Exception as e:
            print("Error sending the public key:", e)

    # Start sending and receiving encrypted messages
    print("Type your message and press Enter. Type 'exit' to quit.")
    while True:
        message = input("Message: ")
        if message.lower() == "exit":
            break

        encrypted_message = encrypt_message(pubkey, message)
        send_message(encrypted_message, destination_ip, port)
        time.sleep(1)  # Wait for 1 second before prompting for the next message

if __name__ == "__main__":
    main()
