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

def receive_messages(port, privkey):
    UDP_IP = get_local_ip()  # Listen on localhost only

    sock = generate_socket()
    sock.bind((UDP_IP, port))

    try:
        while True:
            data, addr = sock.recvfrom(1024)
            decrypted_message = decrypt_message(privkey, data)
            print("\nReceived Message: {}\n".format(decrypted_message.decode()))
    except KeyboardInterrupt:
        print("\nReceiver stopped.")

def send_message(message, destination_ip, port):
    sock = generate_socket()
    sock.sendto(message, (destination_ip, port))
    sock.close()

def main():
    destination_ip = input("Enter the IP address of the receiver (127.0.0.1 for localhost): ")
    port = 12345  # Use a specific port for communication

    # Start the listening thread
    pubkey, privkey = create_keys()
    listen_thread = threading.Thread(target=receive_messages, args=(port, privkey))
    listen_thread.start()

    # Send the public key until it is received
    while True:
        try:
            send_message(pubkey.save_pkcs1(), destination_ip, port)
            print("Sent Public Key to the receiver.")
            time.sleep(1)  # Wait for 1 second before retrying
            # Check if the receiver has sent its public key
            sock = generate_socket()
            sock.bind(("127.0.0.1", port))
            data, addr = sock.recvfrom(4096)
            other_public_key = rsa.PublicKey.load_pkcs1(data)
            print("\nReceived Public Key from the other party: {}".format(other_public_key))
            sock.close()
            break  # Exit the loop if the other public key is received
        except Exception as e:
            print("Error sending/receiving the public key:", e)

    # Start sending and receiving encrypted messages
    print("Type your message and press Enter. Type 'exit' to quit.")
    while True:
        message = input("Message: ")
        if message.lower() == "exit":
            break

        encrypted_message = encrypt_message(other_public_key, message)
        send_message(encrypted_message, destination_ip, port)
        time.sleep(1)  # Wait for 1 second before prompting for the next message

if __name__ == "__main__":
    main()
