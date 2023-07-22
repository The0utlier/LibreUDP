import socket
import rsa
import threading

def generate_rsa_keys():
    return rsa.newkeys(4096)  # Generate 4096-bit RSA keys

def encrypt_message(message, public_key):
    encrypted_message = rsa.encrypt(message.encode(), public_key)
    return encrypted_message

def decrypt_message(data, private_key):
    try:
        decrypted_message = rsa.decrypt(data, private_key).decode()
        print("\n\nDecrypted Message: {}".format(decrypted_message))
    except rsa.pkcs1.DecryptionError:
        print("\n\nFailed to decrypt the message.")

def send_message(message, destination, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, (destination, port))

def receive_message(port, private_key):
    UDP_IP = "127.0.0.1"  # Listen on all available interfaces

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, port))

    print("Listening for messages...")
    try:
        while True:
            data, addr = sock.recvfrom(1024)
            decrypt_message(data, private_key)
    except socket.error as e:
        print("Error receiving message:", e)

def main():
    try:
        # Generate RSA keys
        _, private_key = generate_rsa_keys()
        public_key = rsa.PublicKey(private_key.n, private_key.e)  # Obtain public key from private key

        # Start the listening thread
        port = 12345  # Use a specific port for communication
        listen_thread = threading.Thread(target=receive_message, args=(port, private_key))
        listen_thread.start()

        # Wait for a short time to ensure the listening thread has started
        threading.Event().wait(0.5)

        # Send public key as the first message
        public_key_bytes = public_key.save_pkcs1()
        destination_ip = input("Enter the IP address of the destination: ")
        send_message(public_key_bytes, destination_ip, port)

        while True:
            user_choice = input("Do you want to send a message? (yes/no): ").lower()
            if user_choice == "yes":
                message = input("Enter your message: ")
                encrypted_message = encrypt_message(message, public_key)
                send_message(encrypted_message, destination_ip, port)
            elif user_choice == "no":
                break
            else:
                print("Invalid choice. Please enter 'yes' or 'no'.")

    except Exception as e:
        print("An error occurred:", e)

if __name__ == "__main__":
    main()
