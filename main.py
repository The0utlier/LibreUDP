import socket
import rsa
import threading

public_key = None
private_key = None

def generate_rsa_keys():
    global public_key, private_key
    public_key, private_key = rsa.newkeys(4096)  # Generate 4096-bit RSA keys

def encrypt_message(message, public_key):
    encrypted_message = rsa.encrypt(message.encode(), public_key)
    return encrypted_message

def send_message(message):
    UDP_IP = "127.0.0.1"
    UDP_PORT = 12345

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, (UDP_IP, UDP_PORT))

def receive_message():
    UDP_IP = "127.0.0.1"
    UDP_PORT = 12345

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    print("Listening for messages...")
    try:
        while True:
            data, addr = sock.recvfrom(1024)
            # Check if the received data is the public key
            if public_key is None:
                public_key = rsa.PublicKey.load_pkcs1(data)
                print("Received Public Key from {}".format(addr))
            else:
                decrypt_message(data)
    except socket.error as e:
        print("Error receiving message:", e)

def decrypt_message(data):
    decrypted_message = rsa.decrypt(data, private_key).decode()
    print("\n\nDecrypted Message: {}".format(decrypted_message))

def main():
    global public_key, private_key

    try:
        # Generate RSA keys
        generate_rsa_keys()
        #print("RSA Public Key: {}".format(public_key))
        #print("RSA Private Key: {}".format(private_key))

        # Start the listening thread
        listen_thread = threading.Thread(target=receive_message)
        listen_thread.start()

        # Wait for a short time to ensure the listening thread has started
        threading.Event().wait(0.5)

        # Send public key as the first message
        public_key_bytes = public_key.save_pkcs1()
        send_message(public_key_bytes)

        while True:
            user_choice = input("Do you want to send a message? (yes/no): ").lower()
            if user_choice == "yes":
                message = input("Enter your message: ")
                encrypted_message = encrypt_message(message, public_key)
                #print("Encrypted Message: {}".format(encrypted_message))
                send_message(encrypted_message)
            elif user_choice == "no":
                break
            else:
                print("Invalid choice. Please enter 'yes' or 'no'.")

    except Exception as e:
        print("An error occurred:", e)

if __name__ == "__main__":
    main()
