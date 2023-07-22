## LibreUDP

**The project is a secure messaging application implemented using Python, where two parties can exchange encrypted messages over UDP. The application generates RSA key pairs for each party and saves them in separate files. When one party acts as the server, it waits for a client to connect, exchanges public keys, and saves the client's public key. The client, on the other hand, connects to the server, exchanges public keys, and saves the server's public key. Both parties use each other's public keys to encrypt messages before sending them over the network. The application ensures secure communication, as only the intended recipient possessing the private key can decrypt and read the messages. The project leverages the RSA encryption algorithm to provide confidentiality and data integrity during the message exchange, making it suitable for secure communication in a distributed environment.**


*It runs on port 12345, and uses 4096 bit keys for encryption.*

Help me by donating XMR. 
4AssSsdVqe93BrCBw2Z11JFepkN8pJCuCc11ZVxWwaSPLBMu9HLpHTmXoNXDSiQnWsPjmPpvwNJLWWYNkLTkXbDwCZJZqVq
