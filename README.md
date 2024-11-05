# Triple Diffie-Hellman (3-DH) Protocol Simulation

This project is part of the practical coursework for the **Network Security course** in the Master’s program in
**Engineering and Computer Science** at the **University of Verona**.

This project simulates communication between a Python Client and Server that use the **Triple Diffie-Hellman (3-DH)**
protocol to securely establish a shared key.

### How the Protocol works

The 3-DH Protocol implementation works as follows:

1. **Each Party Generates Key Pairs**:
    - Both the client and server generate a long-term and an ephemeral key pair.
2. **Exchange of Public Keys**:
    - The client and server exchange their long-term and ephemeral _public_ keys.
3. **Calculation of Shared Secrets**:
    - Using the exchanged public keys and their own private keys, both the client and server compute three shared
      secrets
4. **Derivation of the Final Shared Key**:
    - The three shared secrets are concatenated and hashed to generate the final shared key.

## Project Structure

- **server.py**: Python script that acts as the server. It generates the necessary parameters for the DH protocol and
  listens for incoming connections. Once a connection is established, it sends the parameters to the client. The two
  then establish a shared key using the Triple Diffie-Hellman protocol.
- **client.py**: Python script that acts as the client. It connects to the server, receives the parameters, and
  establishes a shared key using the Triple Diffie-Hellman protocol.
- **functions.py** (optional): Python module with auxiliary functions for key generation, encryption, and decryption.

## Running the Project

1. Open two terminals in the `src` directory.
2. Run the server with the command: `python3 server.py`. The server will generate the necessary parameters for the
   Triple Diffie-Hellman protocol and start listening for incoming connections on port `12345`.
3. Run the client with the command: `python3 client.py`. The client will connect to the server, receive the generated
   parameters, and calculate the shared secret.
4. The client will send an encrypted message to the server, which will decrypt and display it.

## Requirements

- `pycryptodome` library for encryption.

## Note on Security

This implementation is intended for educational purposes and to demonstrate how the Triple Diffie-Hellman protocol
works. _**It is not intended for production use**_. For secure communication, it is
recommended to use established cryptographic libraries and protocols.