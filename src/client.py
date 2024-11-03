import socket

from functions import *
from hashlib import sha256


def calculate_shared_secret(local_edh_private, local_ldh_private, remote_edh_public, remote_ldh_public):
    print("Calcolo delle 3 chiavi condivise...")

    sh_k1 = pow(remote_ldh_public, local_edh_private, p)
    sh_k2 = pow(remote_edh_public, local_edh_private, p)
    sh_k3 = pow(remote_edh_public, local_ldh_private, p)

    print(f"sh_k1={sh_k1}, sh_k2={sh_k2}, sh_k3={sh_k3}")

    # combina le chiavi condivise, concatenandole e generando l'hash
    combined_secrets = sh_k1.to_bytes(BYTES, 'big') + sh_k2.to_bytes(BYTES, 'big') + sh_k3.to_bytes(BYTES, 'big')

    shared_secret = sha256(combined_secrets).digest()

    return shared_secret


if __name__ == "__main__":
    # Creazione del socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 12345))

    # Ricezione dei parametri e delle chiavi dal server
    p = int.from_bytes(s.recv(BYTES), 'big')
    g = int.from_bytes(s.recv(BYTES), 'big')
    remote_ldh_public = int.from_bytes(s.recv(BYTES), 'big')
    remote_edh_public = int.from_bytes(s.recv(BYTES), 'big')
    print(f"Parametri ricevuti: p={p}, g={g}")
    print(f"Chiavi ricevute: LDH={remote_ldh_public}, EDH={remote_edh_public}")

    # Generazione delle chiavi
    ldh_private, edh_private, ldh_public, edh_public = generate_keys(p, g)
    ldh = (ldh_private, ldh_public)
    edh = (edh_private, edh_public)
    print(f"Chiavi generate: LDH={ldh}, EDH={edh}")

    # Invio delle chiavi
    s.sendall(ldh_public.to_bytes(BYTES, 'big'))
    s.sendall(edh_public.to_bytes(BYTES, 'big'))

    # Calcolo delle chiavi condivise
    shared_secret = calculate_shared_secret(edh_private, ldh_private, remote_edh_public, remote_ldh_public)
    print(f"Chiave condivisa: {shared_secret}")

    # Invio di un messaggio cifrato con AES-GCM
    plaintext = b"Hello World! This is a encrypted message from Client to Server!"
    nonce, tag, ciphertext = encrypt(plaintext, shared_secret)
    s.sendall(nonce + tag + ciphertext)

    # Chiusura del socket
    s.close()