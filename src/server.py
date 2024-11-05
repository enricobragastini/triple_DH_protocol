import socket
import signal
import sys
from functions import *
from hashlib import sha256


def calculate_shared_secret(local_edh_private, local_ldh_private, remote_edh_public, remote_ldh_public):
    print("Calcolo delle 3 chiavi condivise...")

    sh_k1 = pow(remote_edh_public, local_ldh_private, p)
    sh_k2 = pow(remote_edh_public, local_edh_private, p)
    sh_k3 = pow(remote_ldh_public, local_edh_private, p)

    print(f"sh_k1={sh_k1}, sh_k2={sh_k2}, sh_k3={sh_k3}")

    # combina le chiavi condivise, concatenandole e generando l'hash
    combined_secrets = sh_k1.to_bytes(BYTES, 'big') + sh_k2.to_bytes(BYTES, 'big') + sh_k3.to_bytes(BYTES, 'big')

    shared_secret = sha256(combined_secrets).digest()

    return shared_secret


def signal_handler(sig, frame):
    print("\n\nIntercettato CTRL+C! Chiusura del server...")
    s.close()  # Chiude il socket principale in ascolto
    sys.exit(0)


if __name__ == "__main__":
    # Configura il segnale CTRL+C per chiudere il server
    signal.signal(signal.SIGINT, signal_handler)

    # Inizializzazione dei parametri
    p, g = generate_parameters()
    print(f"Parametri generati: p={p}, g={g}")

    # Generazione della coppia di chiavi long-term
    ldh_private, ldh_public = generate_keys(p, g)

    # Creazione del socket
    PORT = 12345
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', PORT))
    s.listen(1)

    print(f"Server in ascolto su porta {PORT}...")

    while True:
        try:
            # Accettazione della connessione
            conn, addr = s.accept()
            print("\nRicevuta connessione da ", addr)

            # Generazione della coppia di chiavi ephemeral
            edh_private, edh_public = generate_keys(p, g)

            ldh = (ldh_private, ldh_public)
            edh = (edh_private, edh_public)

            # Invio dei parametri e delle chiavi al client
            conn.sendall(p.to_bytes(BYTES, 'big'))
            conn.sendall(g.to_bytes(BYTES, 'big'))
            conn.sendall(ldh_public.to_bytes(BYTES, 'big'))
            conn.sendall(edh_public.to_bytes(BYTES, 'big'))

            # Ricezione delle chiavi da parte del client
            remote_ldh_public = int.from_bytes(conn.recv(BYTES), 'big')
            remote_edh_public = int.from_bytes(conn.recv(BYTES), 'big')

            print(
                f"\nChiavi: \n\tLDH={ldh}\n\tEDH={edh}\n\tRemote LDH={remote_ldh_public}\n\tRemote EDH={remote_edh_public}\n")

            # Calcolo delle chiavi condivise
            shared_secret = calculate_shared_secret(edh_private, ldh_private, remote_edh_public, remote_ldh_public)
            print(f"Chiave condivisa: {shared_secret}")

            # Rimane in ascolto del messaggio cifrato
            data = conn.recv(4096)
            plaintext = decrypt(data, shared_secret).decode()

            print(f"Plaintext: {plaintext}")

        except Exception as e:
            print(f"Errore durante il protocollo: {e}")
            print("Ripristino in ascolto per una nuova connessione...")

        finally:
            conn.close()
            print("\nConnessione chiusa.\nRimango in ascolto per una nuova connessione...\n")
