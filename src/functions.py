import os
import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

DELIMITER = b'###DELIMITER###'
BYTES = 4


def generate_parameters() -> tuple:
    """
    Genera i parametri p e g per il protocollo Diffie Hellman
    :return: p, g
    """

    def is_prime(n) -> bool:
        """
        Test di primalità
        :param n:   Numero da testare
        :return:    True se è primo, False altrimenti
        """
        if n % 2 == 0:
            return False
        for i in range(3, int(n ** 0.5) + 1, 2):
            if n % i == 0:
                return False
        return True

    def generate_prime() -> int:
        """
        Genera un numero primo (di 4 byte).
        :return: Numero primo
        """
        bits = BYTES * 8
        while True:
            p = random.getrandbits(bits)    # Genera un numero casuale di 4 byte
            p |= (1 << bits - 1) | 1        # Imposta il primo e l'ultimo bit a 1 (per essere dispari)
            if is_prime(p):
                return p

    p = generate_prime()        # Numero primo di 8 bit
    g = 2                       # Generatore (sound, not secure)
    return p, g


def generate_keys(p, g):
    """
    Genera le chiavi LDH ed EDH
    """

    # Chiavi private -> interi casuali di 4 byte
    ldh_private = int.from_bytes(random.getrandbits(BYTES * 8).to_bytes(BYTES, 'big'), 'big') % int(p)
    edh_private = int.from_bytes(random.getrandbits(BYTES * 8).to_bytes(BYTES, 'big'), 'big') % int(p)

    # Chiavi pubbliche -> g^private mod p
    ldh_public = pow(g, ldh_private, p)
    edh_public = pow(g, edh_private, p)

    return ldh_private, edh_private, ldh_public, edh_public


def encrypt(plaintext, secret):
    """
    Cifra il plaintext usando AES-GCM
    :param plaintext: plaintext da cifrare
    :param secret: chiave condivisa
    :return: nonce, tag, ciphertext
    """
    nonce = os.urandom(12)
    cipher = Cipher(algorithm=algorithms.AES(secret), mode=modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, encryptor.tag, ciphertext


def decrypt(payload, shared_secret):
    """
    Decifra il ciphertext usando AES-GCM
    :param payload: payload cifrato (nonce, tag, ciphertext)
    :param shared_secret: chiave condivisa
    :return: plaintext
    """
    nonce = payload[:12]        # nonce -> primi 12 bytes
    tag = payload[12:28]        # tag -> 16 bytes
    ciphertext = payload[28:]   # ciphertext

    cipher = Cipher(algorithm=algorithms.AES(shared_secret), mode=modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


if __name__ == "__main__":
    p, g = generate_parameters()
    print(generate_keys(p, g))
