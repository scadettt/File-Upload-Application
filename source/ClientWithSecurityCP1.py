# Client ask Server for public key
# Server provides server_signed.crt 
# Client verify this signed certificate using public key from cacsertificate.crt


# TASK 2: Design a protocol to protect the confidentiality of the content of the uploaded file 
# using public key cryptography. For simplicity, the filename does not have to be encrypted.

# CP1
# 1. Client encrypts the file data (byte blocks) before sending
# 2. SecureStore decrypts on receive
# 3. Using PKCS1v15 (min 11 bytes of padding, max 117 bytes data blocks) 
# for RSA key size 1024 bits, encrypt/ decrypt 128 bytes of data at a time


import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")

def generate_nonce():
    return secrets.token_bytes(16)

def get_timestamp():
    return int(time.time())


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")

        # Generate nonce and timestamp
        nonce = generate_nonce()
        timestamp = get_timestamp()

        # Upon successful connection
        M2 = nonce + convert_int_to_bytes(timestamp) + b"Client Request SecureStore ID"
        M1 = convert_int_to_bytes(len(M2))

        # Send to server
        s.sendall(convert_int_to_bytes(3)) # MODE=3
        s.sendall(M1)
        s.sendall(M2)

        # Receive signed message
        signed_message_size = convert_bytes_to_int(s.recv(8))
        signed_message_raw = s.recv(signed_message_size)
        signed_server_cert_size = convert_bytes_to_int(s.recv(8))
        signed_server_cert_raw = s.recv(signed_server_cert_size)
        print("Received server certificate raw data:")
        print(signed_server_cert_raw.decode('utf-8'))
        # Debug the size of the received data
        print(f"Size of signed message: {signed_message_size}")
        print(f"Size of signed server cert: {signed_server_cert_size}")



        # CHECK SERVER ID
        # 1. Extract public key, Kca+, from  csertificate.crt
        f = open("source/auth/cacsertificate.crt", "rb")
        ca_cert_raw = f.read()
        ca_cert = x509.load_pem_x509_certificate(
            data=ca_cert_raw, backend=default_backend()
        )

        ca_public_key = ca_cert.public_key()

        # 2. Verify signed cert
        signed_server_cert = x509.load_pem_x509_certificate(
            data=signed_server_cert_raw, backend=default_backend()
        )

        ca_public_key.verify(
            signature=signed_server_cert.signature, # signature bytes to verify
            data=signed_server_cert.tbs_certificate_bytes, # certificate data bytes that was signed by CA
            padding=padding.PKCS1v15(), # padding used by CA bot to sign the server's csr
            algorithm=signed_server_cert.signature_hash_algorithm,
        )

        # 3. Extract public key Ks+ from server cert
        server_public_key = signed_server_cert.public_key()

        # Client confirms server is live by verifying the signed message and the validity of the server's certificate
        # 4. Decrypt signed message via verify method
        try:
            server_public_key.verify(
                signed_message_raw,  #in bytes
                M2,
                padding.PSS(         # padding should match whatever used during encryption
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Live server verified successfully.")

            # 5. Validate server cert
            assert signed_server_cert.not_valid_before <= datetime.utcnow() <= signed_server_cert.not_valid_after
        except InvalidSignature:
            print("Server verification failed. Closing connection...")
            s.sendall(convert_int_to_bytes(2))  # Mode=2
            return


        while True:
            filename = input(
                "Enter a filename to send (enter -1 to exit):"
            ).strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                # concatenate encrypted blocks into a single byte array
                encrypted_data = bytearray()
                block_size = 117 # Max block size for PKCS1v15 with 1024-bit key

                for i in range(0, len(data), block_size):
                    block = data[i:i+block_size]
                    encrypted_block = server_public_key.encrypt(
                        block,
                        padding.PKCS1v15()
                    )
                    encrypted_data.extend(encrypted_block)
                
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(encrypted_data)))
                s.sendall(encrypted_data)

            filenamepart = filename.split("/")[-1]
            filename = "enc_" + filenamepart

            #save encrypted file from client to /send_files_enc before sending it to the server side
            with open(f"send_files_enc/{filename}", mode="wb") as fp:
                fp.write(encrypted_data)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])