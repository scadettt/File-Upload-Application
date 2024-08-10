# Client ask Server for public key
# Server provides server_signed.crt 
# Client verify this signed certificate using public key from cacsertificate.crt


# TASK 3: Design a protocol to protect the confidentiality of the content of the uploaded file using symmetric key cryptography.

# CP1
# 1. Client encrypts the file data (byte blocks) before sending
# 2. SecureStore decrypts on receive
# 3. Using PKCS1v15 (min 11 bytes of padding, max 117 bytes data blocks) 
# for RSA key size 1024 bits, encrypt/ decrypt 128 bytes of data at a time


import pathlib
import socket
import sys
import time
import zlib
import hashlib

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


def fernetkey_generation():
    session_key_bytes = Fernet.generate_key() # generates 128-bit symmetric key as bytes
    session_key = Fernet(session_key_bytes) # instantiate a Fernet instance with key
    return session_key, session_key_bytes

def fernetKey_handshake(key_bytes, s):
    try:
        with open("source/auth/server_private_key.pem", mode="r", encoding="utf8") as key_file:
            private_key = serialization.load_pem_private_key(bytes(key_file.read(), encoding="utf8"), password=None)
            public_key = private_key.public_key()
    except Exception as e: print(e)

    #prepare data to send
    m2 = public_key.encrypt(key_bytes,padding.PKCS1v15())
    m1 = convert_int_to_bytes(len(m2))

    #send data to server side for handshake
    s.sendall(convert_int_to_bytes(4))
    s.sendall(m1)
    s.sendall(m2)

def calculate_file_hash(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

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

        """----------------------------------COFIDENTIALITY PROTOCOL 2---------------------------------------------------"""
        #generate session keys
        sessionkey, sessionkey_bytes = fernetkey_generation()

        #perform handshake
        fernetKey_handshake(sessionkey_bytes, s)

        while True:
            filename = input(
                "Enter a filename to send (enter -1 to exit):"
            ).strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename.\nPlease try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            # Calculate file hash
            # file_hash = calculate_file_hash(filename)
            
            """------------------------MODIFIED MODE 1----------------------------------------------------"""
            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename to server
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)            

            # Send the file to server side, after compression and encrypting it with session key
            with open(filename, mode="rb") as fp:
                data = fp.read()
                compressed_data = zlib.compress(data)
                encrypted_data = sessionkey.encrypt(compressed_data)
                # encrypted_data = sessionkey.encrypt(data)
            
            filenamepart = filename.split("/")[-1]
            filename = "enc_" + filenamepart

            #save encrypted file from client to /send_files_enc before sending it to the server side
            with open(f"send_files_enc/{filename}", mode="wb") as fp:
                fp.write(encrypted_data)

            # # Send file hash
            # file_hash_bytes = bytes(file_hash, encoding='utf8')
            # s.sendall(convert_int_to_bytes(len(file_hash_bytes)))
            # s.sendall(file_hash_bytes)

            # send encrypted data in chunks, but only require sending mode 1 once
            s.sendall(convert_int_to_bytes(1))
            s.sendall(convert_int_to_bytes(len(encrypted_data)))
            # s.sendall(encrypted_data)
            chunk_size = 1024
            num_chunks = len(encrypted_data) // chunk_size + (1 if len(encrypted_data) % chunk_size != 0 else 0)
            for i in range(num_chunks):
                chunk = encrypted_data[i * chunk_size:(i + 1) * chunk_size]
                s.sendall(chunk)
                  

        # Close the connection
        # s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")

if __name__ == "__main__":
    main(sys.argv[1:])




