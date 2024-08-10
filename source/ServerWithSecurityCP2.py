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
import zlib # only used for sustainability 
import hashlib
from datetime import datetime, timedelta
import secrets
import traceback
from signal import signal, SIGINT
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend



# Dictionary to store used nonces with their timestamps
used_nonces = {}

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

def is_valid_nonce(nonce):
    # Check if the nonce is already used
    if nonce in used_nonces:
        return False
    # Store the nonce with the current timestamp
    used_nonces[nonce] = datetime.utcnow()
    return True

def is_valid_timestamp(timestamp):
    # Check if the timestamp is within an acceptable range (e.g., 5 minutes)
    current_time = datetime.utcnow()
    message_time = datetime.utcfromtimestamp(timestamp)
    time_difference = current_time - message_time
    return abs(time_difference) < timedelta(minutes=5)


def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)

def calculate_data_hash(data):
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()

def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    address = args[1] if len(args) > 1 else "localhost"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()
            print(f"Server listening on {address}:{port}")

            # if CHECK PASS, begin handshake for file upload
            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    mode = convert_bytes_to_int(read_bytes(client_socket, 8))
                    print(f"Received mode: {mode}")
                    
                    if mode==0: # filename
                        # If the packet is for transferring the filename
                        print("Receiving file...")
                        try:
                            filename_len = convert_bytes_to_int(
                                    read_bytes(client_socket, 8)
                                    )
                            filename = read_bytes(
                                    client_socket, filename_len
                                ).decode("utf-8")
                            print(f"Filename: {filename}")
                            # file_hash_len = convert_bytes_to_int(read_bytes(client_socket, 8))
                            # file_hash = read_bytes(client_socket, file_hash_len).decode("utf-8")
                            # print(f"Received file hash: {file_hash}")
                        except Exception as e:
                            print(f"Error receiving filename: {e}")
                            client_socket.sendall(b"Error receiving filename. Ensure the filename is sent correctly.")

                    elif mode==1: # file data block
                        try:
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()

                            #get length of file
                            file_len = convert_bytes_to_int(read_bytes(client_socket, 8))
                            
                            encrypted_file_data = read_bytes(client_socket, file_len)
                            print(f"File data received: {len(encrypted_file_data)} bytes")

                            #get filename to add into the recv_files_enc folder with its relevant encrypted data
                            filenamepart = filename.split("/")[-1]
                            filename = "enc_recv_" + filenamepart
                            #save received encrypted file from client to /recv_files_enc
                            with open(f"recv_files_enc/{filename}", mode="wb") as fp:
                                fp.write(encrypted_file_data)

                            decrypted_file_data = session_key.decrypt(encrypted_file_data)
                            decompressed_data = zlib.decompress(decrypted_file_data)

                            # # Verify file integrity
                            # received_file_hash = calculate_data_hash(decompressed_data)
                            # if received_file_hash != file_hash:
                            #     print("File integrity check failed! Hashes do not match.")
                            # else:
                            #     print("File integrity check passed.")

                            filename = "recv_" + filenamepart

                            # Write the decrypted file with 'recv_' prefix
                            with open(f"recv_files/{filename}", mode="wb") as fp:
                                fp.write(decompressed_data)
                                # fp.write(decrypted_file_data)
                            print(f"Finished receiving file in {(time.time() - start_time)}s!")
                        except Exception as e:
                            print(f"Error receiving file data: {e}")
                            client_socket.sendall(b"Error receiving file data. Ensure the data blocks are sent correctly.")

                    elif mode==2: # close connection
                        # Close the connection
                        # Python context used here so no need to explicitly close the socket
                        print("Closing connection...")
                        # s.close()
                        break
                    elif mode==3: # authentication
                        try:
                            # Authentication request
                            M1_size = convert_bytes_to_int(read_bytes(client_socket, 8))
                            M2 = read_bytes(client_socket, M1_size)
                            nonce = M2[:16]
                            timestamp = convert_bytes_to_int(M2[16:24])
                            message = M2[24:]
                            print("Received authentication request")

                            # Check nonce and timestamp validity
                            if not is_valid_nonce(nonce) or not is_valid_timestamp(timestamp):
                                print("Invalid nonce or timestamp. Closing connection...")
                                break

                            # Extract both private and public key from .pem file 
                            try:
                                with open("source/auth/server_private_key.pem", mode="r", encoding="utf8") as key_file:
                                    private_key = serialization.load_pem_private_key(
                                        bytes(key_file.read(), encoding="utf8"), password=None
                                    )
                                public_key = private_key.public_key()
                            except Exception as e:
                                print(f"Error loading private key: {e}")
                                traceback.print_exc()
                                break

                            # Sign the entire message (M2: nonce + timestamp + message)
                            signed_M2 = private_key.sign(
                                M2, # message in bytes format
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH,
                                ),
                                hashes.SHA256(), # hashing algorithm used to hash the data before encryption 
                            )

                            # Load server cert
                            with open("source/auth/server_signed.crt", "rb") as cert_file:
                                signed_server_cert = cert_file.read()

                            print("Loaded server certificate:")
                            print(f"Size of server certificate: {len(signed_server_cert)} bytes")
                            print(signed_server_cert.decode('utf-8', errors='ignore'))


                            try:
                                print(f"Sending signed M2 of size: {len(signed_M2)} bytes")
                                client_socket.sendall(convert_int_to_bytes(len(signed_M2)))
                                client_socket.sendall(signed_M2)
                                print("Sent signed M2")
                                client_socket.sendall(convert_int_to_bytes(len(signed_server_cert)))
                                client_socket.sendall(signed_server_cert)
                                print("Sent signed M2 and signed server certificate to client")
                            except Exception as e:
                                print(f"Error sending data: {e}")
                                traceback.print_exc()
                                break
                        except Exception as e:
                            print(f"Error during authentication: {e}")
                            client_socket.sendall(b"Error during authentication. Ensure the correct data is sent.")
                            traceback.print_exc()
                            break
                    elif mode==4:   #sessionkey handshake
                        #receive data from client side
                        try:
                            m1 = convert_bytes_to_int(read_bytes(client_socket, 8)) 
                            sessionkey_bytes_encrypted = read_bytes(client_socket, m1)
                        
                        
                            with open("source/auth/server_private_key.pem", mode="r", encoding="utf8") as key_file:
                                private_key = serialization.load_pem_private_key(bytes(key_file.read(), encoding="utf8"), password=None)
                                                
                            #decrypt data to get session key
                            session_key_bytes = private_key.decrypt(sessionkey_bytes_encrypted, padding.PKCS1v15())
                            session_key = Fernet(session_key_bytes)

                        except Exception as e:
                            print(f"Error during session key handshake: {e}")
                            client_socket.sendall(b"Error during session key handshake. Ensure the correct session key data is sent.")

                

    except Exception as e:
        print(f"Server encountered an error: {e}")
        print("Closing server...")
        s.close()

def handler(signal_received, frame):
    # Handle any cleanup here
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    exit(0)
    
if __name__ == "__main__":
    # Tell Python to run the handler() function when SIGINT is recieved
    signal(SIGINT, handler)
    main(sys.argv[1:])


