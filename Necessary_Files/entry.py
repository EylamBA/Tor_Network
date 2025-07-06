import socket
import threading
import time
import pickle
import sys
import rsaLibrary as myrsa
import aes as myaes
import networlLibary as myNetwork

DIRECTORY_SERVER_IP = sys.argv[1]
PORT = int(sys.argv[2])      
BUFFER_SIZE = 32768
OWN_PORT = myNetwork.get_random_port()
rsaPublicKey, rsaPrivateKey = myrsa.generate_rsa_keys()
aeskey = myaes.generate_random_key()
available = True
was_available = True
log_needed = False
def connect_to_direcoty_server(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((ip, port))
        hybrid_encryption_from_client_to_server(client)
        global available
        global was_available
        
        while True:
            if available == True and was_available == False:
                data = "Release node"
                encrypted_data = myaes.enc(aeskey, data.encode())
                client.sendall(encrypted_data)
                was_available = True

def hybrid_encryption_from_client_to_server(client):
    data = "Hybrid Encryption"
    client.sendall(data.encode())
    d_public_key = client.recv(BUFFER_SIZE)
    d_public_key = d_public_key.decode()
    if log_needed:
        print(d_public_key)
        print(f"aes key: {aeskey}")
    encrypted_aes_key = myrsa.encrypt_message(aeskey, d_public_key)
    if log_needed:
        print(f"Encrypted aes key: {encrypted_aes_key}")
    data = encrypted_aes_key    
    client.sendall(data)
    
    ip = myNetwork.get_ip_address()
    port = OWN_PORT
    key = rsaPublicKey
    bandwidth = 4096
    role = "entry"
    data = f"{ip},{port},{key},{bandwidth},{role}"
    encrypted_data = myaes.enc(aeskey, data.encode())
    client.sendall(encrypted_data)
    

def entry_node_server(ip,port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((ip, port))
        server_socket.listen()
        if log_needed:
            print(f"Server listening on {ip}:{port}")
        while True:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=hanlde_client_entry_node, args=(conn, addr))
            client_thread.start()

def hanlde_client_entry_node(conn, addr):
    decrypted_aes_key = ""
    if log_needed:
        print(f"Connecntion from {addr}")
    global available
    global was_available
    available = False
    with conn:
        data = conn.recv(BUFFER_SIZE)
        data = data.decode()
        if data:                  
            if data == "Hybrid Encryption":
                decrypted_aes_key = hybrid_encryption_from_server_to_client(conn, data)
                
                data = conn.recv(BUFFER_SIZE)
                middle_details = myaes.dec(decrypted_aes_key, data).decode()
                if log_needed:
                    print(f"Middle details: {middle_details}")
                middleDetails = middle_details.split(',')
                middleIP = middleDetails[0]
                middlePort = middleDetails[1]
                
                response = "Ok"
                conn.sendall(response.encode())
    
                data = conn.recv(BUFFER_SIZE)
                exit_details = myaes.dec(decrypted_aes_key, data).decode()
                if log_needed:
                    print(f"Exit details: {exit_details}")
                exitDetails = exit_details.split(',')
                exitIP = exitDetails[0]
                exitPort = exitDetails[1]
                
                response = "Ok"
                conn.sendall(response.encode())
                
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                    client.connect((middleIP, int(middlePort)))
                    
                    hybrid_encryption_from_node_client_to_node_server(client)
                    data = f"{exitIP}, {exitPort}"
                    edata = myaes.enc(aeskey, data.encode())
                    client.sendall(edata)
                    
                    encryptes_aes_key = myaes.enc(decrypted_aes_key, aeskey)
                    conn.sendall(encryptes_aes_key)
                    
                    data = client.recv(BUFFER_SIZE)
                    middle_aes_key = myaes.dec(aeskey, data)
                    encryptes_aes_key = myaes.enc(decrypted_aes_key, middle_aes_key)
                    conn.sendall(encryptes_aes_key)
                    
                    data = client.recv(BUFFER_SIZE)
                    exit_aes_key = myaes.dec(aeskey, data)
                    encryptes_aes_key = myaes.enc(decrypted_aes_key, exit_aes_key)
                    conn.sendall(encryptes_aes_key)
                    
                    data = conn.recv(BUFFER_SIZE)
                    decrypted_data = myaes.dec(aeskey, data)
                    client.sendall(decrypted_data)

                    response = client.recv(BUFFER_SIZE)
                    response = myaes.dec(middle_aes_key, response)
                    conn.sendall(myaes.enc(decrypted_aes_key, response))

                    available = True
                    was_available = False

                    client.close()
                    conn.close()
                    
                    
                
                
                
                

def hybrid_encryption_from_server_to_client(conn, data):
    if log_needed:
        print(f"Recived: {data}")
    response = rsaPublicKey
    conn.sendall(response.encode())
    data = conn.recv(4096)
    if log_needed:
        print(f"Recived: {data}")
    response = "Ok"
    conn.sendall(response.encode())
    decrypted_aes_key = myrsa.decrypt_message(data, rsaPrivateKey)
    if log_needed:
        print(f"Decrypted aes key: {decrypted_aes_key}")   
    return decrypted_aes_key

def hybrid_encryption_from_node_client_to_node_server(client):
    data = "Hybrid Encryption"
    client.sendall(data.encode())
    d_public_key = client.recv(BUFFER_SIZE)
    d_public_key = d_public_key.decode()
    if log_needed:
        print(d_public_key)
        print(f"aes key: {aeskey}")
    encrypted_aes_key = myrsa.encrypt_message(aeskey, d_public_key)
    if log_needed:
        print(f"Encrypted aes key: {encrypted_aes_key}")
    data = encrypted_aes_key    
    client.sendall(data)
    data = client.recv(4096)
    if log_needed:
        print(data.decode())

      

if __name__ == "__main__":
    directory_server_thread = threading.Thread(target=connect_to_direcoty_server, args=(DIRECTORY_SERVER_IP, PORT))
    directory_server_thread.start()
    
    entry_node = threading.Thread(target=entry_node_server, args=("0.0.0.0", OWN_PORT))
    entry_node.start()