import socket
import threading
import time
import pickle
import rsaLibrary as myrsa
import aes as myaes
import networlLibary as myNetwork


BUFFER_SIZE = 32768
OWN_PORT = myNetwork.get_random_port()
rsaPublicKey, rsaPrivateKey = myrsa.generate_rsa_keys()
aeskey = myaes.generate_random_key()
log_needed = False

def connect_to_direcoty_server(ip, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip, port))
    
    hybrid_encryption_from_client_to_server(client)

    return client

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
    data = f"{ip},{port},{key},{bandwidth}"
    if log_needed:
        print(data)
    encrypted_data = myaes.enc(aeskey, data.encode())
    client.sendall(encrypted_data)
    

def get_nodes_details(main, start_message = "START"):
    main.sendall(myaes.enc(aeskey, start_message.encode()))
    data = myaes.dec(aeskey, main.recv(BUFFER_SIZE))
    computers_details = pickle.loads(data)
    if log_needed:
        print("Received list:", computers_details)
    return computers_details

def start_sequence(message, computers_details = []): 
    entryDetails = computers_details[0].split(',')
    entryIP = entryDetails[0]
    entryPort = entryDetails[1]
    if log_needed:
        print(f"ENTRY IP: {entryIP}")
        print(f"ENTRY PORT: {entryPort}")
    
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((entryIP, int(entryPort)))
        
        hybrid_encryption_from_client_to_node(client)
        
        middleDetails = computers_details[1].split(',')
        middleIP = middleDetails[0]
        middlePort = middleDetails[1]
        if log_needed:
            print(f"MIDDLE IP: {middleIP}")
            print(f"MIDDLE PORT: {middlePort}")
        
        data = f"{middleIP}, {middlePort}"
        edata = myaes.enc(aeskey, data.encode())
        client.sendall(edata)
        
        data = client.recv(BUFFER_SIZE)
        if log_needed:
            print(data.decode())
        
        exitDetails = computers_details[2].split(',')
        exitIP = exitDetails[0]
        exitPort = exitDetails[1]
        if log_needed:
            print(f"EXIT IP: {exitIP}")
            print(f"EXIT PORT: {exitPort}")
        
        data = f"{exitIP}, {exitPort}"
        edata = myaes.enc(aeskey, data.encode())
        client.sendall(edata)
        
        data = client.recv(BUFFER_SIZE)
        if log_needed:
            print(data.decode())
        
        
        data = client.recv(BUFFER_SIZE)
        entry_aes_key = myaes.dec(aeskey, data)
        if log_needed:
            print(entry_aes_key)
        
        data = client.recv(BUFFER_SIZE)
        middle_aes_key = myaes.dec(aeskey, data)
        if log_needed:
            print(middle_aes_key)
        
        data = client.recv(BUFFER_SIZE)
        exit_aes_key = myaes.dec(aeskey, data)
        if log_needed:
            print(exit_aes_key)
        
        layer1 = myaes.enc(exit_aes_key, message.encode())
        layer2 = myaes.enc(middle_aes_key, layer1)
        layer3 = myaes.enc(entry_aes_key, layer2)
        
        client.sendall(layer3)

        response = client.recv(BUFFER_SIZE)
        response = myaes.dec(aeskey, response)

        client.close()

        return response.decode()
        
        
        
        

def hybrid_encryption_from_client_to_node(client):
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


def disconected(client):
    data = "EXIT"
    client.sendall(myaes.enc(aeskey, data.encode()))
    data = myaes.dec(aeskey, client.recv(BUFFER_SIZE)).decode()
    if log_needed:
        print(f"Recived from directort server: {data}")
    client.close()

    
    
    