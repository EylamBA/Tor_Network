import socket
import threading
import pickle
import random
import rsaLibrary as myrsa
import aes as myaes

# IP and PORT fro the directort server
IP = "0.0.0.0"
PORT = 12345
BUFFER_SIZE = 32768
# The path to the file where the logged comupted saved
computers_details_path = "Necessary_Files\computers_details.txt"

# The server privae and public RSA keys
rsaPublicKey, rsaPrivateKey = myrsa.generate_rsa_keys()

# array of all the computer connected to the server
computer_array = []


def start_server(ip, port):
    """
    This function starts the server. 
    It's waiting for new connection and when a new connection happens it's send the client to a new thread
    Args:
        ip (string): ip for the directory server
        port (int): port for the directory server
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((ip, port))
        server_socket.listen()
        print(f"Server listening on {ip}:{port}")

        while True:
            # new connecion
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()


def handle_client(conn, addr):
    """
    This function handle all the client request
    Args:
        conn (): _description_
        addr (tuple): the client ip and port
    """

    # client decrypted aes key
    decrypted_client_aes_key = ""

    # client port to other computer to connect to
    user_port = 0

    print(f"Connecntion from {addr}")

    with conn:
        try:
            data = conn.recv(BUFFER_SIZE)
            data = data.decode()
            if data:      
                # Hybrid connection is to exchange key to be at the end with the same aes key as the client            
                if data == "Hybrid Encryption":
                    print(f"Recived: {data}")
                    # send the public key
                    response = rsaPublicKey
                    conn.sendall(response.encode())

                    # recive the encrypted aes key of the client
                    data = conn.recv(BUFFER_SIZE)
                    print(f"Recived: {data}")

                    # decrypting the client aes key
                    decrypted_client_aes_key = myrsa.decrypt_message(data, rsaPrivateKey)
                    print(f"Decrypted aes key: {decrypted_client_aes_key}")

                    # getting the client details from the message: ip, port, rsa public key, bandwidth, and role if needed(entry, middle or exit)
                    data = conn.recv(BUFFER_SIZE)
                    decrypted_data = myaes.dec(decrypted_client_aes_key, data).decode()
                    print(f"Recived: {decrypted_data}")

                    # adding the cient info to the logged computers file
                    add_client_info(decrypted_data)   

                    # extracting the user port when needed to serach for specific computer in the file
                    # the serch will be like: if client aip and his connection port for other computer apear in the file then do something
                    user_port = decrypted_data.split(',')[1]   

            # waiting for client's other request request
            while True:
                data = conn.recv(BUFFER_SIZE)
                if data:                
                    # decrypted the request the client sent          
                    data = myaes.dec(decrypted_client_aes_key, data).decode()
                    print(data) 
                    if data != "EXIT":   
                        # START means to send a list of three nodes: entry, middle and exit to the client
                        if data == "START":
                            # getting the nodes from the client
                            computers_details = getNodes(addr, user_port)

                            # searialize the response and send it encrypted
                            serialized_data = pickle.dumps(computers_details)
                            conn.sendall(myaes.enc(decrypted_client_aes_key, serialized_data)) 
                        
                        elif data == "Release node":
                                realeseNode(addr, user_port)

                        # for testing, thing other than "START" the direcory server will response by saying "Hello back"    
                        else:          
                            response = "Hello back"
                            encryypted_rsponse = myaes.enc(decrypted_client_aes_key, response.encode())
                            conn.sendall(encryypted_rsponse)
                    
                        
                    else:
                        # if the client want to exit, the directory server will return "Goodbye" 
                        # and remove the client from the logged computer file
                        response = "Goodbye"
                        encryypted_rsponse = myaes.enc(decrypted_client_aes_key, response.encode())
                        conn.sendall(encryypted_rsponse)

                        #removing the client
                        remove_client_info(addr, user_port)
                        
                        #closing the connection
                        conn.close()

                        # exiting the loop and closing the thread
                        break
                    
        except:
            remove_client_info(addr, user_port)



def add_client_info(data):
    """
    Adding client info to the logged computers file

    Args:
        data (string): containing ip, port, rsa public key, bandwidth, and role if needed(entry, middle or exit)
    """
    with open(computers_details_path, 'a') as file:
        file.write(f"{data}\n")
        computer_array.append(data)

    
def remove_client_info(addr, user_port):
    """
    Remove the client from the logged computers file

    Args:
        addr (tupple): the tupple contains the ip and the port of the client (ip, port)
        user_port (string): the port saved in the logged computer file
    """
    
    # getting the line that needs to be removed from the line
    line_need_to_remove = f"{addr[0]}"

    # gettting the lines of the file
    with open(computers_details_path, 'r') as file:
        lines = file.readlines()

    computer_array.clear()

    # rewriting of the file lines but without the line that needs to be removed
    with open(computers_details_path, 'w') as file:
        for line in lines:
            # check if the line to be reomved is not the line, if it not than write it to the file, if it does than not
            if line_need_to_remove not in line:
                file.write(line)
                computer_array.append(line)


def getNodes(addr, user_port):
    """
    Getting three nodes from the file: entry, middle and exit

    Args:
        addr (tupple): the tupple contains the ip and the port of the client (ip, port)
        user_port (string): the port saved in the logged computer file

    Returns:
        sorted_computer_details: list of all the nodes details sorted by the order: entry -> middle -> exit
    """

    nodes_list = []

    # getting the line that needs to be removed from the line
    line_not_needed = f"{addr[0]},{user_port}"

    # gettting the lines of the file
    with open(computers_details_path, 'r') as file:
        lines = file.readlines()

    # sehuffle the lines so not every time the function will return the same three nodes
    random.shuffle(lines)
    
    # these are flags that say it a node already been chosen
    entry_flag = 0
    middle_flag = 0
    exit_flag = 0
    # looping through the lines in the directory files and gettign the requird nodes
    """for line in lines:
            if not(entry_flag != 0 and middle_flag != 0 and exit_flag != 0):
                if line_not_needed not in line:
                    if "entry" in line and entry_flag == 0:
                        nodes_list.append(line)
                        entry_flag += 1
                    elif "middle" in line and middle_flag == 0:
                        nodes_list.append(line)
                        middle_flag += 1
                    elif "exit" in line and exit_flag == 0:
                        nodes_list.append(line)
                        exit_flag += 1
            else:
                break
                """
    for i in range(len(lines)):
            if not(entry_flag != 0 and middle_flag != 0 and exit_flag != 0):
                if line_not_needed not in lines[i] and ",not available" not in lines[i]:
                    if "entry" in lines[i] and entry_flag == 0:
                        nodes_list.append(lines[i])
                        entry_flag += 1
                        lines[i] = (f"{lines[i]},not available")
                    elif "middle" in lines[i] and middle_flag == 0:
                        nodes_list.append(lines[i])
                        middle_flag += 1
                        lines[i] = (f"{lines[i]},not available")
                    elif "exit" in lines[i] and exit_flag == 0:
                        nodes_list.append(lines[i])
                        exit_flag += 1
                        lines[i] = (f"{lines[i]},not available")
            else:
                break
    

    # sorting the list by oredr: entry -> middle -> exit
    order = {"entry": 0, "middle": 1, "exit": 2}
    sorted_nodes_list = sorted(nodes_list, key=lambda x: order[next(word for word in order if word in x)])
    
    nl = [item.replace('\n', '') for item in lines]
    nl2 = [item + '\n' for item in nl]
    with open(computers_details_path, 'w') as file:
        for line in nl2:
                file.write(line)

    # returning the sorted nodes list
    return sorted_nodes_list

def realeseNode(addr, user_port):
    line_needed = f"{addr[0]},{user_port}"
    updated_lines = []

    with open(computers_details_path, 'r') as file:
        lines = file.readlines()
    
    for line in lines:
        if line_needed in line:
            updated_line = line.replace(",not available", "").strip()
            updated_lines.append(updated_line + '\n')
        else:
            updated_lines.append(line)
    
    with open(computers_details_path, 'w') as file:
        file.writelines(updated_lines)


if __name__ == "__main__":
    # cleaing the logged computers file
    file = open(computers_details_path, 'w')
    file.close()

    # string the sertver
    start_server(IP, PORT)