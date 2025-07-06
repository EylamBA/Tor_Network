import socket
import threading
import sqlite3
from string import ascii_letters, digits
import smtplib
import ssl
from email.message import EmailMessage
import secrets

IP = "0.0.0.0"
PORT = 12346

EMAIL_SENDER = ""
EMAIL_SEND_PASSWORD = ""

with open("Data_Folder\Email.txt", "r") as f:
    lines = f.readlines()
    EMAIL_SENDER = lines[0].split(" ")[1].split("\n")[0]
    EMAIL_SEND_PASSWORD = lines[1].split(" ", 1)[1]


#001 = register
#002 = login
#003 = send message

db_file = 'Data_Folder\db.db'
conn = sqlite3.connect(db_file)
cursor = conn.cursor()

def main():
    initialize_database()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((IP, PORT))
        server_socket.listen()
        print(f"Server listening on {IP}:{PORT}")

        while True:
            # new connecion
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()


def initialize_database():
    db_conn = sqlite3.connect(db_file)
    cursor = db_conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Messages (
        Sender TEXT,
        Receiver TEXT,
        Message TEXT,
        Time TEXT,
        PRIMARY KEY (Sender)
    )
    ''')
    db_conn.commit()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Users (
        Username TEXT,
        Password TEXT,
        Email TEXT,
        PRIMARY KEY (Username)
    )
    ''')
    db_conn.commit()

    db_conn.close()
            


def handle_client(conn, addr):
    print(f"Connection from {addr}")

    while True:
        data = conn.recv(32768)
        if data:
            data = data.decode()
            print(data)
            data = data.split("=")
            if data[0] == "send":
                print(f"Received: {data[1]}")
                data = data[1].split(",", 3)
                sender = data[0].split("sender:")[1]
                receiver = data[1].split("reciver:")[1]
                message = data[2].split("message:")[1]
                time = data[3].split("time:")[1]

                if sender == receiver:
                    data = "Message sent to self"
                elif not checkReciver(receiver):
                    data = "Reciver not exsist"
                else:
                    #send_message(sender, receiver, message)
                    db_conn = sqlite3.connect(db_file)
                    cursor = db_conn.cursor()
                    cursor.execute('''
                    INSERT INTO Messages (Sender, Receiver, Message, Time)
                    VALUES (?, ?, ?, ?)
                    ''', (sender, receiver, message, time,))
                    db_conn.commit()
                    db_conn.close()  # Close the database connection after use
                    data = "Message sent successfully"
            elif data[0] == "register":
                print(f"Received: {data[1]}")
                if not(data[1].count(",") > 2):
                    data = data[1].split(",")
                    username = data[0].split(":")[1]
                    password = data[1].split(":")[1]
                    email = data[2].split(":")[1]

                    if not is_username_exists(username) or usernameValid(username):
                        if check_email_provider(email):
                            db_conn = sqlite3.connect(db_file)
                            cursor = db_conn.cursor()
                            cursor.execute('''
                            INSERT OR REPLACE INTO Users (Username, Password, Email)
                            VALUES (?, ?, ?)
                            ''', (username, password, email))
                            db_conn.commit()
                            db_conn.close()  # Close the database connection after use
                            data = f"OK,{username}"
                        else:
                            data = "NO,Email providers not suported"
                        
                    else:
                        data = "NO, Username already in use"
                else:
                    data = "Username not valid"
            elif data[0] == "login":
                print(f"Received: {data[1]}")
                if not(data[1].count(",") > 1):
                    data = data[1].split(",")
                    username = data[0].split(":")[1]
                    password = data[1].split(":")[1]
                    print(f"Received: {username}, {password}")
                    if check_login(username, password):
                        data = f"OK,{username}"
                    else:
                        data = "NO, Invalid credentials"
            elif data[0] == "forgotpassword":
                if not(data[1].count(",") > 1):
                    data = data[1].split(",")
                    username = data[0].split(":")[1]
                    email = check_if_email_exsits(username)
                    if email:
                        print(f"{username}, {email}")                  
                        varifaction_code = send_varifaction_code(email)
                        data = f"OK,{varifaction_code}"
                    else:
                        data = "NO, username doesn't exsits"
            elif data[0] == "resetpassword":
                if not(data[1].count(",") > 1):
                    data = data[1].split(",")
                    username = data[0].split(":")[1]
                    new_password = data[1].split(":")[1]
                    change_password(username, new_password)
                    data = "Password reset successfully"
                else:
                    data = "Couldn't reset password"
            elif data[0] == "searchusers":
                if (data[1].count(",") > 0):
                    data = data[1].split(",", 2)
                    username = data[0].split(":")[1]
                    sender = data[1].split(":")[1]
                    search_results = search_users(username)
                    if search_results:
                        if sender in search_results:
                            search_results.remove(sender)
                        data = f"OK,{search_results}"
                    else:
                        data = "No users found"
                else:
                    data = "Search term not valid"
            elif data[0] == "getmessages":
                if (data[1].count(",") > 0):
                    data = data[1].split(",", 2)
                    user1 = data[0].split(":")[1]
                    user2 = data[1].split(":")[1]
                    if user1 == user2:
                        data = "Message sent to self"
                    elif is_username_exists(user2):
                        message = get_messages(user1, user2)
                        print(message) #[[sender, message], [sender, message], ...]
                        if message:
                            data = f"OK,{message}"
                        else:
                            data = "No messages found"
                    else:
                        data = "Username doesn't exist"
                        """
                    messages = get_messages(sender, receiver)
                    if messages:
                        data = f"OK,{messages}"
                    else:
                        data = "No messages found"
                        """
                else:
                    data = "Search term not valid"
                    



                    

            conn.sendall(data.encode())


def send_message(sender, receiver, message):
    db_conn = sqlite3.connect(db_file)
    cursor = db_conn.cursor()
    cursor.execute('''
    INSERT INTO Messages (Sender, Receiver, Message)
    VALUES (?, ?, ?)
    ''', (sender, receiver, message,))
    db_conn.commit()
    db_conn.close()  # Close the database connection after use


def is_username_exists(username):
    db_conn = sqlite3.connect(db_file)
    cursor = db_conn.cursor()
    
    # Check if the username already exists in the Users table
    cursor.execute('''
    SELECT 1 FROM Users WHERE Username = ?
    ''', (username,))
    
    result = cursor.fetchone()
    db_conn.close()
    
    # If result is not None, it means the username exists in the table
    return result is not None

def usernameValid(username):
    return set(username).difference(ascii_letters + digits)

def check_email_provider(email):
    # List of common email providershttps://www.w3schools.com/sql/sql_and.asp
    known_providers = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", 
                       "icloud.com", "aol.com", "protonmail.com", "zoho.com"]
    
    # Split the email to get the domain
    try:
        domain = email.split("@")[1]
    except IndexError:
        return False  # Invalid email format
    
    # Check if the domain is in the list of known providers
    if email.split("@")[0] == "":
        return False
    return domain.lower() in known_providers

def checkReciver(receiver):
    db_conn = sqlite3.connect(db_file)
    cursor = db_conn.cursor()
    
    cursor.execute('''
    SELECT 1 FROM Users WHERE Username = ?
    ''', (receiver,))
    
    result = cursor.fetchone()
    db_conn.close()
    

    return result is not None

def check_login(username, password):
    db_conn = sqlite3.connect(db_file)
    cursor = db_conn.cursor()
    
    cursor.execute('''
    SELECT 1 FROM Users WHERE Username = ? AND Password = ?
    ''', (username, password,))
    
    result = cursor.fetchone()
    db_conn.close()
    

    return result is not None

def check_if_email_exsits(username):
    db_conn = sqlite3.connect(db_file)
    cursor = db_conn.cursor()

    cursor.execute("SELECT Email FROM Users WHERE Username = ?", (username,))
    result = cursor.fetchone()

    db_conn.close()
    
    if result:
        # User exists, retrieve and return the email
        email = result[0]
        return email
    else:
        return False

def send_varifaction_code(email):
    email_receiver = email

    # Set the subject and body of the email
    code = secrets.randbelow(900000) + 100000
    subject = 'Varification code for secure chats'
    body = f"""
    Varification Code: {code}
    """

    em = EmailMessage()
    em['From'] = EMAIL_SENDER
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body)

    # Add SSL (layer of security)
    context = ssl.create_default_context()

    # Log in and send the email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(EMAIL_SENDER, EMAIL_SEND_PASSWORD)
        smtp.sendmail(EMAIL_SENDER, email_receiver, em.as_string())

        return code

def change_password(username, password):
    db_conn = sqlite3.connect(db_file)
    cursor = db_conn.cursor()
    
    cursor.execute('''
    UPDATE Users SET Password =? WHERE Username =?
    ''', (password, username,))
    
    db_conn.commit()
    db_conn.close()

def search_users(username):
    db_conn = sqlite3.connect(db_file)
    cursor = db_conn.cursor()

    cursor.execute("SELECT Username FROM Users WHERE Username LIKE ?", (f"{username}%",))
    result = cursor.fetchall()

    db_conn.close()
    return [row[0] for row in result]

def get_messages(user1, user2):
    # Connect to the SQLite database
    db_conn = sqlite3.connect(db_file)
    cursor = db_conn.cursor()
    
    # Query to fetch messages between user1 and user2 in both directions
    cursor.execute('''
    SELECT Sender, Receiver, Message 
    FROM Messages 
    WHERE (Sender = ? AND Receiver = ?) 
    OR (Sender = ? AND Receiver = ?)
    ''', (user1, user2, user2, user1))
    
    # Fetch all the results
    messages = cursor.fetchall()
    
    # Close the database connection
    db_conn.close()

    # Create a list where we only include Sender and Message (ignoring Receiver)
    modified_messages = []
    for sender, receiver, message in messages:
        # If the message is equal to the sender, just use the sender's name and message
        if sender == message:
            modified_messages.append([sender, message])
        else:
            modified_messages.append([sender, message])
    
    return modified_messages


if __name__ == "__main__":
    main()