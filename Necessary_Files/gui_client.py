import tkinter as tk
from tkinter import messagebox
import socket
import infrastructure as infrastructure
import run_three_nodes as run_three_nodes
import time
from termcolor import colored
import ast
import datetime

DIRECTORY_SERVER_IP = "192.168.0.120"
DIRECTORY_SERVER_PORT = "12345"

APPLICATION_SERVER_IP = "192.168.0.120"
APPLICATION_SERVER_PORT = "12346"


def connect_to_server():
    try:
        global client
        run_three_nodes.run_all_nodes(DIRECTORY_SERVER_IP, DIRECTORY_SERVER_PORT)
        client = infrastructure.connect_to_direcoty_server(DIRECTORY_SERVER_IP, int(DIRECTORY_SERVER_PORT))
        print("Loading...")
        time.sleep(1)
        print("Connected to the server.")
    except Exception as e:
        print(f"Error connecting to server: {e}")

# Define main app window
root = tk.Tk()
root.geometry("600x400")
root.configure(bg="#F5F5F5")

logged_user = ""
user_to_reset_password = ""
varifaction_code = ""
talking_with = ""
# Update the window title based on the screen
def update_title(title):
    root.title(title)

# Clear input fields and error messages
def clear_signup_fields():
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    email_entry.delete(0, tk.END)
    signup_error_label.config(text="")

def clear_login_fields():
    login_username_entry.delete(0, tk.END)
    login_password_entry.delete(0, tk.END)
    login_error_label.config(text="")


def clear_reset_fields():
    reset_username_entry.delete(0, tk.END)
    reset_error_label.config(text="")

def clear_code_field():
    code_entry.delete(0, tk.END)
    code_error_label.config(text="")

def clear_new_password_fields():
    #new_username_entry.delete(0, tk.END)
    new_password_entry.delete(0, tk.END)
    new_password_error_label.config(text="")

# Switch between frames
def switch_to_login():
    update_title("Login")
    clear_signup_fields()
    clear_reset_fields()
    clear_code_field()
    clear_new_password_fields()
    signup_frame.pack_forget()
    reset_frame.pack_forget()
    reset_code_frame.pack_forget()
    new_password_frame.pack_forget()
    #welcome_frame.pack_forget()
    login_frame.pack()

def switch_to_signup():
    update_title("Sign Up")
    clear_login_fields()
    login_frame.pack_forget()
    reset_frame.pack_forget()
    reset_code_frame.pack_forget()
    new_password_frame.pack_forget()
    #welcome_frame.pack_forget()
    signup_frame.pack()

def switch_to_reset():
    update_title("Password Reset")
    clear_login_fields()
    login_frame.pack_forget()
    reset_code_frame.pack_forget()
    new_password_frame.pack_forget()
    #welcome_frame.pack_forget()
    reset_frame.pack()

# Switch to new password screen
def switch_to_new_password():
    update_title("Set New Password")
    clear_code_field()
    clear_reset_fields()
    reset_code_frame.pack_forget()
    new_password_frame.pack()

def switch_to_main(username):
    update_title("Welcome")
    clear_login_fields()
    clear_signup_fields()
    login_frame.pack_forget()
    signup_frame.pack_forget()
    reset_frame.pack_forget()
    reset_code_frame.pack_forget()
    new_password_frame.pack_forget()
    left_frame.pack(side=tk.LEFT, fill=tk.Y)
    search_label.pack(pady=10)
    search_entry.pack(padx=10, pady=5)
    search_button.pack(pady=5)
    result_listbox.pack(fill=tk.BOTH, expand=True, padx=15, pady=50)
    result_listbox.bind("<Double-1>", on_user_select)
    right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    user_name.place(relx=1.0, rely=0.0, anchor="ne", x=-10, y=10,)
    user_name.config(text=logged_user)
    
    """welcome_label.config(text=f"Welcome, {username}!")
    root.geometry("600x400")  # Resize window for the welcome screen
    welcome_frame.pack()"""

# Show verification screen for password reset
def send_reset_code():
    if reset_username_entry.get() == "":
        reset_error_label.config(text="Please enter a username.")
    else:
        username = reset_username_entry.get()
        global user_to_reset_password
        message, user_to_reset_password = f"forgotpassword=username:{username}", username
        #client.sendall(message.encode())
        #response = client.recv(32768).decode()
        response = send_message_using_directory_server(client, message)
        if response.split(",")[0] == "OK":
            global varifaction_code
            varifaction_code = response.split(",")[1]
            #reset_error_label.config(text="Verification code sent!")
            clear_reset_fields()
            reset_code_frame.pack()
            reset_frame.pack_forget()
        else:
            reset_error_label.config(text=response.split(",")[1][1:])

# Verify code and navigate accordingly
def verify_code():
    clear_reset_fields()
    if code_entry.get() == "":  # Example code for verification
        code_error_label.config(text="Enter the code to verify")
    else:
        if code_entry.get() == varifaction_code:  # Example code for verification
            switch_to_new_password()  # Navigate to new password screen
        else:
            code_error_label.config(text="Wrong code")
        

# Signup and login function placeholders
def signup():
    username = username_entry.get()
    password = password_entry.get()
    email = email_entry.get()
    message = f"register=username:{username},password:{password},email:{email}"
    #client.sendall(message.encode())
    #response = client.recv(32768).decode()
    response = send_message_using_directory_server(client, message)
    if not username or not password or not email:
        signup_error_label.config(text="All fields are required for signup.")
    else:
        if response.split(",")[0] == "OK":
            global logged_user
            logged_user = response.split(",")[1]
            switch_to_main(logged_user)
        else:    
            signup_error_label.config(text=response.split(",")[1][1:])

def login():
    username = login_username_entry.get()
    password = login_password_entry.get()
    if not username or not password:
        login_error_label.config(text="All fields are required for login.")
    else:
        message = f"login=username:{username},password:{password}"
        #client.sendall(message.encode())
        #response = client.recv(32768).decode()
        response = send_message_using_directory_server(client, message)
        if response.split(",")[0] == "OK":
            global logged_user
            logged_user = response.split(",")[1]
            switch_to_main(logged_user)
        else:
            login_error_label.config(text=response.split(",")[1][1:])

def reset_passwrod():
    new_password = new_password_entry.get()
    chack_new_password = chack_new_password_entry.get()
    if new_password == "" or chack_new_password_entry == "":
        new_password_error_label.config(text="Please enter a new password.")
    else:
        if new_password != chack_new_password:
            new_password_error_label.config(text="Passwords do not match.")
        else:
            message = f"resetpassword=username:{user_to_reset_password},newpassword:{new_password}"
            #client.sendall(message.encode())
            #response = client.recv(32768).decode()
            response = send_message_using_directory_server(client, message)
            print(f"{response}")
            switch_to_login()

def exit():
    diconnect(client)
    root.destroy()

def send_message_using_directory_server(client, message):
    nodes_details = infrastructure.get_nodes_details(client)     
    message = f"{APPLICATION_SERVER_IP},{APPLICATION_SERVER_PORT},{message}"
    response = infrastructure.start_sequence(message, nodes_details)
    return response

def diconnect(client):
    infrastructure.disconected(client)

# Signup Frame
signup_frame = tk.Frame(root, bg="#F5F5F5")
signup_frame.pack()

tk.Label(signup_frame, text="Sign Up", font=("Helvetica", 16), bg="#F5F5F5").pack(pady=20)

tk.Label(signup_frame, text="Username:", bg="#F5F5F5").pack()
username_entry = tk.Entry(signup_frame, width=30, relief="flat", highlightbackground="#A0A0A0", highlightthickness=1)
username_entry.pack(pady=5)

tk.Label(signup_frame, text="Password:", bg="#F5F5F5").pack()
password_entry = tk.Entry(signup_frame, show="*", width=30, relief="flat", highlightbackground="#A0A0A0", highlightthickness=1)
password_entry.pack(pady=5)

tk.Label(signup_frame, text="Email:", bg="#F5F5F5").pack()
email_entry = tk.Entry(signup_frame, width=30, relief="flat", highlightbackground="#A0A0A0", highlightthickness=1)
email_entry.pack(pady=5)

signup_error_label = tk.Label(signup_frame, text="", fg="red", bg="#F5F5F5")
signup_error_label.pack(pady=5)

tk.Button(signup_frame, text="Sign Up", command=signup, width=15, bg="#4CAF50", fg="white", relief="flat").pack(pady=10)
tk.Button(signup_frame, text="Switch to Login", command=switch_to_login, bg="#F5F5F5", relief="flat", fg="#1E90FF").pack()

# Login Frame
login_frame = tk.Frame(root, bg="#F5F5F5")

tk.Label(login_frame, text="Login", font=("Helvetica", 16), bg="#F5F5F5").pack(pady=20)

tk.Label(login_frame, text="Username:", bg="#F5F5F5").pack()
login_username_entry = tk.Entry(login_frame, width=30, relief="flat", highlightbackground="#A0A0A0", highlightthickness=1)
login_username_entry.pack(pady=5)

tk.Label(login_frame, text="Password:", bg="#F5F5F5").pack()
login_password_entry = tk.Entry(login_frame, show="*", width=30, relief="flat", highlightbackground="#A0A0A0", highlightthickness=1)
login_password_entry.pack(pady=5)

login_error_label = tk.Label(login_frame, text="", fg="red", bg="#F5F5F5")
login_error_label.pack(pady=5)

tk.Button(login_frame, text="Login", command=login, width=15, bg="#4CAF50", fg="white", relief="flat").pack(pady=10)
tk.Button(login_frame, text="Forgot Password?", command=switch_to_reset, bg="#F5F5F5", relief="flat", fg="#1E90FF").pack()
tk.Button(login_frame, text="Switch to Sign Up", command=switch_to_signup, bg="#F5F5F5", relief="flat", fg="#1E90FF").pack(pady=10)

# Password Reset Frame
reset_frame = tk.Frame(root, bg="#F5F5F5")

tk.Label(reset_frame, text="Password Reset", font=("Helvetica", 16), bg="#F5F5F5").pack(pady=20)

tk.Label(reset_frame, text="Enter Username:", bg="#F5F5F5").pack()
reset_username_entry = tk.Entry(reset_frame, width=30, relief="flat", highlightbackground="#A0A0A0", highlightthickness=1)
reset_username_entry.pack(pady=5)

reset_error_label = tk.Label(reset_frame, text="", fg="red", bg="#F5F5F5")
reset_error_label.pack(pady=5)

tk.Button(reset_frame, text="Send Verification Code", command=send_reset_code, width=20, bg="#4CAF50", fg="white", relief="flat").pack(pady=10)
tk.Button(reset_frame, text="Back to Login", command=switch_to_login, bg="#F5F5F5", relief="flat", fg="#1E90FF").pack()

# Verification Code Frame
reset_code_frame = tk.Frame(root, bg="#F5F5F5")

tk.Label(reset_code_frame, text="Enter Verification Code", font=("Helvetica", 16), bg="#F5F5F5").pack(pady=20)

tk.Label(reset_code_frame, text="Verification Code:", bg="#F5F5F5").pack()
code_entry = tk.Entry(reset_code_frame, width=30, relief="flat", highlightbackground="#A0A0A0", highlightthickness=1)
code_entry.pack(pady=5)

code_error_label = tk.Label(reset_code_frame, text="", fg="red", bg="#F5F5F5")
code_error_label.pack(pady=5)

tk.Button(reset_code_frame, text="Verify Code", command=verify_code, width=15, bg="#4CAF50", fg="white", relief="flat").pack(pady=10)
tk.Button(reset_code_frame, text="Back to login", command=switch_to_login, bg="#F5F5F5", relief="flat", fg="#1E90FF").pack(pady=10)


# New Password Frame
new_password_frame = tk.Frame(root, bg="#F5F5F5")

tk.Label(new_password_frame, text="Set New Password", font=("Helvetica", 16), bg="#F5F5F5").pack(pady=20)


tk.Label(new_password_frame, text="New Password:", bg="#F5F5F5").pack()
new_password_entry = tk.Entry(new_password_frame, show="*", width=30, relief="flat", highlightbackground="#A0A0A0", highlightthickness=1)
new_password_entry.pack(pady=5)

tk.Label(new_password_frame, text="New Password Again:", bg="#F5F5F5").pack()
chack_new_password_entry = tk.Entry(new_password_frame, show="*", width=30, relief="flat", highlightbackground="#A0A0A0", highlightthickness=1)
chack_new_password_entry.pack(pady=5)

new_password_error_label = tk.Label(new_password_frame, text="", fg="red", bg="#F5F5F5")
new_password_error_label.pack(pady=5)

tk.Button(new_password_frame, text="Submit", command=reset_passwrod, width=15, bg="#4CAF50", fg="white", relief="flat").pack(pady=10)

"""
# Welcome Frame
welcome_frame = tk.Frame(root, bg="#F5F5F5")

welcome_label = tk.Label(welcome_frame, text="", font=("Helvetica", 16), bg="#F5F5F5")
welcome_label.pack(pady=20)


"""

#================================================================#



# Update chat window for selected user
def open_chat(user):
    chat_label.pack(pady=10)
    chat_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    chat_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5))
    send_button.pack(side=tk.RIGHT)
    input_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
    global talking_with
    talking_with = user
    chat_label.config(text=f"Chat with {user}")
    chat_text.config(state=tk.NORMAL)
    chat_text.delete("1.0", tk.END)
    chat_text.insert(tk.END, f"Chat started with {user}\n")
    chat_text.config(state=tk.DISABLED)

def send_message(chat_text, chat_entry):
    message = chat_entry.get().strip()
    if message:
        message = f"send=sender:{logged_user},reciver:{talking_with},message:{message},time:{datetime.datetime.now()}"
        response = send_message_using_directory_server(client, message)
        chat_entry.delete(0, tk.END)

def search_users():
    search_query = search_entry.get()
    message = f"searchusers=username:{search_query},sender:{logged_user}"
    response = send_message_using_directory_server(client, message)
    if response.split(",")[0] == "OK":
        list_part = response[3:]
        list_part = list_part.strip()[1:-1]
        users = [name.strip().strip("'") for name in list_part.split(",")]
        print(users)

        results = users
        result_listbox.delete(0, tk.END)
        for user in results:
            result_listbox.insert(tk.END, user)

"""def fetch_usernames(search_query):
    usernames = ['elad', 'eylam1', 'eylam123', 'eylam123321', 'eylam1234',
                 'eylam1234323', 'eylam123434t', 'eylam12345', 'eylam123454',
                 'eylam123456', 'eylam124354231', 'eylam13243546575645342',
                 'eylam2', 'eylam3', 'eylam4', 'eylam44', 'eylam5']
    return sorted([user for user in usernames if search_query.lower() in user.lower()])"""

# When clicking a user in the listbox
def on_user_select(event):
    selected_user = result_listbox.get(result_listbox.curselection())
    open_chat(selected_user)
    update_chat()

def update_chat():
    message = f"getmessages=user1:{logged_user},user2:{talking_with}"
    response = send_message_using_directory_server(client, message)
    if response.split(",")[0] == "OK":
        list_part = response[3:]
        messages = ast.literal_eval(list_part)
        
        chat_text.config(state=tk.NORMAL)
        chat_text.delete("1.0", tk.END)
        
        
        for sender, msg in messages:
            if sender == logged_user:
                chat_text.tag_configure("right", justify="right")
                chat_text.insert(tk.END, f"\n{msg}\n", "right")
                chat_text.tag_add("right_bubble", "end-2c linestart", "end-1c")
                chat_text.tag_configure("right_bubble", background="#DCF8C6", lmargin1=50, rmargin=8)
            else:
                chat_text.insert(tk.END, f"\n{msg}\n", "left")
                chat_text.tag_add("left_bubble", "end-2c linestart", "end-1c")
                chat_text.tag_configure("left_bubble", background="#E8E8E8", lmargin1=8, rmargin=50)
        
        chat_text.config(state=tk.DISABLED)
        chat_text.yview(tk.END)
    root.after(7984, update_chat)

# Left Frame for Search
left_frame = tk.Frame(root, bg="#E8E8E8", width=200)
#left_frame.pack(side=tk.LEFT, fill=tk.Y)

search_label = tk.Label(left_frame, text="Search Users", bg="#E8E8E8", font=("Helvetica", 14))
#search_label.pack(pady=10)

search_entry = tk.Entry(left_frame, width=25)
#search_entry.pack(pady=5)

search_button = tk.Button(left_frame, text="Search", command=search_users)
#search_button.pack(pady=5)

result_listbox = tk.Listbox(left_frame)
#result_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
#result_listbox.bind("<Double-1>", on_user_select)


# Right Frame for Chat
right_frame = tk.Frame(root, bg="#FFFFFF")
#right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

user_name = tk.Label(right_frame, text="", font=("Helvetica", 16), anchor="ne")

chat_label = tk.Label(right_frame, text="Chat Window", bg="#FFFFFF", font=("Helvetica", 14))
#chat_label.pack(pady=10)

chat_text = tk.Text(right_frame, state=tk.DISABLED, wrap=tk.WORD)
#chat_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

input_frame = tk.Frame(right_frame, bg="#FFFFFF")



chat_entry = tk.Entry(right_frame)
#chat_entry.pack(fill=tk.X, padx=10, pady=5)

send_button = tk.Button(right_frame, text="Send", command=lambda: send_message(chat_text, chat_entry))
#send_button.pack(pady=5)


#================================================================#


# Exit Button
exit_button = tk.Button(root, text="Exit", command=exit, width=10, bg="#F44336", fg="white", relief="flat")


# Function to position the exit button symmetrically
def place_exit_button(event=None):
    padding = 1
    window_width = root.winfo_width()
    window_height = root.winfo_height()
    exit_button.place(x=padding, y=window_height - padding - exit_button.winfo_height(), anchor="w")

# Place the button initially
place_exit_button()

# Update button position when window is resized
root.bind("<Configure>", place_exit_button)



# Initial screen
switch_to_login()
connect_to_server()

root.mainloop()
