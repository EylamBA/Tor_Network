import subprocess
import threading
import time

script1 = 'Necessary_Files\entry.py'
script2 = 'Necessary_Files\middle.py'
script3 = 'Necessary_Files\exit.py'
log_needed = False

def run_entry(ip, port):
    if log_needed:
        print(f"Running {script1}...")
    subprocess.run(['python', script1, ip, port], check=True)

def run_midddle(ip, port):
    if log_needed:
        print(f"Running {script2}...")
    subprocess.run(['python', script2, ip, port], check=True)
    
def run_exit(ip, port):
    if log_needed:
        print(f"Running {script3}...")
    subprocess.run(['python', script3, ip, port], check=True)

def run_all_nodes(ip, port):
    entry_node = threading.Thread(target=run_entry, args=(ip, port))
    entry_node.start()
    
    middle_node = threading.Thread(target=run_midddle, args=(ip, port))
    middle_node.start()
    
    exit_node = threading.Thread(target=run_exit, args=(ip, port))
    exit_node.start()
    
