import socket
import hashlib
import pyotp
import json
import secrets

# Data base of users would go here with the secret key and  password hash
USERS = {
}

# Stateful session table: tracks client_address state, nonce, username
sessions = {}

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 12345))
    server.listen(5)
    print("The SRDS Server is Listening...")

    while True:
        client_sock, addr = server.accept()
        sessions[addr] = {"state": "UNAUTHENTICATED", "nonce": None}
        
        data = client_sock.recv(1024).decode()
        msg = json.loads(data)

# Stage 1: Handle Initial Identity Claim
        if msg['command'] == "AUTH_INIT" and sessions[addr]["state"] == "UNAUTHENTICATED":
            username = msg['payload']['username']
# SECURITY: Generate a unique code to mitigate Replay Attacks (Part B/C Mitigation from lab 3)
            nonce = secrets.token_hex(16)
            sessions[addr].update({"state": "AWAITING_VERIFY", "nonce": nonce, "user": username})
            
            response = {"command": "AUTH_CHALLENGE", "payload": {"nonce": nonce}}
            client_sock.send(json.dumps(response).encode())

# Stage 2: Verify Multi-Factor Credentials
        elif msg['command'] == "AUTH_VERIFY" and sessions[addr]["state"] == "AWAITING_VERIFY":
            user_data = USERS.get(sessions[addr]["user"])
            client_hash = msg['payload']['hash']
            client_otp = msg['payload']['otp']
            nonce = sessions[addr]["nonce"]

# SECURITY: Verify the Knowledge Factor (Password + Nonce Hash)
            expected_hash = hashlib.sha256((user_data["pwd_hash"] + nonce).encode()).hexdigest()
            
# SECURITY: Verify the Time-synced TOTP
            totp = pyotp.TOTP(user_data["otp_secret"])
            
            if client_hash == expected_hash and totp.verify(client_otp):
# SECURITY: Transition to AUTHENTICATED only after both factors pass
                sessions[addr]["state"] = "AUTHENTICATED"
                client_sock.send(json.dumps({"status": "SUCCESS WOOOOO"}).encode())
            else:
                client_sock.send(json.dumps({"status": "FAIL BOOOOOO"}).encode())
                client_sock.close() 
# Close connection to prevent brute force and standard pratice

start_server()