import socket     
import hashlib 
import pyotp

s = socket.socket()         
port = 12345                
s.connect(('127.0.0.1', port)) 

def password_auth():
    while True:
        try:
            pw = input("password: ")
            s.send(hashlib.sha256(pw.encode()).digest())
            pw_res = s.recv(1024).decode()
            if pw_res.startswith("OTP"):
                print(pw_res)
                return True
            print(pw_res)
        except:
            print("authentication has failed")
            return False

def OTP_auth():
    while True:
        try:
            pw = input("OTP code: ")
            s.send(pw.encode())
            pw_res = s.recv(1024).decode()
            if pw_res.startswith("OTP code has been accepted"):
                print(pw_res)
                return True
            print(pw_res)
        except:
            print("authentication has failed")
            return False

f = input('Name: ')
print('type exit to ruin our connection')
s.send (("HELLO|" + f).encode())
print (s.recv(1024).decode())

opt_authenticated = False
if password_auth():
    opt_authenticated = OTP_auth()

while opt_authenticated:
    try: 
        msg = input()
        input_s = ("MSG|" + msg).encode()
        if msg == "exit":
            s.send(b"EXIT|")
            print (s.recv(1024).decode())
            break
        s.send(input_s)
        print (s.recv(1024).decode())
    except Exception as error:
        print(error)
        break
s.close()