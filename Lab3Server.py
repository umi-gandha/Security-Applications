import socket 
import pyotp  

auth_dict = {
  "umika": b'\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad'
}

base32secret3232 = 'JBSWY3DPEBLW64TMMFQW45DP'
s = socket.socket()         
print ("Socket successfully created")
port = 12345                
 

def chat_function():
   while True:
      try:
          goop = c.recv(1042).decode()
          if goop.startswith("MSG|"):
              if goop[4:] == "":
                  c.send("AY why didnt you say HELLO to me...rude much".encode())
                  print("message was empty")
               
              elif goop[4:] == "goodbye to you":
                  c.send(("thanks" + username + "switching off").encode())
                  c.close()
                  exit()
              else:
                  print(goop)
                  c.send(("thanks"+ username + "Got your message").encode())
            
          elif goop == ("EXIT|"):
               c.send(b"shoo go away")
               c.close()
               print ("Disconected and waiting for a new connection")
               break
          else:
               print("incorrect format of " + username)
               c.send(b'try again please')
               c.close()        
      
      except Exception as error:
        print(error)
        print("client connection broken" )
        
        if goop[4:] == "good-day to you":
           c.close()
           exit()
           break
        c.close()

def pw_authentication(counter):
    try:
        while counter > 0 :
            pw = c.recv(1042)
            if pw == auth_dict[username]:
                c.send(("Please provide the OTP code " + username).encode())
                print("You have been authenticated")
                return True
            else:
                print("you have not been authenticated")
                c.send(("Incorrect information has been entered. try again please").encode())
                counter -= 1
        return False
    except Exception as error:
        print(error)
        print("This username does not exist")
        return False

def OTP_auth():
    otp_counter = 4
    try:
        while otp_counter > 0:
            totp = pyotp.TOTP(base32secret3232)
            totp.now()
            OTP = c.recv(1042).decode()
            if totp.verify(OTP):
                c.send(("OTP code has been accepted " + username).encode())
                print("you are now authenticated")
                return True
            else:
                print("you are currently not authenticated")
                c.send(("the incorrect OTP has been entered").encode())
                otp_counter -= 1
    except Exception as error:
        print(error)
        print("an error has occured")
        return False

s.bind(('', port))         
print ("socket binded to %s" %(port)) 
s.listen(5)     
print ("socket is listening") 

while True: 
  c, addr = s.accept()     
  print ('Connection from', addr )
  
  data = c.recv(1024).decode()
  if data.startswith("HELLO|"):
    username = data[6:]
    c.send(("HIIII welcome").encode())
    print("connection made to" + username)
    counter = 7

    if pw_authentication(counter) and OTP_auth():
            chat_function()
    else:
            c.send("something broke".encode())
    c.close()

  else:
   print("The server did not receive a hello")
   c.send(("Why do you keep not sayig hello to me, that hurts my feelings").encode())
   c.close()