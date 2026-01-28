import nmap # type: ignore

try: 
    nm = nmap.PortScanner()

    try:
        print("\nScan has begun\n")
        nm.scan('127.0.0.1', '22-1024', timeout=30) # if scan takes longer than 30 seconds it will timeout
    except:
         print("Permission Error Occured")
         nm.scan('127.0.0.1', '22-1024', timeout=30) # if scan takes longer than 30 seconds it will timeout

    nm.command_line() #perform the nmap scan
    nm.scaninfo() #shows nmap scan information
    nm.all_hosts() #all the hosts in the scan
    nm['127.0.0.1'].hostname() #hostname for the ip
    nm['127.0.0.1'].state() #shows the state of host
    nm['127.0.0.1'].all_protocols() #list of protocols


    if not nm.all_hosts:
        print('\n-----------')
        print("Error")
        print("No host was discovered or is unreachable")
        print('\n------------')
    else:
        for host in nm.all_hosts():
                print('\n---------------')
                print('Host : %s (%s)' % (host, nm[host].hostname()))
                print('State : %s' % nm[host].state())
                
                for proto in nm[host].all_protocols():
                    print('---------------')
                    print('Protocol : %s' % proto)
                    lport = nm[host][proto].keys() # gets the port keys and converts it to a list

                    for port in lport: # loop showing the status of each port
                        print ('port: %s\tstate : %s' % (port, nm[host][proto][port]['state']),'|', (nm[host][proto][port]['name'])) #state and name are on the same level in the port dictionary

except nmap.PortScannerError as e:
     print(f"Nmap Error: {e}") # Error handling for nmap not being installed
except Exception as e:
     print(f"An unexpected error occurred: {e}") # More error handling
