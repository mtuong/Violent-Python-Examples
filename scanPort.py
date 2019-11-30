import optparse
from socket import *

server = 'files.oucru.org'
ip = "45.125.205.130"
port = 21
portList = [21,22,25,80,110]
banner = 'OUCRU'
password = 'mtuong'

setdefaulttimeout(2)
sname = gethostbyname(server)
print('IP address of server ', server, 'is: ', sname)

s = socket()
for port in portList:
    try:
        s.connect((ip,port))  
        ans = s.recv(1024)
        print(ans)        
        if banner in str(ans):
            print('Welcome to ftp server of OUCRU')

    except Exception as e:
        print('Error = ', str(e))

def checkVulns(banner):
    f = open("vuln_banners.txt",'r')
    for line in f.readlines():
        if line.strip('\n') in banner:
            print("[+] Server is vulnerable: "+banner.strip('\n'))
        else:
            print('Server is healthy')
            print(line)

def connScan(tgtHost, tgtPort):

    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('ViolentPython\r\n')
        results = connSkt.recv(100)
        print('[+]%d/tcp open'% tgtPort)
        print('[+] ', str(results))
        connSkt.close()
    except:
        print('[-]%d/tcp closed'% tgtPort)

def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print("[-] Cannot resolve '%s': Unknown host"%tgtHost)
        return
    
    try:
        tgtName = gethostbyaddr(tgtIP)
        print('\n[+] Scan Results for: ', tgtName[0])
    except:
        print('\n[+] Scan Results for: ', tgtIP)
        
        setdefaulttimeout(1)
        for tgtPort in tgtPorts:
            print('Scanning port ', tgtPort)
            connScan(tgtHost, int(tgtPort))

tgtHost = server
tgtPort = portList

portScan(tgtHost, tgtPort)
