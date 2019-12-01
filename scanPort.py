import optparse
import nmap
from socket import *
from threading import *

screenLock = Semaphore(value=1)

server = 'files.oucru.org'
# ip = "45.125.205.130"

portList = [21,22,25,80,110,443]
banner = 'OUCRU'
password = 'mtuong'

IP = gethostbyname(server)
print('IP address of server ', server, 'is: ', IP)

def topPorts():
    f = open("topPorts.txt",'r')
    tport = []

    print('\nList of Ports:\n')
    for line in f.readlines():        
        print(line.split(':')[0])
        tport.append(line.split(':')[0])

    return tport

def IPlist():
    f = open("IPlist.txt",'r')

    print('\nList of IP addresses:\n')
    for line in f.readlines():        
        print(line.strip('\n'))
        try:
            print(gethostbyaddr(line))
        
        except Exception as e:
            print('Error: ', str(e))


def sConnect(server, port):
    try:
        print('Connecting to server: ', server, ' on port: ', port)
        setdefaulttimeout(2)
        s = socket()
        s.connect((IP,port))  
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
        screenLock.acquire()
        print('[+]%d/tcp open'% tgtPort)
        print('[+] ', str(results))
        
    except:
        screenLock.acquire()
        print('[-]%d/tcp closed'% tgtPort)
    finally:
        screenLock.release()
        connSkt.close()

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
            t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
            t.start()
'''
def nmapScan(tgtHost, tgtPort):
    nmScan = nmap.PortScanner()
    nmScan.scan(tgtHost, tgtPort)
    state=nmScan[tgtHost]['tcp'][int(tgtPort)]['state']
    print(" [*] " + tgtHost + " tcp/"+tgtPort +" "+state)
'''


def scanIPs():
    f = open("IPlist.txt",'r')

    print('\n Scanning ...\n')
    for line in f.readlines():        
        # print(line.strip('\n'))
        tgtHost = line.strip('\n')
        portScan(tgtHost, tgtPorts)


# tgtHost = server
tgtPorts = topPorts()
IPlist()
port = 21
# sConnect(server, port)
scanIPs()
'''
for tgtPort in tgtPorts:
    nmapScan(tgtHost, tgtPort)
'''
