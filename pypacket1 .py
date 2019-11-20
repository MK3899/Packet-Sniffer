import socket,struct,binascii,os
import pye
from netifaces import interfaces, ifaddresses, AF_INET

if os.name == "nt":
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    s.bind(("YOUR_INTERFACE_IP",0))
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
else:
    s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
issa=1

for ifaceName in interfaces():
    addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'No IP addr'}] )]
    if(ifaceName=='wlp3s0'):    
	#print '%s: %s' % (ifaceName, ', '.join(addresses))
	myIP=addresses
myIP=str(myIP[0])
print myIP


while issa<40:
    pkt=s.recvfrom(65565)
    unpack=pye.unpack()
    
    for i in unpack.ip_header(pkt[0][14:34]).iteritems():
	a,b=i
	if a == "Source Address" :
            #print b
	    if b==myIP:
        	print "{} : {} | ".format(a,b),
    		print "\n\n===>> [+] ------------ Ethernet Header----- [+]"
    		for i in unpack.eth_header(pkt[0][0:14]).iteritems():
    		    c,d=i
    		    print "{} : {} | ".format(c,d),
   	        print "\n\n===>> [+] ------------ IP Header ------------[+]"
   	        for i in unpack.ip_header(pkt[0][14:34]).iteritems():
       	            c,d=i
		    if c=="Protocol":
			if d==6:
				print "{} : {} |".format(c,"TCP"),
			elif d==17:
				print "{} : {} |".format(c,"UDP"),
			elif d==4:
				print "{} : {} |".format(c,"IPv4"),
			else:
				print "{} : {} |".format(c,d),
		    else:
        	    	print "{} : {} | ".format(c,d),
                print "\n\n===>> [+] ------------ Tcp Header ----------- [+]"
                for  i in unpack.tcp_header(pkt[0][34:54]).iteritems():
                    c,d=i
                    print "{} : {} | ".format(c,d),
		print '\n \n \n \n '
        elif a=="Destination Address":
	    if b == myIP:
        	print "{} : {} | ".format(a,b),
    		print "\n\n===>> [+] ------------ Ethernet Header----- [+]"
    		for i in unpack.eth_header(pkt[0][0:14]).iteritems():
    		    c,d=i
    		    print "{} : {} | ".format(c,d),
   	        print "\n\n===>> [+] ------------ IP Header ------------[+]"
   	        for i in unpack.ip_header(pkt[0][14:34]).iteritems():
       	            c,d=i
		    if c=="Protocol":
			if d==6:
				print "{} : {} |".format(c,"TCP"),
			elif d==17:
				print "{} : {} |".format(c,"UDP"),
			elif d==4:
				print "{} : {} |".format(c,"IPv4"),
			else:
				print "{} : {} |".format(c,d),
		    else:
        	    	print "{} : {} | ".format(c,d),
                print "\n\n===>> [+] ------------ Tcp Header ----------- [+]"
                for  i in unpack.tcp_header(pkt[0][34:54]).iteritems():
                    c,d=i
                    print "{} : {} | ".format(c,d),
		print '\n \n \n \n '
    issa=issa+1

    
