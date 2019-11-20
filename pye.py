import socket
import struct
import binascii
class unpack:
	def __cinit__(self):
		self.data=None

	
	def eth_header(self, data):
		obj=data
		obj=struct.unpack("!6s6sH",obj)
		destination_mac=binascii.hexlify(obj[0])
		source_mac=binascii.hexlify(obj[1])
		eth_protocol=obj[2]
		data={"Destination Mac":destination_mac,
		"Source Mac":source_mac,
		"Protocol":eth_protocol}
		return data

	
	
	
	def ip_header(self, data):
		obj=struct.unpack("!BBHHHBBH4s4s", data)
		_version=obj[0] 
		_tos=obj[1]
		_total_length =obj[2]
		_identification =obj[3]
		_fragment_Offset =obj[4]
		_ttl =obj[5]
		_protocol =obj[6]
		_header_checksum =obj[7]
		_source_address =socket.inet_ntoa(obj[8])
		
		_destination_address =socket.inet_ntoa(obj[9])

		data={'Version':_version,
		"Tos":_tos,
		"Total Length":_total_length,
		"Identification":_identification,
		"Fragment":_fragment_Offset,
		"TTL":_ttl,
		"Protocol":_protocol,
		"Header CheckSum":_header_checksum,
		"Source Address":_source_address,
		"Source Host" : socket.getfqdn(_source_address),	
		"Destination Host ":socket.getfqdn(_destination_address),
		"Destination Address":_destination_address}
		return data

	
	def tcp_header(self, data):
		obj=struct.unpack('!HHLLBBHHH',data)
		_source_port =obj[0] 
		_destination_port  =obj[1]
		_sequence_number  =obj[2]
		_acknowledge_number  =obj[3]
		_offset_reserved  =obj[4]
		_tcp_flag  =obj[5]
		_window  =obj[6]
		_checksum  =obj[7]
		_urgent_pointer =obj[8]
		data={"Source Port":_source_port,
		"Destination Port":_destination_port,
		"Sequence Number":_sequence_number,
		"Acknowledge Number":_acknowledge_number,
		"Offset & Reserved":_offset_reserved,
		"Tcp Flag":_tcp_flag,
		"Window":_window,
		"CheckSum":_checksum,
		"Urgent Pointer":_urgent_pointer
		}
		return data 


def mac_formater(a):
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
	return b

def get_host(q):
	try:
		k=socket.gethostbyaddr(q)
	except:
		k='Unknown'
	return k
