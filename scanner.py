"""
just some testing code..
"""

def main():
	import sys
	import socket
	
	# comp_name = sys.argv[1]
	# start_port = int(sys.argv[2])
	# end_port   = int(sys.argv[3])
	# get raw input for targets
	
	# for comp_name, try running windows vm, setting ethernet ipv4 add to 192.168.10.3
	comp_name = input("please enter ip address of target: ") # comp_name (aka IP addr)
	start_port = input("enter starting port: ")
	end_port = input("enter ending port: ")
	print("target ip:", comp_name)
	comp_name = str(comp_name)
	start_port = int(start_port)
	end_port = int(end_port)
	# AF_INET means using IPv4 Internet Protocol,
	# SOCK_STREAM means make TCP connection
	for p in range(start_port, end_port+1):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		res = sock.connect_ex((comp_name, p))
		if res == 0:
			print("open on ", p)
			
			# from here, just to test, if open
			# then we should send a UDP Datagram,
			# send a ICMP Ping
			# a TCP packet, and aim to get the response to that
			# packet
			
			
		else:
			print("closed on",p)
		sock.close()
if __name__ == "__main__":

	main()
