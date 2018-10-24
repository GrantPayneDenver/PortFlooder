"""
Scanner and Flooding Module


 TODO:
 	1: create methods that actually flood ports we've scanned and found open
 	 1.a: Make sure that they cover the full range of flooding / DDOS we talked about
 	 1.b: see if there are "dummy" ip addresses out there that you can target and test flooding on
 	3: see if ICMP_Ping_flood() can be made to be distributed somehow.


Testing IPs: 192.174.63.97    www.NREL.gov
		     151.101.117.164  www.nytimes.com
			 104.16.60.202    www.thrashermagazine.com

gathered from whois lookups @ https://www.ultratools.com/tools/ipWhoisLookup
"""

import sys
import socket
import scapy
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
		print("These are all open ports found for all hosts scanned: ")
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


def ICMP_Ping_Flood(host, amount=1):
	"""
	Sends a flood of pings n pings set by amount using the ICMP protocols.
	Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
	"""
	try:
		amount=int(amount)
		# Ping command count option as function of OS
		param = '-n' if system_name().lower() == 'windows' else '-c'
		for i in range(0, amount):
			# Building the command. Ex: "ping -c 1 google.com"
			command = ['ping', param, '1', host]
			# Pinging
			print(system_call(command))
	except Exception as e:
		print('something went wrong in ping flood ', e)
		print('host and number of pings set: ', host, ' ', amount)

def scanning(args, state):
	"""
	scans host specified by user
	saves the open ports discovered in State object
	"""
	host  = args[2]
	start_port = int(args[3])
	end_port   = int(args[4])
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
	print("-l              - list the sets of ports found open for all hosts scanned")
	print("-pf             - flood a target host with an ICMP PING flood.\n" 
			"            Requires three args, <host> and <port start> and <port end>")
	print("-a            - save hosts and open ports to a .txt file")
	print("-r            - read in hosts and open ports from a .txt file")
	print()
	print()
	print("Examples: ")
	if print_code_name:
		print("scanner.py -l")
		print("scanner.py -s 192.168.0.1 0 500")
		print("scanner.py -pf 192.168.0.1  <num of pings>")
	else:
		print("-l")
		print("-s 192.168.0.1 0 500")
		print("-pf 192.168.0.1   <num of pings>")

	# sys.exit(0)


if __name__ == "__main__":
	"""
		takes in args for operations
		and also iters thru a loop waiting for operations through raw input
		saves the program state with State (ports found open, etc)
	"""
	state = State()

	# if no args sent, just print usage()
	try:
		# see if started script with args, if not except and go to while True
		sys.argv[1]

		if sys.argv[1] in ('-h', '-help'):
			usage()
		args = sys.argv
		if args[1] == "-s":
			scanning(args, state)
		elif args[1] == "-l":
			list_ports(state)
		elif args[1] == "-pf":
			# call for a ping flood
			print("WARNING: make sure you're not actually flooding a 'real' IP address")
			ICMP_Ping_Flood(host=args[1], amount=args[2])
		elif args[1] == "-r":
			state.load()
		else:
			print("invalid arguments entered: %s" % sys.argv)
	except IndexError:
		usage()

	while True:

		print("Enter a set of commands <sans the file name> (hint, type -h or -help for help)""")
		print("To quit, enter -q/-Q")
		print()
		cmds = input("<#SCNR> ").split()
		if 'scanner.py' in cmds:
			cmds.remove('scanner.py')
		if not cmds: continue
		if cmds[0] in ('-h', '-help'):
			usage(False)
		elif cmds[0] == "-s":
			# insert an arg at zeroth index so it aligns with how
			# sys.args is formmated
			# ex: sys.args is [<scanner.py>, <-s>, <host> <strt prt> <end prt>]
			# ex: cmds     is [<'filler'>,   <-s>, <host> <strt prt> <end prt>]
			cmds.insert(0, 'filler')
			scanning(cmds, state)
		elif cmds[0] == "-l":
			list_ports(state)
		elif cmds[0] == "-pf":
			# call for a ping flood
			print("WARNING: make sure you're not actually flooding a 'real' IP address")
			ICMP_Ping_Flood(host=cmds[1], amount=cmds[2])
		elif cmds[0] in ('-q', '-Q'):
			sys.exit(0)
		elif cmds[0] == '-a':
			state.save()
		elif cmds[0] == "-r":
			state.load()
		else:
			print("invalid arguments entered: %s" % cmds)