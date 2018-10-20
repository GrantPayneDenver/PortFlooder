"""
Scanner and Flooding Module


 TODO:
 	1: create methods that actually flood ports we've scanned and found open
 	 1.a: Make sure that they cover the full range of flooding / DDOS we talked about
 	 1.b: see if there are "dummy" ip addresses out there that you can target and test flooding on
 	2: Implement State load() and save() to save hosts and their open ports to disk


Testing IPs: 192.174.63.97    www.NREL.gov
		     151.101.117.164  www.nytimes.com
			 104.16.60.202    www.thrashermagazine.com

gathered from whois lookups @ https://www.ultratools.com/tools/ipWhoisLookup
"""

import sys
import socket
from multiprocessing import Pool

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
		pass # need to implement

	def load(self):
		"""
		Will open saved hosts and open ports using specified path
		:return:
		"""

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
	print("-f              - flood a target host and list of target ports.\n" 
			"            Requires three args, <host> and <port start> and <port end>")
	print()
	print()
	print("Examples: ")
	if print_code_name:
		print("scanner.py -l")
		print("scanner.py -s 192.168.0.1 0 500")
		print("scanner.py -f 192.168.0.1 0 500")
	else:
		print("-l")
		print("-s 192.168.0.1 0 500")
		print("-f 192.168.0.1 0 500")

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
		sys.argv[1]
	except:  
		usage()

	if sys.argv[1] in ('-h', '-help'):
		usage()

	args = sys.argv
	if args[1] == "-s":
		scanning(args, state)
	elif args[1] == "-l":
		list_ports(state)
	elif args[1] == "-f":
		print("WARNING: make sure you're not actually flooding a 'real' IP address")
	else:
		print("invalid arguments entered: %s" % sys.argv)

	while True:

		print("Enter another set of commands <sans the file name> (hint, type -h or -help for help)""")
		print("To quit, enter -q/-Q")
		print()
		cmds = input("<#SCNR> ").split()
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
		elif cmds[0] == "-f":
			print("WARNING: make sure you're not actually flooding a 'real' IP address")
		elif cmds[0] in ('-q', '-Q'):
			sys.exit(0)
		else:
			print("invalid arguments entered: %s" % cmds)