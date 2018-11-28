**PortScanner**
by: Tuan Phan, Grant Payne

*** video ***
https://www.youtube.com/watch?v=5zwPB8KvkI0


This module acts as an educational tool to show how portscanning, 
packet construction and sending, and traffic logging using Snort are done. 
It shows the ease with which portscanning can be done, as well as how 
flooding could be achieved if one could scale up the packets that the code 
sends (UDP, PING and TCP/SYN).

The tool runs as a command line interface tool, which allows the user to 
specify any IP address they'd like to scan, as well as a port on that host 
they'd like to send crafted packets to. It can also save and load hosts the
ports that are open on the hosts in a .txt file for future use.

**Snort**

Part of the project utilizes snort to log traffic. One can configure snort "rules"
that are triggered for certain types of traffic. Once the rules are triggered snort 
will log that traffic, which can be read using snort commands.

**sources**
No sources were consulted during the devising of this project.

**Directions**
to run this code, open terminal or command line and invoke it with:
>>> scanner.py
That's it!

**Usage Examples**

to get the help menu:
>>> -h

to scan a host:
>>> -s 192.168.10.2

to list open ports on hosts:
>>> -l 

to send 10 udp packets on port 80 to that same host:
>>> -udp 192.168.10.2 80 10





