# -*- coding: utf-8 -*-
#!/bin/python

import argparse
import dpkt
import getopt
import os
import socket
import sys

from dpkt.compat import compat_ord
from graphviz import Digraph

inputfilename = ""
outputfilename = ""
parsetype = ""
interfacelist = []
flowlist = []

##################################################################################
class Interface:
	def __init__(self, name, macaddress, ipv4address, ipv4subnetmask, ipv6address, ipv6subnetmask, tcpport, udpport):
		self.name = name
		self.macaddress = macaddress
		self.ipv4address = ipv4address
		self.ipv4subnetmask = ipv4subnetmask
		self.ipv6address = ipv6address
		self.ipv6subnetmask = ipv6subnetmask
		self.macaddresslist = []
#		self.ipv4addresslist = []
#		self.ipv6addresslist = []
		self.tcpportlist = []
		self.udpportlist = []
		if tcpport != '':
			self.appendTcpportlist(tcpport)
		if udpport != '':
			self.appendUdpportlist(udpport)

	def setName(self, name):
		self.name = name

	def getName(self):
		return self.name

	def setMacaddress(self, macaddress):
		self.macaddress = macaddress

	def getMacaddress(self):
		return self.macaddress

	def setIpv4address(self, ipv4address):
		self.ipv4address = ipv4address

	def getIpv4address(self):
		return self.ipv4address

	def setIpv4subnetmask(self, ipv4subnetmask):
		self.ipv4subnetmask = ipv4subnetmask

	def getIpv4subnetmask(self):
		return self.ipv4subnetmask

	def setIpv6address(self, ipv6address):
		self.ipv6address = ipv6address

	def getIpv6address(self):
		return self.ipv6address

	def setIpv6subnetmask(self, ipv6subnetmask):
		self.ipv6subnetmask = ipv6subnetmask

	def getIpv6subnetmask(self):
		return self.ipv6subnetmask

	def appendTcpportlist(self, tcpport):
		if not self.searchTcpportlist(tcpport):
			self.tcpportlist.append(tcpport)

	def getTcpportlist(self):
		return self.tcpportlist

	def searchTcpportlist(self, tcpport):
		for port in self.tcpportlist:
			if port == tcpport:
				return True
		return False

	def appendUdpportlist(self, udpport):
		if not self.searchUdpportlist(udpport):
			self.udpportlist.append(udpport)

	def getUdpportlist(self):
		return self.udpportlist

	def searchUdpportlist(self, udpport):
		for port in self.udpportlist:
			if port == udpport:
				return True
		return False

	# def appendMacaddress(self, macaddress):
	# 	if macaddress != "ff:ff:ff:ff:ff:ff" and not searchMacaddresslist(macaddress):
	# 		self.macaddresslist.append(macaddress)

	# def getMacaddresslist(self):
	# 	return self.macaddresslist

	# def searchMacaddresslist(self, macaddress):
	# 	for address in self.macaddresslist:
	# 		if address == macaddress:
	# 			return True
	# 	return False

	# def setIpaddresslist(self, ipaddress):
	# 	if not checkMulticastIpaddress(ipaddress) and not searchIpaddresslist(ipaddress):
	# 		self.ipaddresslist.append(ipaddress)

	# def appendIpaddresslist(self):
	# 	return self.ipaddresslist

	# def searchIpaddresslist(self, ipaddress):
	# 	for address in self.ipaddresslist:
	# 		if address == ipaddress:
	# 			return True
	# 	return False

	# def appendIp6addresslist(self, ip6address):
	# 	if not searchIp6addresslist(ip6address):
	# 		self.ip6addresslist.append(ip6address)

	# def getIp6addresslist(self):
	# 	return self.ip6addresslist

	# def searchIp6addresslist(self, ip6address):
	# 	for address in self.ip6addresslist:
	# 		if address == ip6address:
	# 			return True
	# 	return False


class Flowipv4:
	def __init__(self, ip_protocol, src_ipv4address, src_port, dst_ipv4address, dst_port):
		self.ip_protocol = ip_protocol
		self.src_ipv4address = src_ipv4address
		self.src_port = src_port
		self.dst_ipv4address = dst_ipv4address
		self.dst_port = dst_port

	def setIp_protocol(self, ip_protocol):
		self.ip_protocol = ip_protocol

	def getIp_protocol(self):
		return self.ip_protocol

	def setSrc_ipv4address(self, src_ipv4address):
		self.src_ipv4address = src_ipv4address

	def getSrc_ipv4address(self):
		return self.src_ipv4address

	def setSrc_port(self, src_port):
		self.src_port = src_port

	def getSrc_port(self):
		return self.src_port

	def setDst_ipv4address(self, dst_ipv4address):
		self.dst_ipv4address = dst_ipv4address

	def getDst_ipv4address(self):
		return self.dst_ipv4address

	def setDst_port(self, dst_port):
		self.dst_port = dst_port

	def getDst_port(self):
		return self.dst_port


##################################################################################
def argumentCheck():
	result = argumentParser()
	if result == False:
		sys.exit(1)
	print ''


def argumentParser():
	global parsetype, inputfilename, outputfilename

	usage = 'Usage: python %s parsetype inputfile outputfile [--help]'%os.path.basename(__file__)

	argparser = argparse.ArgumentParser(usage=usage)
	argparser.add_argument('parsetype', type=str, help='ipv4 (l2 and ipv6 type are not implemented.)')
	argparser.add_argument('inputfile', type=str, help='input pcap file name')
	argparser.add_argument('outputfile', type=str, help='output file name (The file extension does not include.)')
	args = argparser.parse_args()

	if args.parsetype:
			parsetype = args.parsetype
	else:
		return False
	if args.inputfile:
			inputfilename = args.inputfile
	else:
		return False
	if args.outputfile:
			outputfilename = args.outputfile
	else:
		return False
	return True


def pcapParserIpv4():
	global interfacelist, flowlist

	# clear
	interfacelist = []
	flowlist = []

	# Read pcap file
	packets = dpkt.pcap.Reader(open(os.getcwd() + '/' + inputfilename, 'rb'))
	packetcount = 0

	# Parse 1
	for timestamp, buf in packets:
		packetcount += 1

		try:
			eth = dpkt.ethernet.Ethernet(buf)
		except:
			print 'Fail parse frame no:', packet_count, ' skipped.'
			continue

		src_macaddress = mac_addr(eth.src)
		dst_macaddress = mac_addr(eth.dst)

		if type(eth.data) == dpkt.ip.IP:

			ip = ''
			ip_protocol = ''
			src_ipaddress = ''
			src_ipsubnetmask = ''
			dst_ipaddress = ''
			dst_subnetmask = ''

			tcp = ''
			src_tcpport = ''
			dst_tcpport = ''

			udp = ''
			src_udpport = ''
			dst_udpport = ''


			if type(eth.data) == dpkt.ip.IP:
				ip = eth.data
				ip_protocol = ip.p
				src_ipaddress = inet_to_str(ip.src)
				src_ipsubnetmask = ''
				dst_ipaddress = inet_to_str(ip.dst)
				dst_ipsubnetmask = ''


				if type(ip.data) == dpkt.tcp.TCP:
					tcp = ip.data
					src_tcpport = tcp.sport
					dst_tcpport = tcp.dport

				elif type(ip.data) == dpkt.udp.UDP:
					udp = ip.data
					src_udpport = udp.sport
					dst_udpport = udp.dport

				src_interface = None
				dst_interface = None

				for i in interfacelist:
					if i.getIpv4address() == src_ipaddress:
						src_interface = i
					elif i.getIpv4address() == dst_ipaddress:
						dst_interface = i

				# src
#				if src_interface == None and not checkMulticastIpv4address(src_ipaddress):
				if src_interface == None:
					src_interface = Interface(
											src_ipaddress,		# name
											'', 				# macaddress
											src_ipaddress,		# ipv4address
											'',					# ipv4subnetmask
											'',					# ipv6address
											'',					# ipv6subnetmask
											src_tcpport,		# tcpport
											src_udpport			# udpport
											)

					# append
					interfacelist.append(src_interface)

#				elif src_interface != None and not checkMulticastIpv4address(src_ipaddress):
				else:
					# tcpport
					src_interface.appendTcpportlist(src_tcpport)

					# udpport
					src_interface.appendUdpportlist(src_udpport)

				# dst
#				if dst_interface == None and not checkMulticastIpv4address(dst_ipaddress):
				if dst_interface == None:
					dst_interface = Interface(
											dst_ipaddress,		# name
											'', 				# macaddress
											dst_ipaddress,		# ipv4address
											'',					# ipv4subnetmask
											'',					# ipv6address
											'',					# ipv6subnetmask
											dst_tcpport,		# tcpport
											dst_udpport			# udpport
											)
					# append
					interfacelist.append(dst_interface)

#				elif dst_interface != None and not checkMulticastIpv4address(dst_ipaddress):
				else:
					# tcpport
					dst_interface.appendTcpportlist(dst_tcpport)

					# udpport
					dst_interface.appendUdpportlist(dst_udpport)


#				print "eth:%s, %s" % (src_macaddress, dst_macaddress)
#				print "ip:%s, %s, %s" % (ip_protocol, src_ipaddress, dst_ipaddress)
#				print "tcp:%s, %s udp:%s, %s" % (src_tcpport, dst_tcpport, src_udpport, dst_udpport)


				# flow
				flag = False

				for f in flowlist:
					if ip_protocol == 1:	# icmp
						if f.getIp_protocol() == ip_protocol and f.getSrc_ipv4address() == src_ipaddress and f.getDst_ipv4address() == dst_ipaddress:
							flag = True
					elif ip_protocol == 6:	# tcp
						if f.getIp_protocol() == ip_protocol and f.getSrc_ipv4address() == src_ipaddress and f.getSrc_port() == src_tcpport and f.getDst_ipv4address() == dst_ipaddress and f.getDst_port() == dst_tcpport:
							flag = True
					elif ip_protocol == 17:	# udp
						if f.getIp_protocol() == ip_protocol and f.getSrc_ipv4address() == src_ipaddress and f.getSrc_port() == src_udpport and f.getDst_ipv4address() == dst_ipaddress and f.getDst_port() == dst_udpport:
							flag = True

#				if flag == False and not checkMulticastIpv4address(src_ipaddress) and not checkMulticastIpv4address(dst_ipaddress):
				if flag == False:
					if ip_protocol == 1:	# icmp
						flow = Flowipv4(ip_protocol, src_ipaddress, '', dst_ipaddress, '')
						flowlist.append(flow)
					elif ip_protocol == 6:	# tcp
						flow = Flowipv4(ip_protocol, src_ipaddress, src_tcpport, dst_ipaddress, dst_tcpport)
						flowlist.append(flow)
					elif ip_protocol == 17:	# udp
						flow = Flowipv4(ip_protocol, src_ipaddress, src_udpport, dst_ipaddress, dst_udpport)
						flowlist.append(flow)



def mac_addr(address):
	return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def checkMulticastMacaddress(macaddress):
	return False

def checkMulticastIpv4address(ipaddress):
	ip1 = int(ipaddress.split(".")[0])
	if ipaddress == "255.255.255.255" or ip1 >= 224 and ip1 <= 239:
		return True
	return False

def checkMulticastIpv6address(ip6address):
	return False

def checkPrivateIpv4address(ipaddress):
	ip1 = int(ipaddress.split(".")[0])
	ip2 = int(ipaddress.split(".")[1])
	ip3 = int(ipaddress.split(".")[2])
	ip4 = int(ipaddress.split(".")[3])

	if ip1 == 10:
		return True
	elif ip1 == 172 and ip2 >= 16 and ip2 <=31:
		return True
	elif ip1 == 192 and ip2 == 168:
		return True

	return False


def makeGraphIpv4():

	privatelist = []
	multicastlist = []
	globallist = []

	g = Digraph(format='png', engine='fdp')
	g.attr(compound='true')
	g.attr(rankdir='LR')
	g.attr(rank='same')

	# node
	for i in interfacelist:
		if checkPrivateIpv4address(i.name):	# private ipaddress
			privatelist.append(i)
		elif checkMulticastIpv4address(i.name): # multicast ipaddress
			multicastlist.append(i)
		else:	# global ipaddress
			globallist.append(i)

	for i in privatelist:
		g1 = None

		with g.subgraph(name='cluster_private') as g01:
			g01.attr(label='private network')
			g01.attr(color='blue')
			g01.attr(rank='same')

			with g01.subgraph(name='cluster_'+i.name) as g1:
				g1.attr(label=i.name)
				g1.attr(color='blue')
				g1.attr(rank='same')
#				g1.attr("graph", style="filled")
#				g1.attr("graph", color="lightgray")

				g2 = None
				if len(i.getTcpportlist()) != 0:
					with g1.subgraph(name='cluster_'+i.name+'_tcp') as g2:
						g2.attr(label='TCP')
						g2.attr(color='green')
						g2.attr(rank='same')
						for tport in i.getTcpportlist():
							if tport != '':
								g2.node(i.name+'_tcp_'+str(tport), label=str(tport), shape="box", color='green')

				g2 = None
				if len(i.getUdpportlist()) != 0:
					with g1.subgraph(name='cluster_'+i.name+'_udp') as g2:
						g2.attr(label='UDP')
						g2.attr(color='orange')
						g2.attr(rank='same')
						for uport in i.getUdpportlist():
							if uport != '':
								g2.node(i.name+'_udp_'+str(uport), label=str(uport), shape="box", color='orange')

	for i in multicastlist:
		g1 = None

		with g.subgraph(name='cluster_private') as g01:
			g01.attr(label='private network')
			g01.attr(color='blue')
			g01.attr(rank='same')

			with g01.subgraph(name='cluster_multicast') as g02:
				g02.attr(label='multicast')
				g02.attr('graph', color='purple')
				g02.attr(rank='same')

				with g02.subgraph(name='cluster_'+i.name) as g1:
					g1.attr(label=i.name)
					g1.attr(color='blue')
					g1.attr(rank='same')
#						g1.attr("graph", style="filled")
#					g1.attr("graph", color="lightgray")

					g2 = None
					if len(i.getTcpportlist()) != 0:
						with g1.subgraph(name='cluster_'+i.name+'_tcp') as g2:
							g2.attr(label='TCP')
							g2.attr(color='green')
							g2.attr(rank='same')
							for tport in i.getTcpportlist():
								if tport != '':
									g2.node(i.name+'_tcp_'+str(tport), label=str(tport), shape="box", color='green')

					g2 = None
					if len(i.getUdpportlist()) != 0:
						with g1.subgraph(name='cluster_'+i.name+'_udp') as g2:
							g2.attr(label='UDP')
							g2.attr(color='orange')
							g2.attr(rank='same')
							for uport in i.getUdpportlist():
								if uport != '':
									g2.node(i.name+'_udp_'+str(uport), label=str(uport), shape="box", color='orange')

	for i in globallist:
		g1 = None

		with g.subgraph(name='cluster_global') as g03:
			g03.attr(label='public network')
			g03.attr('graph', color='red')
			g03.attr(rank='same')

			with g03.subgraph(name='cluster_'+i.name) as g1:
				g1.attr(label=i.name)
				g1.attr(color='red')
				g1.attr(rank='same')
#				g1.attr("graph", style="filled")
#				g1.attr("graph", color="lightgray")

				g2 = None
				if len(i.getTcpportlist()) != 0:
					with g1.subgraph(name='cluster_'+i.name+'_tcp') as g2:
						g2.attr(label='TCP')
						g2.attr(color='green')
						g2.attr(rank='same')
						for tport in i.getTcpportlist():
							if tport != '':
								g2.node(i.name+'_tcp_'+str(tport), label=str(tport), shape="box", color='green')

				g2 = None
				if len(i.getUdpportlist()) != 0:
					with g1.subgraph(name='cluster_'+i.name+'_udp') as g2:
						g2.attr(label='UDP')
						g2.attr(color='orange')
						g2.attr(rank='same')
						for uport in i.getUdpportlist():
							if uport != '':
								g2.node(i.name+'_udp_'+str(uport), label=str(uport), shape="box", color='orange')

	# edge
	for f in flowlist:
		if f.ip_protocol == 1:	# icmp
			g.edge('cluster_'+f.getSrc_ipv4address(), 'cluster_'+f.getDst_ipv4address(), ltail='cluster_'+f.getSrc_ipv4address(), lhead='cluster_'+f.getDst_ipv4address(), color='black')
		elif f.ip_protocol == 6:	# tcp
			g.edge(f.getSrc_ipv4address()+'_tcp_'+str(f.getSrc_port()), f.getDst_ipv4address()+'_tcp_'+str(f.getDst_port()), color='green')
		elif f.ip_protocol == 17:	# udp
			g.edge(f.getSrc_ipv4address()+'_udp_'+str(f.getSrc_port()), f.getDst_ipv4address()+'_udp_'+str(f.getDst_port()), color='orange')

	g.view(outputfilename)

def main():

	# Check argument
	argumentCheck()

	if parsetype == "l2":
		pass

	elif parsetype == "ipv4":
		# Parse
		pcapParserIpv4()

		# Make Graph
		makeGraphIpv4()

	elif parsetype == "ipv6":
		pass

if __name__ == '__main__':
	main()
