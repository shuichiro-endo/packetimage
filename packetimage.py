# -*- coding: utf-8 -*-
#!/bin/python

import argparse
import dpkt
import getopt
import ipaddress
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
	def __init__(self, name, macaddress, vlanid, ipv4address, ipv6address, tcpport, udpport):
		self.name = name
		self.macaddress = macaddress
		self.ipv4address = ipv4address
		self.ipv6address = ipv6address
#		self.macaddresslist = []
		self.vlanidlist = []
		if vlanid != '':
			self.appendVlanidlist(vlanid)
		self.tcpportlist = []
		if tcpport != '':
			self.appendTcpportlist(tcpport)
		self.udpportlist = []
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

	def setIpv6address(self, ipv6address):
		self.ipv6address = ipv6address

	def getIpv6address(self):
		return self.ipv6address

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

	def appendVlanidlist(self, vlanid):
		if not self.searchVlanidlist(vlanid):
			self.vlanidlist.append(vlanid)

	def getVlanidlist(self):
		return self.vlanidlist

	def searchVlanidlist(self, vlanid):
		for v in self.vlanidlist:
			if v == vlanid:
				return True
		return False


class Flowl2:
	def __init__(self, src_macaddress, dst_macaddress, type, vlanidlist):
		self.src_macaddress = src_macaddress
		self.dst_macaddress = dst_macaddress
		self.type = type
		self.vlanidlist = vlanidlist

	def setSrc_macaddress(self, src_macaddress):
		self.src_macaddress = src_macaddress

	def getSrc_macaddress(self):
		return self.src_macaddress

	def setDst_macaddress(self, dst_macaddress):
		self.dst_macaddress = dst_macaddress

	def getDst_macaddress(self):
		return self.dst_macaddress

	def setType(self, type):
		self.type = type

	def getType(self):
		return self.type

	def appendVlanidlist(self, vlanid):
		if not self.searchVlanidlist(vlanid):
			self.vlanidlist.append(vlanid)

	def getVlanidlist(self):
		return self.vlanidlist

	def searchVlanidlist(self, vlanid):
		for v in self.vlanidlist:
			if v == vlanid:
				return True
		return False



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


class Flowipv6:
	def __init__(self, protocol, src_ipv6address, src_port, dst_ipv6address, dst_port):
		self.protocol = protocol
		self.src_ipv6address = src_ipv6address
		self.src_port = src_port
		self.dst_ipv6address = dst_ipv6address
		self.dst_port = dst_port

	def setProtocol(self, protocol):
		self.protocol = protocol

	def getProtocol(self):
		return self.protocol

	def setSrc_ipv6address(self, src_ipv6address):
		self.src_ipv6address = src_ipv6address

	def getSrc_ipv6address(self):
		return self.src_ipv6address

	def setSrc_port(self, src_port):
		self.src_port = src_port

	def getSrc_port(self):
		return self.src_port

	def setDst_ipv6address(self, dst_ipv6address):
		self.dst_ipv6address = dst_ipv6address

	def getDst_ipv6address(self):
		return self.dst_ipv6address

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

	usage = 'python %s parsetype inputfile outputfile [--help]'%os.path.basename(__file__)

	argparser = argparse.ArgumentParser(usage=usage)
	argparser.add_argument('parsetype', type=str, help='l2 or ipv4 or ipv6')
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


def mac_addr(address):
	return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def checkMulticastMacaddress(macaddress):
	mac1 = macaddress.split(":")[0].lower()
	mac2 = macaddress.split(":")[1].lower()
	mac3 = macaddress.split(":")[2].lower()
	mac4 = macaddress.split(":")[3].lower()
	mac4_dec = int(mac4, 16)
	mac5 = macaddress.split(":")[4].lower()
	mac6 = macaddress.split(":")[5].lower()

	if macaddress.lower() == 'ff:ff:ff:ff:ff:ff':
		return True
	elif macaddress.lower() == '01:00:0c:cc:cc:cc':	# CDP/VTP
		return True
	elif macaddress.lower() == '01:00:0c:cc:cc:cd':	# PVSTP
		return True
	elif macaddress.lower() == '01:80:c2:00:00:00':	# 802.1D STP/RSTP/MSTP
		return True
	elif macaddress.lower() == '01:80:c2:00:00:01':	# 802.3X PAUSE
		return True
	elif macaddress.lower() == '01:80:c2:00:00:02':	# 802.3ah LACP/EFM OAM
		return True
	elif macaddress.lower() == '01:80:c2:00:00:03':	# 802.1x EAP
		return True
	elif macaddress.lower() == '01:80:c2:00:00:0e':	# LLDP
		return True
	elif macaddress.lower() == '01:80:c2:00:00:10':	# Switch
		return True
	elif macaddress.lower() == '01:80:c2:00:00:14':	# IS-IS Level1
		return True
	elif macaddress.lower() == '01:80:c2:00:00:15':	# IS-IS Level2
		return True
	elif macaddress.lower().startswith('01:80:c2:00:00:3'):	# 802.1ag CFM(L2ping/L2Ttraceroute)
		return True
	elif macaddress.lower().startswith('01:00:5e') and mac4_dec <= 127:	# IPv4 multicast 01:00:5E(00000001 00000000 01011110 0)
		return True
	elif macaddress.lower().startswith('33:33'):	# IPv6 multicast 33:33
		return True

	return False


def checkMulticastIpv4address(address):
	if address == '255.255.255.255' or ipaddress.IPv4Address(address.decode('utf-8')).is_multicast:
		return True
	return False


def checkPrivateIpv4address(address):
	if ipaddress.IPv4Address(address.decode('utf-8')).is_private:
		return True
	return False


def checkLinkLocalUnicastIpv6address(address):
	if ipaddress.IPv6Address(address.decode('utf-8')).is_link_local:
		return True
	return False


def checkMulticastIpv6address(address):
	if ipaddress.IPv6Address(address.decode('utf-8')).is_multicast:
		return True
	return False


def checkUniqueLocalUnicastIpv6address(address):
	if ipaddress.IPv6Address(address.decode('utf-8')).is_private:
		return True
	return False


def pcapParserL2():
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
			print 'Fail parse frame no:', packetcount, ' skipped.'
			continue

		src_macaddress = mac_addr(eth.src)
		dst_macaddress = mac_addr(eth.dst)
		t = eth.type

		# 802.1Q or 802.1AD or legacy QinQ
		if t == dpkt.ethernet.ETH_TYPE_8021Q or t == dpkt.ethernet.ETH_TYPE_8021AD or t == dpkt.ethernet.ETH_TYPE_QINQ1 or t == dpkt.ethernet.ETH_TYPE_QINQ2:
			if type(eth.data) == dpkt.arp.ARP:
				t = dpkt.ethernet.ETH_TYPE_ARP
			elif type(eth.data) == dpkt.ip.IP:
				t = dpkt.ethernet.ETH_TYPE_IP
			elif type(eth.data) == dpkt.aoe.AOE:
				t = dpkt.ethernet.ETH_TYPE_AOE
			elif type(eth.data) == dpkt.cdp.CDP:
				t = dpkt.ethernet.ETH_TYPE_CDP
			elif type(eth.data) == dpkt.dtp.DTP:
				t = dpkt.ethernet.ETH_TYPE_DTP
			elif type(eth.data) == dpkt.ipx.IPX:
				t = dpkt.ethernet.ETH_TYPE_IPX
			elif type(eth.data) == dpkt.ip6.IP6:
				t = dpkt.ethernet.ETH_TYPE_IP6
			elif type(eth.data) == dpkt.ppp.PPP:
				t = dpkt.ethernet.ETH_TYPE_PPP
			elif type(eth.data) == dpkt.pppoe.PPPoE:
				t = dpkt.ethernet.ETH_TYPE_PPPoE

		vlanidlist = []

		if hasattr(eth, 'vlan_tags'):
			for v in eth.vlan_tags:
#				print "Packet No." + str(packetcount) + ", vlan id = " + str(v.id)
				vlanidlist.append(v.id)
		else:	# untag
			vlanidlist.append('untag')


		src_interface = None
		dst_interface = None

		for i in interfacelist:
			if i.getMacaddress() == src_macaddress:
				src_interface = i
			elif i.getMacaddress() == dst_macaddress:
				dst_interface = i

		# src
		if src_interface == None:
			src_interface = Interface(
										src_macaddress,		# name
										src_macaddress, 	# macaddress
										'',					# vlan
										'',					# ipv4address
										'',					# ipv6address
										'',					# tcpport
										''					# udpport
										)
			# vlanid
			for vid in vlanidlist:
				src_interface.appendVlanidlist(vid)
			# append
			interfacelist.append(src_interface)
		else:
			# vlanid
			for vid in vlanidlist:
				src_interface.appendVlanidlist(vid)

		# dst
		if dst_interface == None:
			dst_interface = Interface(
										dst_macaddress,		# name
										dst_macaddress,		# macaddress
										'',					# vlan
										'',					# ipv4address
										'',					# ipv6address
										'',					# tcpport
										''					# udpport
										)
			# vlanid
			for vid in vlanidlist:
				dst_interface.appendVlanidlist(vid)
			# append
			interfacelist.append(dst_interface)
		else:
			# vlanid
			for vid in vlanidlist:
				dst_interface.appendVlanidlist(vid)


		# flow
		flag = False
		for f in flowlist:
			if f.getSrc_macaddress() == src_macaddress and f.getDst_macaddress() == dst_macaddress and f.getType() == t:
				flag = True
				break
		if flag == False:
			flow = Flowl2(src_macaddress, dst_macaddress, t, vlanidlist)
			flowlist.append(flow)
		else:
			for vid in vlanidlist:
				f.appendVlanidlist(vid)


def makeGraphL2():
	privatelist = []
	multicastlist = []

	g = Digraph(format='png', engine='fdp')
	g.attr(compound='true')
	g.attr(rankdir='LR')
	g.attr(rank='same')

	# node
	for i in interfacelist:
		if checkMulticastMacaddress(i.name): # multicast macaddress
			multicastlist.append(i)
		else:
			privatelist.append(i)

	g1 = None
	with g.subgraph(name='cluster_private') as g1:
		g1.attr(label='private network')
		g1.attr(color='blue')
		g1.attr(rank='same')

		for i in privatelist:
			makeGraphL2_vlanid(g1, i)

		g2 = None
		with g1.subgraph(name='cluster_multicast') as g2:
			g2.attr(label='multicast')
			g2.attr('graph', color='purple')
			g2.attr(rank='same')

			for i in multicastlist:
				makeGraphL2_vlanid(g2, i)

	# edge
	for f in flowlist:
		if f.type == dpkt.ethernet.ETH_TYPE_EDP:	# EDP
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='gray')
		elif f.type == dpkt.ethernet.ETH_TYPE_PUP:	# PUP
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='chartreuse')
		elif f.type == dpkt.ethernet.ETH_TYPE_IP:	# IPv4
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='red')
		elif f.type == dpkt.ethernet.ETH_TYPE_ARP:	# ARP
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='greenyellow')
		elif f.type == dpkt.ethernet.ETH_TYPE_AOE:	# AOE
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='dodgerblue')
		elif f.type == dpkt.ethernet.ETH_TYPE_CDP:	# CDP
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='aquamarine')
		elif f.type == dpkt.ethernet.ETH_TYPE_DTP:	# DTP
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='deeppink')
		elif f.type == dpkt.ethernet.ETH_TYPE_REVARP:	# Reverse ARP
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='darkseagreen')
		elif f.type == dpkt.ethernet.ETH_TYPE_IPX:	# IPX
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='darkgreen')
		elif f.type == dpkt.ethernet.ETH_TYPE_IP6:	# IPv6
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='cyan')
		elif f.type == dpkt.ethernet.ETH_TYPE_PPP:	# PPP
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='darkkhaki')
		elif f.type == dpkt.ethernet.ETH_TYPE_MPLS:	# MPLS
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='indigo')
		elif f.type == dpkt.ethernet.ETH_TYPE_MPLS_MCAST:	# MPLS Multicast
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='brown')
		elif f.type == dpkt.ethernet.ETH_TYPE_PPPoE_DISC:	# PPPoE Discovery Stage
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='slateblue')
		elif f.type == dpkt.ethernet.ETH_TYPE_PPPoE:	# PPPoE
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='lightsalmon')
		elif f.type == dpkt.ethernet.ETH_TYPE_LLDP:	# LLDP
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='coral')
		elif f.type == dpkt.ethernet.ETH_TYPE_TEB:	# TEB
			for vid in f.getVlanidlist():
				g.edge(f.getSrc_macaddress().replace(':', '-')+'_vlanid_'+str(vid), f.getDst_macaddress().replace(':', '-')+'_vlanid_'+str(vid), color='chocolate')

	g.view(outputfilename)


def makeGraphL2_vlanid(g, i):
	g1 = None
	with g.subgraph(name='cluster_'+i.name.replace(':', '-')) as g1:
		g1.attr(label=i.name)
		g1.attr(color='black')
		g1.attr(rank='same')

		g2 = None
		if len(i.getVlanidlist()) != 0:
			with g1.subgraph(name='cluster_'+i.name.replace(':', '-')+'_vlan') as g2:
				g2.attr(label='vlan')
				g2.attr(color='orange')
				g2.attr(rank='same')

				for vid in i.getVlanidlist():
					if vid != '':
						g2.node(i.name.replace(':', '-')+'_vlanid_'+str(vid), label=str(vid), shape="box", color='orange')


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
			print 'Fail parse frame no:', packetcount, ' skipped.'
			continue

		src_macaddress = mac_addr(eth.src)
		dst_macaddress = mac_addr(eth.dst)

		if type(eth.data) == dpkt.ip.IP:

			ip = eth.data
			ip_protocol = ip.p
			src_ipaddress = inet_to_str(ip.src)
			dst_ipaddress = inet_to_str(ip.dst)

			tcp = ''
			src_tcpport = ''
			dst_tcpport = ''

			udp = ''
			src_udpport = ''
			dst_udpport = ''

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
			if src_interface == None:
				src_interface = Interface(
											src_ipaddress,		# name
											'', 				# macaddress
											'',					# vlan
											src_ipaddress,		# ipv4address
											'',					# ipv6address
											src_tcpport,		# tcpport
											src_udpport			# udpport
											)

				# append
				interfacelist.append(src_interface)

			else:
				# tcpport
				src_interface.appendTcpportlist(src_tcpport)

				# udpport
				src_interface.appendUdpportlist(src_udpport)

			# dst
			if dst_interface == None:
				dst_interface = Interface(
											dst_ipaddress,		# name
											'', 				# macaddress
											'',					# vlan
											dst_ipaddress,		# ipv4address
											'',					# ipv6address
											dst_tcpport,		# tcpport
											dst_udpport			# udpport
											)
				# append
				interfacelist.append(dst_interface)

			else:
				# tcpport
				dst_interface.appendTcpportlist(dst_tcpport)

				# udpport
				dst_interface.appendUdpportlist(dst_udpport)

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

	g1 = None
	with g.subgraph(name='cluster_global') as g1:
		g1.attr(label='public network')
		g1.attr(color='red')
		g1.attr(rank='same')

		for i in globallist:
			makeGraphIpv4_tcp_udp(g1, i)

		g2 = None
		with g1.subgraph(name='cluster_private') as g2:
			g2.attr(label='private network')
			g2.attr(color='blue')
			g2.attr(rank='same')

			for i in privatelist:
				makeGraphIpv4_tcp_udp(g2, i)

			g3 = None
			with g2.subgraph(name='cluster_multicast') as g3:
				g3.attr(label='multicast')
				g3.attr(color='purple')
				g3.attr(rank='same')

				for i in multicastlist:
					makeGraphIpv4_tcp_udp(g3, i)

	# edge
	for f in flowlist:
		if f.getIp_protocol() == 1:	# icmp
			g.edge('cluster_'+f.getSrc_ipv4address(), 'cluster_'+f.getDst_ipv4address(), ltail='cluster_'+f.getSrc_ipv4address(), lhead='cluster_'+f.getDst_ipv4address(), color='black')
		elif f.getIp_protocol() == 6:	# tcp
			g.edge(f.getSrc_ipv4address()+'_tcp_'+str(f.getSrc_port()), f.getDst_ipv4address()+'_tcp_'+str(f.getDst_port()), color='green')
		elif f.getIp_protocol() == 17:	# udp
			g.edge(f.getSrc_ipv4address()+'_udp_'+str(f.getSrc_port()), f.getDst_ipv4address()+'_udp_'+str(f.getDst_port()), color='orange')

	g.view(outputfilename)



def makeGraphIpv4_tcp_udp(g, i):

	g1 = None
	with g.subgraph(name='cluster_'+i.name) as g1:
		g1.attr(label=i.name)
		g1.attr(color='black')
		g1.attr(rank='same')

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


def pcapParserIpv6():
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
			print 'Fail parse frame no:', packetcount, ' skipped.'
			continue

		src_macaddress = mac_addr(eth.src)
		dst_macaddress = mac_addr(eth.dst)

		if type(eth.data) == dpkt.ip6.IP6:

			ipv6 = eth.data
			ipv6_nextheader = ipv6.nxt
			src_ipv6address = inet_to_str(ipv6.src)
			dst_ipv6address = inet_to_str(ipv6.dst)
			protocol = ''

			tcp = ''
			src_tcpport = ''
			dst_tcpport = ''

			udp = ''
			src_udpport = ''
			dst_udpport = ''

			if type(ipv6.data) == dpkt.icmp6.ICMP6:
				protocol = 'icmp6'

			elif type(ipv6.data) == dpkt.tcp.TCP:
				tcp = ipv6.data
				src_tcpport = tcp.sport
				dst_tcpport = tcp.dport
				protocol = 'tcp'

			elif type(ipv6.data) == dpkt.udp.UDP:
				udp = ipv6.data
				src_udpport = udp.sport
				dst_udpport = udp.dport
				protocol = 'udp'

			src_interface = None
			dst_interface = None

			for i in interfacelist:
				if i.getIpv6address() == src_ipv6address:
					src_interface = i
				elif i.getIpv6address() == dst_ipv6address:
					dst_interface = i

			# src
			if src_interface == None:
				src_interface = Interface(
											src_ipv6address,	# name
											'', 				# macaddress
											'',					# vlan
											'',					# ipv4address
											src_ipv6address,	# ipv6address
											src_tcpport,		# tcpport
											src_udpport			# udpport
											)

				# append
				interfacelist.append(src_interface)

			else:
				# tcpport
				src_interface.appendTcpportlist(src_tcpport)

				# udpport
				src_interface.appendUdpportlist(src_udpport)

			# dst
			if dst_interface == None:
				dst_interface = Interface(
											dst_ipv6address,	# name
											'', 				# macaddress
											'',					# vlan
											'',					# ipv4address
											dst_ipv6address,	# ipv6address
											dst_tcpport,		# tcpport
											dst_udpport			# udpport
											)
				# append
				interfacelist.append(dst_interface)

			else:
				# tcpport
				dst_interface.appendTcpportlist(dst_tcpport)

				# udpport
				dst_interface.appendUdpportlist(dst_udpport)


			# flow
			flag = False

			for f in flowlist:
				if protocol == 'icmp6':	# icmp6
					if f.getProtocol() == protocol and f.getSrc_ipv6address() == src_ipv6address and f.getDst_ipv6address() == dst_ipv6address:
						flag = True
				elif protocol == 'tcp':	# tcp
					if f.getProtocol() == protocol and f.getSrc_ipv6address() == src_ipv6address and f.getSrc_port() == src_tcpport and f.getDst_ipv6address() == dst_ipv6address and f.getDst_port() == dst_tcpport:
						flag = True
				elif protocol == 'udp':	# udp
					if f.getProtocol() == protocol and f.getSrc_ipv6address() == src_ipv6address and f.getSrc_port() == src_udpport and f.getDst_ipv6address() == dst_ipv6address and f.getDst_port() == dst_udpport:
						flag = True

			if flag == False:
				if protocol == 'icmp6':	# icmp6
					flow = Flowipv6(protocol, src_ipv6address, '', dst_ipv6address, '')
					flowlist.append(flow)
				elif protocol == 'tcp':	# tcp
					flow = Flowipv6(protocol, src_ipv6address, src_tcpport, dst_ipv6address, dst_tcpport)
					flowlist.append(flow)
				elif protocol == 'udp':	# udp
					flow = Flowipv6(protocol, src_ipv6address, src_udpport, dst_ipv6address, dst_udpport)
					flowlist.append(flow)


def makeGraphIpv6():
	linklocallist = []
	uniquelocallist = []
	globallist = []
	multicastlist_interface = []
	multicastlist_link = []
	multicastlist_admin = []
	multicastlist_site = []
	multicastlist_organization = []
	multicastlist_global = []

	g = Digraph(format='png', engine='fdp')
	g.attr(compound='true')
	g.attr(rankdir='LR')
	g.attr(rank='same')

	# node
	for i in interfacelist:
		if checkLinkLocalUnicastIpv6address(i.name):	# link local unicast address
			linklocallist.append(i)

		elif checkUniqueLocalUnicastIpv6address(i.name):	# unique local unicast address
			uniquelocallist.append(i)

		elif checkMulticastIpv6address(i.name):	# multicast address
			ipv6_1 = i.name.split(':')[0]

			if ipv6_1.endswith('1'):	# interface local
				multicastlist_interface.append(i)
			elif ipv6_1.endswith('2'):	# link local
				multicastlist_link.append(i)
			elif ipv6_1.endswith('4'):	# admin local
				multicastlist_admin.append(i)
			elif ipv6_1.endswith('5'):	# site local
				multicastlist_site.append(i)
			elif ipv6_1.endswith('8'):	# organization local
				multicastlist_organization.append(i)
			elif ipv6_1.endswith('E'):	# global
				multicastlist_global.append(i)
			else:
				pass

		else:	# global unicast address
			globallist.append(i)


	g1 = None
	with g.subgraph(name='cluster_global') as g1:
		g1.attr(label='public network')
		g1.attr('graph', color='red')
		g1.attr(rank='same')

		for i in globallist:
			makeGraphIpv6_tcp_udp(g1, i)

		g2 = None
		with g1.subgraph(name='cluster_multicast_global') as g2:
			g2.attr(label='multicast_global')
			g2.attr(color='purple')
			g2.attr(rank='same')

			for i in multicastlist_global:
				makeGraphIpv6_tcp_udp(g2, i)

		g2 = None
		with g1.subgraph(name='cluster_private') as g2:
			g2.attr(label='private network')
			g2.attr(color='blue')
			g2.attr(rank='same')

			g3 = None
			with g2.subgraph(name='cluster_uniquelocal') as g3:
				g3.attr(label='unique local')
				g3.attr(color='yellow')
				g3.attr(rank='same')

				for i in uniquelocallist:
					makeGraphIpv6_tcp_udp(g3, i)

				g4 = None
				with g3.subgraph(name='cluster_multicast_admin') as g4:
					g4.attr(label='multicast_adminlocal')
					g4.attr(color='purple')
					g4.attr(rank='same')

					for i in multicastlist_admin:
						makeGraphIpv6_tcp_udp(g4, i)

				g4 = None
				with g3.subgraph(name='cluster_multicast_site') as g4:
					g4.attr(label='multicast_sitelocal')
					g4.attr(color='purple')
					g4.attr(rank='same')

					for i in multicastlist_site:
						makeGraphIpv6_tcp_udp(g4, i)

				g4 = None
				with g3.subgraph(name='cluster_multicast_organization') as g4:
					g4.attr(label='multicast_organizationlocal')
					g4.attr(color='purple')
					g4.attr(rank='same')

					for i in multicastlist_organization:
						makeGraphIpv6_tcp_udp(g4, i)

				g4 = None
				with g3.subgraph(name='cluster_linklocal') as g4:
					g4.attr(label='link local')
					g4.attr(color='cyan')
					g4.attr(rank='same')

					for i in linklocallist:
						makeGraphIpv6_tcp_udp(g4, i)

					g5 = None
					with g4.subgraph(name='cluster_multicast_link') as g5:
						g5.attr(label='multicast_linklocal')
						g5.attr(color='purple')
						g5.attr(rank='same')

						for i in multicastlist_link:
							makeGraphIpv6_tcp_udp(g5, i)

					g5 = None
					with g4.subgraph(name='cluster_multicast_interface') as g5:
						g5.attr(label='multicast_interfacelocal')
						g5.attr(color='purple')
						g5.attr(rank='same')

						for i in multicastlist_interface:
							makeGraphIpv6_tcp_udp(g5, i)

	# edge
	for f in flowlist:
		if f.getProtocol() == 'icmp6':	# icmp
			g.edge('cluster_'+f.getSrc_ipv6address().replace(':', '-'), 'cluster_'+f.getDst_ipv6address().replace(':', '-'), ltail='cluster_'+f.getSrc_ipv6address().replace(':', '-'), lhead='cluster_'+f.getDst_ipv6address().replace(':', '-'), color='black')
		elif f.getProtocol() == 'tcp':	# tcp
			g.edge(f.getSrc_ipv6address().replace(':', '-')+'_tcp_'+str(f.getSrc_port()), f.getDst_ipv6address().replace(':', '-')+'_tcp_'+str(f.getDst_port()), color='green')
		elif f.getProtocol() == 'udp':	# udp
			g.edge(f.getSrc_ipv6address().replace(':', '-')+'_udp_'+str(f.getSrc_port()), f.getDst_ipv6address().replace(':', '-')+'_udp_'+str(f.getDst_port()), color='orange')

	g.view(outputfilename)


def makeGraphIpv6_tcp_udp(g, i):
	g1 = None
	with g.subgraph(name='cluster_'+i.name.replace(':', '-')) as g1:
		g1.attr(label=i.name)
		g1.attr(color='black')
		g1.attr(rank='same')

		g2 = None
		if len(i.getTcpportlist()) != 0:
			with g1.subgraph(name='cluster_'+i.name.replace(':', '-')+'_tcp') as g2:
				g2.attr(label='TCP')
				g2.attr(color='green')
				g2.attr(rank='same')
				for tport in i.getTcpportlist():
					if tport != '':
						g2.node(i.name.replace(':', '-')+'_tcp_'+str(tport), label=str(tport), shape="box", color='green')

		g2 = None
		if len(i.getUdpportlist()) != 0:
			with g1.subgraph(name='cluster_'+i.name.replace(':', '-')+'_udp') as g2:
				g2.attr(label='UDP')
				g2.attr(color='orange')
				g2.attr(rank='same')
				for uport in i.getUdpportlist():
					if uport != '':
						g2.node(i.name.replace(':', '-')+'_udp_'+str(uport), label=str(uport), shape="box", color='orange')


def main():

	# Check argument
	argumentCheck()

	if parsetype == "l2":
		# Parse
		pcapParserL2()

		# Make Graph
		makeGraphL2()

	elif parsetype == "ipv4":
		# Parse
		pcapParserIpv4()

		# Make Graph
		makeGraphIpv4()

	elif parsetype == "ipv6":
		# Parse
		pcapParserIpv6()

		# Make Graph
		makeGraphIpv6()


if __name__ == '__main__':
	main()
