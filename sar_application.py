from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link, get_host, get_all_host
from ryu.topology import event, switches 
import networkx as nx
import json
import logging
import struct
from webob import Response
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether
from ryu.app.ofctl.api import get_datapath

import datetime
from geometric_based import *

# Packet Classification parameters
SRC_IP = 0
DST_IP = 1
PROTO  = 2
SPORT  = 3
DPORT  = 4
ACTION = 5

# IP lookup parameters
IP     = 0
SUBNET = 1
DPID   = 2

# Topologies
TOPO = 2

class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	_CONTEXTS = {'wsgi': WSGIApplication}
	
	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		wsgi = kwargs['wsgi']
		self.topology_api_app = self
		self.net = nx.DiGraph()
		self.nodes = {}
		self.links = {}
		self.no_of_nodes = 0
		self.no_of_links = 0		
		self.datapaths = []
		self.switch_id = []
		self.mac_to_port = {}
		self.mac_to_dpid = {}
		self.port_to_mac = {}
		self.i=0
		
		# Packet Classification initial parameters
		
		self.classify = {}
		self.classify["r1"] = ["00*","110*","6","*","*","allow"]
		self.classify["r2"] = ["00*","11*","6","*","*","allow"]
		self.classify["r3"] = ["1*","10*","1","*","*","allow"]
		self.classify["r4"] = ["0*","01*","*","*","*","allow"]
		self.classify["r5"] = ["0*","10*","6","*","*","allow"]
		self.classify["r6"] = ["0*","1*","1","*","*","allow"]
		self.classify["r7"] = ["*","00*","*","*","*","allow"]
		self.classify["r8"] = ["*","*","*","*","*","allow"]


		self.counters = {} 
		self.counters["r1"] = 0                           
		self.counters["r2"] = 0                           
		self.counters["r3"] = 0                           
		self.counters["r4"] = 0                           
		self.counters["r5"] = 0                           
		self.counters["r6"] = 0                           
		self.counters["r7"] = 0                           
		self.counters["r8"] = 0                           

		
		if TOPO == 1:			
			self.switch = {}
			self.switch["195.0.0.254"  ] = ["195.0.0.254","8","1"] 
			self.switch["128.128.0.254"] = ["128.128.0.254","12","2"] 
			self.switch["154.128.0.254"] = ["154.128.0.254","16","3"] 

			self.lookup = {}
			self.lookup["195.0.0.1"]   = "195.0.0.254"
			self.lookup["195.0.0.2"]   = "195.0.0.254"
			self.lookup["128.128.0.1"] = "128.128.0.254"
			self.lookup["128.128.0.2"] = "128.128.0.254"
			self.lookup["154.128.0.1"] = "154.128.0.254"
			self.lookup["154.128.0.2"] = "154.128.0.254"
			
			self.ip_to_mac = {}
			self.ip_to_mac["195.0.0.1"]   = "00:00:00:00:00:01"
			self.ip_to_mac["195.0.0.2"]   = "00:00:00:00:00:02"
			self.ip_to_mac["128.128.0.1"] = "00:00:00:00:00:03"
			self.ip_to_mac["128.128.0.2"] = "00:00:00:00:00:04"
			self.ip_to_mac["154.128.0.1"] = "00:00:00:00:00:05"
			self.ip_to_mac["154.128.0.2"] = "00:00:00:00:00:06"
		
		elif TOPO == 2:
			self.switch = {}
			self.switch["195.0.0.254"  ]   = ["195.0.0.254","8","1"] 
			self.switch["128.128.0.254"]   = ["128.128.0.254","12","2"] 
			self.switch["154.128.0.254"]   = ["154.128.0.254","16","3"] 
			self.switch["197.160.0.254"]   = ["197.160.0.254","24","4"]
			self.switch["192.168.0.254"]   = ["192.168.0.254","24","5"]	
			self.switch["192.169.0.254"]  = ["192.169.0.254","24","6"]
			self.switch["192.170.0.254"]  = ["192.170.0.254","24","7"]

			self.lookup = {}
			self.lookup["195.0.0.1"]     = "195.0.0.254"
			self.lookup["195.0.0.2"]     = "195.0.0.254"
			self.lookup["128.128.0.1"]   = "128.128.0.254"
			self.lookup["154.128.0.1"]   = "154.128.0.254"
			self.lookup["197.160.0.1"]   = "197.160.0.254"
			self.lookup["192.168.0.1"]   = "192.168.0.254"
			self.lookup["192.169.0.1"]  = "192.169.0.254"
			self.lookup["192.170.0.1"]  = "192.170.0.254"
			
			self.ip_to_mac = {}
			self.ip_to_mac["195.0.0.1"]     = "00:00:00:00:00:01"
			self.ip_to_mac["195.0.0.2"]     = "00:00:00:00:00:02"
			self.ip_to_mac["128.128.0.1"]   = "00:00:00:00:00:03"
			self.ip_to_mac["154.128.0.1"]   = "00:00:00:00:00:04"
			self.ip_to_mac["197.160.0.1"]   = "00:00:00:00:00:05"
			self.ip_to_mac["192.168.0.1"]   = "00:00:00:00:00:06"
			self.ip_to_mac["192.169.0.1"]  = "00:00:00:00:00:07"
			self.ip_to_mac["192.170.0.1"]  = "00:00:00:00:00:08"			
		
		self.CP = self.table_cross_producting(self.classify)
		self.BM = self.table_bit_map(self.classify)
		rules(self,10)

	def ls(self,obj):
		print("\n".join([x for x in dir(obj) if x[0] != "_"]))
		
	def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
		if opcode == 1:
			targetMac = "00:00:00:00:00:00"
			targetIp = dstIp
		elif opcode == 2:
			targetMac = dstMac
			targetIp = dstIp

		e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
		a = arp.arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
		p = Packet()
		p.add_protocol(e)
		p.add_protocol(a)
		p.serialize()

		actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
		out = datapath.ofproto_parser.OFPPacketOut(
			datapath=datapath,
			buffer_id=0xffffffff,
			in_port=datapath.ofproto.OFPP_CONTROLLER,
			actions=actions,
			data=p.data)
		datapath.send_msg(out)
	
		
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		msg = ev.msg
		self.datapaths.append(msg.datapath)
		self.switch_id.append(msg.datapath_id)
		
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)
		
	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
        
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']		

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
			return
		dst = eth.dst
		src = eth.src
		
		dpid_src = datapath.id
		
		# TOPOLOGY DISCOVERY------------------------------------------
		
		switch_list = get_switch(self.topology_api_app, None)   
		switches=[switch.dp.id for switch in switch_list]		
		self.net.add_nodes_from(switches)
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		# print links
		
		# MAC LEARNING-------------------------------------------------
		
		self.mac_to_port.setdefault(dpid_src, {})
		self.mac_to_port.setdefault(src, {})
		self.port_to_mac.setdefault(dpid_src, {})
		self.mac_to_port[dpid_src][src] = in_port	
		self.mac_to_dpid[src] = dpid_src
		self.port_to_mac[dpid_src][in_port] = src
		self.logger.info("Packet in the controller from switch: %s", dpid_src)
		#print self.mac_to_port
		
		# HANDLE ARP PACKETS--------------------------------------------
		
		if eth.ethertype == ether_types.ETH_TYPE_ARP:
			arp_packet = pkt.get_protocol(arp.arp)
			arp_dst_ip = arp_packet.dst_ip
			arp_src_ip = arp_packet.src_ip
			# self.logger.info("ARP packet from switch: %s source IP: %s destination IP: %s from port: %s", dpid_src, arp_src_ip, arp_dst_ip, in_port)
			# self.logger.info("ARP packet from switch: %s source MAC: %s destination MAC:%s from port: %s", dpid_src, src, dst, in_port)
			
			if arp_dst_ip in self.ip_to_mac:
				if arp_packet.opcode == 1:
					# send arp reply (SAME SUBNET)
					dstIp = arp_src_ip
					srcIp = arp_dst_ip
					dstMac = src
					srcMac = self.ip_to_mac[arp_dst_ip]
					outPort = in_port
					opcode = 2 # arp reply packet
					self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
			else:
				if arp_packet.opcode == 1:
					# send arp reply (GATEWAY)
					dstIp = arp_src_ip
					srcIp = arp_dst_ip
					dstMac = src
					srcMac = self.port_to_mac[dpid_src][in_port]
					outPort = in_port
					opcode = 2 # arp reply packet
					self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
		
		# HANDLE IP PACKETS----------------------------------------------- 	
		
		ip4_pkt = pkt.get_protocol(ipv4.ipv4)
		if ip4_pkt:
			src_ip = ip4_pkt.src
			dst_ip = ip4_pkt.dst
			src_MAC = src
			dst_MAC = dst
			proto  = str(ip4_pkt.proto)
			sport = "0"
			dport = "0" 
			if proto == "6":
				tcp_pkt = pkt.get_protocol(tcp.tcp)
				sport = str(tcp_pkt.src_port)
				dport = str(tcp_pkt.dst_port)
			   
			if proto == "17":
				udp_pkt = pkt.get_protocol(udp.udp)
				sport = str(udp_pkt.src_port)
				dport = str(udp_pkt.dst_port)
				
			self.logger.info("Packet from the switch: %s, source IP: %s, destination IP: %s, From the port: %s, Protocol number: %s", dpid_src, src_ip, dst_ip, in_port, proto)
			
			# PACKET CLASSIFICATION FUNCTION: it returns action: "allow" or "deny"
			action_rule = self.cross_producting_classification(self.CP, src_ip, dst_ip, proto, sport, dport)
			#action_rule = self.bit_map_classification(self.BM, src_ip, dst_ip, proto, sport, dport)
			
			#action_rule = "allow"	
			if action_rule == "allow":		
					
			# IP LOOKUP FUNCTION: it is zero if it didn't find a solution
				self.logger.info("Packet in switch: %s, source MAC: %s, destination MAC: %s, From the port: %s", dpid_src, src, dst, in_port)
				
			# Shortest path computation
			# self.logger.info("Packet in switch: %s, source MAC: %s, destination MAC: %s, From the port: %s", dpid_src, src, dst, in_port)
				
				datapath_dst = get_datapath(self, self.mac_to_dpid[dst_MAC])		
				dpid_dst = datapath_dst.id
				self.logger.info(" --- Destination present on switch: %s", dpid_dst)
					
				# Shortest path computation
				path = nx.shortest_path(self.net,dpid_src,dpid_dst)
				self.logger.info(" --- Shortest path: %s", path)
				
				if len(path) == 1:
					In_Port = self.mac_to_port[dpid_src][src]
					Out_Port = self.mac_to_port[dpid_dst][dst]	
					actions_1 = [datapath.ofproto_parser.OFPActionOutput(Out_Port)]
					actions_2 = [datapath.ofproto_parser.OFPActionOutput(In_Port)]
					match_1 = parser.OFPMatch(in_port=In_Port, eth_dst=dst)
					self.add_flow(datapath, 1, match_1, actions_1)

					actions = [datapath.ofproto_parser.OFPActionOutput(Out_Port)]
					data = msg.data
					pkt = packet.Packet(data)
					eth = pkt.get_protocols(ethernet.ethernet)[0]
					# self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
					pkt.serialize()
					out = datapath.ofproto_parser.OFPPacketOut(
						datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
						actions=actions, data=pkt.data)
					datapath.send_msg(out)
					
					
				elif len(path) == 2:				
					path_port = self.net[path[0]][path[1]]['port']
					actions = [datapath.ofproto_parser.OFPActionOutput(path_port)]
					data = msg.data
					pkt = packet.Packet(data)
					eth = pkt.get_protocols(ethernet.ethernet)[0]
					eth.src = self.ip_to_mac[src_ip] 
					eth.dst = self.ip_to_mac[dst_ip] 
					# self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
					pkt.serialize()
					out = datapath.ofproto_parser.OFPPacketOut(
					datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
						actions=actions, data=pkt.data)
					datapath.send_msg(out)	
					
				elif len(path) > 2:
					# Add flows in the middle of the network path 
					for i in range(1, len(path)-1):							
						In_Port = self.net[path[i]][path[i-1]]['port']
						Out_Port = self.net[path[i]][path[i+1]]['port']
						dp = get_datapath(self, path[i])
						# self.logger.info("Matched OpenFlow Rule = switch: %s, from in port: %s, to out port: %s, source IP: %s, and destination IP: %s", path[i], In_Port, Out_Port, src_ip, dst_ip)
					
						actions_1 = [dp.ofproto_parser.OFPActionOutput(Out_Port)]
						match_1 = parser.OFPMatch(in_port=In_Port, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
						self.add_flow(dp, 1, match_1, actions_1)
					
					path_port = self.net[path[0]][path[1]]['port']
					actions = [datapath.ofproto_parser.OFPActionOutput(path_port)]
					data = msg.data
					pkt = packet.Packet(data)
					eth = pkt.get_protocols(ethernet.ethernet)[0]
					# change the mac address of packet
					eth.src = self.ip_to_mac[src_ip] 
					eth.dst = self.ip_to_mac[dst_ip] 
					# self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
					pkt.serialize()
					out = datapath.ofproto_parser.OFPPacketOut(
					datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
						actions=actions, data=pkt.data)
					datapath.send_msg(out)

	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):
		switch_list = get_switch(self.topology_api_app, None)   
		switches=[switch.dp.id for switch in switch_list]		
		self.net.add_nodes_from(switches)
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)		
		# print "**********List of links"
		# print self.net.edges()
        #for link in links_list:
	    #print link.dst
            #print link.src
            #print "Novo link"
	    #self.no_of_links += 1		

#-------------------------------------------------------------------------------------------------------
	
	#create cross-producting table
	def table_cross_producting(self, classify):
		self.logger.info("--- cross-producting table ---\n") 
		CP = []
		
		for i in range(5):

			#for destination ip and source ip fields
			if(i == 0 or i == 1):
				f = []
				
				#calculate ranges
				for j in self.classify:
					f.append(self.classify[j][i])
				f.sort(key=len)
				f_len = len(max(f, key=len))
				R = []
				for j in range(len(f)):
					s = f[j][0:-1]
					s1 = s + (f_len-len(s)) * "0"
					s2 = s + (f_len-len(s)) * "1"
					if (j == 0):
						R.append([s1,s2])

					while (s1 in [value[0] for value in R] and s2 not in [value[1] for value in R]):
						ind = ([value[0] for value in R].index(s1))
						end =  ([value[1] for value in R][ind])  
						start = bin(int(s2, 2) + int('1',2)).replace('0b','')
						start = (f_len-len(start)) * "0"+ start
						R.pop(ind)
						R.append([s1,s2])
						R.append([start,end])

					while (s1 not in [value[0] for value in R] and s2 in [value[1] for value in R]):
						ind = ([value[1] for value in R].index(s2))
						start =  ([value[0] for value in R][ind])  
						end = bin(int(s1, 2) - int('1',2)).replace('0b','')
						end = (f_len-len(end)) * "0"+ end
						R.pop(ind)
						R.append([s1,s2])
						R.append([start,end])

					while (s1 not in [value[0] for value in R] and s2 not in [value[1] for value in R]):
						R.append([s1,s2])

				#assign rules to right ranges
				T = {}
				for key, value in sorted(self.classify.items()):
					v = value[i][0:-1]
					x = len(v)
					for j in range(len(R)):
						if(R[j][0][0:x] <= v and v <= R[j][1][0:x]):
							new_key = R[j][0] + "-" + R[j][1]
							if new_key in T:
								T[new_key].append(key)
							else:
								T[new_key] = [key]
				
				self.logger.info("T %s: %s\n" % (i,T))
				CP.append(T)

			#for other fields
			else:
				T = {}
				for key, value in sorted(self.classify.items()):
					v = value[i]
					if v in T:
						T[v].append(key)
					else:
						T[v] = [key]
			
				self.logger.info("T %s: %s\n" % (i,T))
				CP.append(T)
		
		self.logger.info("Cross-producting: %s \n" % (CP))
		return CP


	#find matching rule and action according to cross-producting 
	def cross_producting_classification(self, cp, src_ip, dst_ip, proto, sport, dport):
		action = "deny"
		self.logger.info("--- cross-producting classification ---") 

		match_rules = []
		print(src_ip, dst_ip, proto, sport, dport)

		for i in range(5):
			temp = []	

			#find matching rules for ip fields
			if(i <= 1):
				if(i == 0 ):
					ip = src_ip
				else:
					ip = dst_ip
				pre = ''.join([ bin(int(x))[2:].rjust(8,'0') for x in ip.split('.')])
				for key, values in cp[i].items():
					m = key.index('-')
					start = key[:m]
					end = key[(m+1):]
					bin_len = len(start)
					bin_pre = pre[0:bin_len]
					if(start <= bin_pre and bin_pre <= end):
						for value in values:
							temp.append(value)	
			
			#find matching rules for other fields
			else:
				if(i == 2):
					value = proto
				elif(i == 3):
					value = sport
				else:
					value = dport
				for key, values in cp[i].items():
					if(key == value or key =="*"):	
						for value in values:
							temp.append(value)
			
			#compare matching rules for each fields
			if(i == 0):
				match_rules = temp
			else:
				match_rules = [x for x in match_rules if x in temp]

		#find highest priority rule
		if(len(match_rules) != 0):	
			match_rules.sort()
			self.logger.info(" Matched rules : %s" % (match_rules))
			rule = match_rules[0]
			match = self.classify[rule]
			action = match[ACTION]
			self.counters[rule] = self.counters[rule] + 1
			self.logger.info(" --- Packet matched rule %s. Action is %s" % (rule, match[ACTION]))
		return action
	


	#create bit-map table
	def table_bit_map(self, classify):
		self.logger.info("--- bit_map table ---\n") 
		BM = []

		for i in range(5):
			T = {}
			f =[]
			
			for key, value in sorted(self.classify.items()):

				#for destination ip and source ip fields
				if(i==0 or i==1):
					f =[]
					x = []

					for j in self.classify:
						f.append(self.classify[j][i])
					f_len = len(max(f, key=len)) -1
					v = value[i][0:-1]

					#calculate intervals and their bitmaps
					for k in range (2**f_len):
						temp = bin(int('0',2) + k*int('1',2)).replace('0b','')
						x.append((f_len-len(temp)) * "0"+ temp)
						if(x[k][0:len(v)] == v):
							if x[k] in T:
								T[x[k]].append(1)
							else:
								T[x[k]] = [1]
						else:
							if x[k] in T:
								T[x[k]].append(0)
							else:
								T[x[k]] = [0]
				
				#for other fields
				else:
					x = []
					f =[]
					for j in self.classify:
						if self.classify[j][i] not in f:
							f.append(self.classify[j][i])
					f_len = len(f)
					v = value[i]

					#calculate intervals and their bitmaps
					for k in range (f_len):
						if(f[k] == v):
							if f[k] in T:
								T[f[k]].append(1)
							else:
								T[f[k]] = [1]
						else:
							if f[k] in T:
								T[f[k]].append(0)
							else:
								T[f[k]] = [0]

			self.logger.info("T %s: %s\n" % (i,T))
			BM.append(T)		

		self.logger.info("Bit-map: %s \n" % (BM))
		return BM



	#find matching rule and action according to bit-map 
	def bit_map_classification(self, bm, src_ip, dst_ip, proto, sport, dport):
		action = "deny"
		self.logger.info("--- bit-map classification ---") 

		for i in range(5):

			#find matching rules for ip fields
			if(i <= 1):
				temp = []		
				if(i == 0 ):
					ip = src_ip
				else:
					ip = dst_ip
				pre = ''.join([ bin(int(x))[2:].rjust(8,'0') for x in ip.split('.')])
				for key, values in bm[i].items():
					bin_len = len(key)
					bin_pre = pre[0:bin_len]
					if(bin_pre == key):
						temp = values

			#find matching rules for other fields
			else:
				if(i == 2):
					value = proto
				elif(i == 3):
					value = sport
				else:
					value = dport
				temp = [0]*len(self.classify)
				for key, values in bm[i].items():
					if(key == value or key == "*"):	
						temp = [(a or b) for a, b in zip(temp, values)]
			
			#compare matching rules for each fields
			if(i == 0):
				match_rules = temp
			else:
				match_rules = [a * b for a, b in zip(temp, match_rules)]

		#find highest priority rule
		if 1 in match_rules:
			rule = match_rules.index(1)
			rule = sorted(self.classify.keys())[rule]
			match = self.classify[rule]
			action = match[ACTION]
			self.counters[rule] = self.counters[rule] + 1
			self.logger.info(" --- Packet matched rule %s. Action is %s" % (rule, match[ACTION]))
		print(match_rules)
		return action
	
app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')
app_manager.require_app('ryu.app.gui_topology.gui_topology')		