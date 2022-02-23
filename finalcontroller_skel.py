# Final Skeleton
#
# Hints/Reminders from Lab 3:
#
# To check the source and destination of an IP packet, you can use
# the header information... For example:
#
# ip_header = packet.find('ipv4')
#
# if ip_header.srcip == "1.1.1.1":
#   print "Packet is from 1.1.1.1"
#
# Important Note: the "is" comparison DOES NOT work for IP address
# comparisons in this way. You must use ==.
# 
# To send an OpenFlow Message telling a switch to send packets out a
# port, do the following, replacing <PORT> with the port number the 
# switch should send the packets out:
#
#    msg = of.ofp_flow_mod()
#    msg.match = of.ofp_match.from_packet(packet)
#    msg.idle_timeout = 30
#    msg.hard_timeout = 30
#
#    msg.actions.append(of.ofp_action_output(port = <PORT>))
#    msg.data = packet_in
#    self.connection.send(msg)
#
# To drop packets, simply omit the action.
#

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Final (object):
	"""
	A Firewall object is created for each switch that connects.
	A Connection object for that switch is passed to the __init__ function.
	"""
	def __init__ (self, connection):
		# Keep track of the connection to the switch so that we can
		# send it messages!
		self.connection = connection

		# This binds our PacketIn event listener
		connection.addListeners(self)

	def do_final (self, packet, packet_in, port_on_switch, switch_id):
		# This is where you'll put your code. The following modifications have 
		# been made from Lab 3:
		#   - port_on_switch: represents the port that the packet was received on.
		#   - switch_id represents the id of the switch that received the packet.
		#      (for example, s1 would have switch_id == 1, s2 would have switch_id == 2, etc...)
		# You should use these to determine where a packet came from. To figure out where a packet 
		# is going, you can use the IP header information.

		ip = packet.find('ipv4')
		icmp = packet.find('icmp')
		
		#If ip traffic then specify the ports
		if ip is not None:
			#For Switch 1 on Floor 1
			if switch_id == 1:
				if ip.dstip == '10.1.1.10':
					self.forwarding(packet, packet_in, 1)
				elif ip.dstip == '10.1.2.20':
					self.forwarding(packet, packet_in, 2)
				else:
					self.forwarding(packet, packet_in, 3)
			#For Switch 2 on Floor 1
			elif switch_id == 2:
				if ip.dstip == '10.1.3.30':
					self.forwarding(packet, packet_in, 1)
				elif ip.dstip == '10.1.4.40':
					self.forwarding(packet, packet_in, 2)
				else:
					self.forwarding(packet, packet_in, 3)
			#For Switch 1 on Floor 2
			elif switch_id == 3:
				if ip.dstip == '10.2.5.50':
					self.forwarding(packet, packet_in, 1)
				elif ip.dstip == '10.2.6.60':
					self.forwarding(packet, packet_in, 2)
				else:
					self.forwarding(packet, packet_in, 3)
			#For Switch 2 on Floor 2
			elif switch_id == 4:
				if ip.dstip == '10.2.7.70':
					self.forwarding(packet, packet_in, 1)
				elif ip.dstip == '10.2.8.80':
					self.forwarding(packet, packet_in, 2)
				else:
					self.forwarding(packet, packet_in, 3)


			#For the core switch
			elif switch_id == 5:
				#Handle the h_untrust
				if port_on_switch == 4:
					if ip.dstip == '108.24.31.112':
						self.forwarding(packet, packet_in, 3)
					#Block all ICMP traffic
					elif icmp is not None:
						self.drop(packet, packet_in)
					else:
						#Drop all ip traffic aimed at the server
						if ip.dstip == '10.3.9.90':
							self.drop(packet, packet_in)
						elif ip.dstip == '10.1.1.10' or ip.dstip == '10.1.2.20':
							self.forwarding(packet, packet_in, 1)
						elif ip.dstip == '10.1.3.30' or ip.dstip == '10.1.4.40':
							self.forwarding(packet, packet_in, 2)
						elif ip.dstip == '10.2.5.50' or ip.dstip == '10.2.6.60':
							self.forwarding(packet, packet_in, 5)
						elif ip.dstip == '10.2.7.70' or ip.dstip == '10.2.8.80':
							self.forwarding(packet, packet_in, 6)
						#Connection to the h_trust
						#elif ip.dstip == '108.24.31.112':
							#self.forwarding(packet, packet_in, 3)
				#Handle the h_trust      
				elif port_on_switch == 3:
					#Block any icmp and ip traffic to the server
					if ip.dstip == '106.44.82.103':
						self.forwarding(packet, packet_in, 4)
					elif ip.dstip == '10.3.9.90':
						self.drop(packet, packet_in)
					#Drop all icmp traffic to floor 2
					elif icmp is not None and ip.dstip >= '10.2.5.50' and ip.dstip <= '10.2.8.80':
						self.drop(packet, packet_in)
					elif ip.dstip == '10.1.1.10' or ip.dstip == '10.1.2.20':
						self.forwarding(packet, packet_in, 1)
					elif ip.dstip == '10.1.3.30' or ip.dstip == '10.1.4.40':
						self.forwarding(packet, packet_in, 2)
					#Connection to h_untrust
					#elif ip.dstip == '106.44.82.103':
						#self.forwarding(packet, packet_in, 4)
				#Communication between the two departments(floors) and to the trusted host
				elif port_on_switch == 1 or port_on_switch == 2:
					if ip.dstip >= '10.2.5.50' and ip.dstip <= '10.2.8.80':
						self.drop(packet, packet_in)
					#Communication on the 1st floor and to the server
					elif port_on_switch == 1 and ip.dstip >= '10.1.3.30' and ip.dstip <= '10.1.4.40':
						self.forwarding(packet, packet_in, 2)
					elif port_on_switch == 2 and ip.dstip >= '10.1.1.10' and ip.dstip <= '10.1.2.20':
						self.forwarding(packet, packet_in, 1)
					#Sending traffic to the server for floor 1
					elif ip.dstip == '10.3.9.90':
						self.forwarding(packet, packet_in, 7)
					#Trusted host connection
					elif ip.dstip == '108.24.31.112':
						self.forwarding(packet, packet_in, 3)
				elif port_on_switch == 5 or port_on_switch == 6:
					if ip.dstip >= '10.1.1.10' and ip.dstip <= '10.1.4.40':
						self.drop(packet, packet_in)
					#Communication on the 2nd floor
					elif port_on_switch == 5 and ip.dstip >= '10.2.7.70' and ip.dstip <= '10.2.8.80':
						self.forwarding(packet, packet_in, 6)
					elif port_on_switch == 6 and ip.dstip >= '10.2.5.50' and ip.dstip <= '10.2.6.60':
						self.forwarding(packet, packet_in, 5)
					#Sending traffic to the server for floor 2
					elif ip.dstip == '10.3.9.90':
						self.forwarding(packet, packet_in, 7) 
				#Connections from the DC switch to the floor switches
				elif port_on_switch == 7:
					if ip.dstip >= '10.1.1.10' and ip.dstip <= '10.1.2.20':
						self.forwarding(packet, packet_in, 1)
					elif ip.dstip >= '10.1.3.30' and ip.dstip <= '10.1.4.40':
						self.forwarding(packet, packet_in, 2)
					elif ip.dstip >= '10.2.5.50' and ip.dstip <= '10.2.6.60':
						self.forwarding(packet, packet_in, 5)
					elif ip.dstip >= '10.2.7.70' and ip.dstip <= '10.2.8.80':
						self.forwarding(packet, packet_in, 6)


			#Handle the DC switch
			elif switch_id == 6:
				if ip.dstip == '10.3.9.90':
					self.forwarding(packet, packet_in, 2)
				else:
					self.forwarding(packet, packet_in, 1)
		else:
			#Flood the non ip traffic
			self.flood(packet, packet_in)


	def drop(self, packet, packet_in):
		msg = of.ofp_flow_mod()
		msg.match = of.ofp_match.from_packet(packet)
		msg.idle_timeout = 60
		msg.hard_timeout = 60
		msg.buffer_id = packet_in.buffer_id
		self.connection.send(msg)

	def flood(self, packet, packet_in):
		msg = of.ofp_flow_mod()
		msg.match = of.ofp_match.from_packet(packet)
		msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
		msg.idle_timeout = 60
		msg.hard_timeout = 60
		msg.buffer_id = packet_in.buffer_id
		self.connection.send(msg)

	def forwarding(self, packet, packet_in, port_no):
		msg = of.ofp_flow_mod()
		msg.match = of.ofp_match.from_packet(packet)
		msg.actions.append(of.ofp_action_output(port = port_no))
		msg.idle_timeout = 60
		msg.hard_timeout = 60
		msg.buffer_id = packet_in.buffer_id
		self.connection.send(msg)

	def _handle_PacketIn (self, event):
		"""
		Handles packet in messages from the switch.
		"""
		packet = event.parsed # This is the parsed packet data.
		if not packet.parsed:
			log.warning("Ignoring incomplete packet")
			return

		packet_in = event.ofp # The actual ofp_packet_in message.
		self.do_final(packet, packet_in, event.port, event.dpid)

def launch ():
	"""
	Starts the component
	"""
	def start_switch (event):
		log.debug("Controlling %s" % (event.connection,))
		Final(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)
