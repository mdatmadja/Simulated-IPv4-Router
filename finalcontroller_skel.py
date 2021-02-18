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
    def send(port):
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet)
      msg.data = packet_in
      msg.priority = 1
      msg.idle_timeout = 50
      msg.hard_timeout = 50
      msg.match.dl_type = 0x0800
      msg.match.nw_proto = None
      msg.match.nw_src = None
      msg.match.nw_dst = None
      msg.buffer_id = packet_in.buffer_id
      msg.actions.append(of.ofp_action_output(port = port))
      self.connection.send(msg)
    
    deptA = ["10.1.1.10", "10.1.2.20", "10.1.3.30", "10.1.4.40"]
    deptB = ["10.2.5.50", "10.2.6.60", "10.2.7.70", "10.2.8.80"]

    ip = packet.find('ipv4')

    #ip.srcip
    #ip.dstip

    if packet.find('icmp'):
      print("ICMP")
      print(ip.srcip)
      print(ip.dstip)
      #Block ICMP traffic from Untrusted Host to 10-80(deptA/deptB) and Server
      if ip.srcip == "106.44.82.103" and ((ip.dstip in deptA) or (ip.dstip in deptB) or (ip.dstip == "10.3.9.90")):
        print("Untrust drop")
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.priority = 1
        msg.idle_timeout = 50
        msg.hard_timeout = 50
        msg.match.dl_type = 0x0800
        msg.match.nw_proto = 1
        msg.match.nw_src = None
        msg.match.nw_dst = None
        msg.buffer_id = packet_in.buffer_id
        self.connection.send(msg)
      elif ip.dstip == "106.44.82.103" and ((ip.srcip in deptA) or (ip.srcip in deptB) or (ip.srcip == "10.3.9.90")):
        print("Untrust drop")
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.priority = 1
        msg.idle_timeout = 50
        msg.hard_timeout = 50
        msg.match.dl_type = 0x0800
        msg.match.nw_proto = 1
        msg.match.nw_src = None
        msg.match.nw_dst = None
        msg.buffer_id = packet_in.buffer_id
        self.connection.send(msg)
      #Block ICMP traffic from Trusted Host to 50-80(deptB) and Server
      elif ip.srcip == "108.24.31.112" and ((ip.dstip in deptB) or (ip.dstip == "10.3.9.90")):
        print("Trust drop")
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.priority = 1
        msg.idle_timeout = 50
        msg.hard_timeout = 50
        msg.match.dl_type = 0x0800
        msg.match.nw_proto = 1
        msg.match.nw_src = None
        msg.match.nw_dst = None
        msg.buffer_id = packet_in.buffer_id
        self.connection.send(msg)
      elif ip.dstip == "108.24.31.112" and ((ip.srcip in deptB) or (ip.srcip == "10.3.9.90")):
        print("Trust drop")
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.priority = 1
        msg.idle_timeout = 50
        msg.hard_timeout = 50
        msg.match.dl_type = 0x0800
        msg.match.nw_proto = 1
        msg.match.nw_src = None
        msg.match.nw_dst = None
        msg.buffer_id = packet_in.buffer_id
        self.connection.send(msg)
      #Block ICMP traffic from deptA to deptB and vice versa
      elif (ip.srcip in deptA and ip.dstip in deptB) or (ip.srcip in deptB and ip.dstip in deptA):
        print("Drop between")
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.priority = 1
        msg.idle_timeout = 50
        msg.hard_timeout = 50
        msg.match.dl_type = 0x0800
        msg.match.nw_proto = 1
        msg.match.nw_src = None
        msg.match.nw_dst = None
        msg.buffer_id = packet_in.buffer_id
        self.connection.send(msg)

    if ip:
      print("IP")
      #Core Switch
      if switch_id == 1:
        print("Core")
        print(ip.dstip)
        #Forward to Floor/Switch
        if ip.dstip == "10.1.1.10" or ip.dstip == "10.1.2.20":
          print("11")
          send(8)
        elif ip.dstip == "10.1.3.30" or ip.dstip == "10.1.4.40":
          print("12")
          send(9)
        elif ip.dstip == "10.2.5.50" or ip.dstip == "10.2.6.60":
          print("21")
          send(10)
        elif ip.dstip == "10.2.7.70" or ip.dstip == "10.2.8.80":
          print("22")
          send(11)
        elif ip.dstip == "106.44.82.103":
          send(12)
        elif ip.dstip == "108.24.31.112":
          send(13)    
        elif ip.dstip == "10.3.9.90":
          #Block IP traffic from Untrusted/Trusted Host to Server
          if ip.srcip == "106.44.82.103" or ip.srcip == "108.24.31.112":
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet)
            msg.priority = 1
            msg.idle_timeout = 50
            msg.hard_timeout = 50
            msg.match.dl_type = 0x0800
            msg.match.nw_proto = None
            msg.match.nw_src = None
            msg.match.nw_dst = None
            msg.buffer_id = packet_in.buffer_id
            self.connection.send(msg)
          else:
            send(14)

      #Floor 1 Switch 1
      elif switch_id == 11:
        print("F1S1")
        print(ip.dstip)
        #Host 10
        if ip.dstip == "10.1.1.10":
          send(8)
        #Host 20
        elif ip.dstip == "10.1.2.20":
          send(9)
        #Core Switch
        else:
          send(1)
      
      #Floor 1 Switch 2
      elif switch_id == 12:
        print("F1S2")
        print(ip.dstip)
        #Host 30
        if ip.dstip == "10.1.3.30":
          send(8)
        #Host 40
        elif ip.dstip == "10.1.4.40":
          send(9)
        #Core Switch
        else:
          send(1)

      #Floor 2 Switch 1
      elif switch_id == 21:
        print("F2S1")
        print(ip.dstip)
        #Host 50
        if ip.dstip == "10.2.5.50":
          send(8)
        #Host 60
        elif ip.dstip == "10.2.6.60":
          send(9)
        #Core Switch
        else:
          send(1)

      #Floor 2 Switch 2
      elif switch_id == 22:
        print("F2S2")
        print(ip.dstip)
        #Host 70
        if ip.dstip == "10.2.7.70":
          send(8)
        #Host 80
        elif ip.dstip == "10.2.8.80":
          send(9)
        #Core Switch
        else:
          send(1)
      
      #Data Center Switch
      elif switch_id == 3:
        print("Data Center")
        print(ip.dstip)
        if ip.dstip == "10.3.9.90":
          send(9)
        else:
          send(8)
    else:
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet)
      msg.data = packet_in
      msg.priority = 1
      msg.idle_timeout = 50
      msg.hard_timeout = 50
      msg.match.dl_type = 0x0800
      msg.match.nw_proto = None
      msg.match.nw_src = None
      msg.match.nw_dst = None
      msg.buffer_id = packet_in.buffer_id
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
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
