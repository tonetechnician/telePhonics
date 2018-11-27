#!/usr/bin/env python

"""controlledStreamer.py: stream packets over OSC"""

"""
Open a PCAP and send out OSC for sound production.

Usage: $python controlledStreamer.py [-i IP] [-p PORT] [--no-control] input_pcap

positional arguments:
  input_pcap            PCAP input file.

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP        The ip to listen on. Default: 127.0.0.1
  -p PORT, --port PORT  The port to listen on. Default: 5005
  --no-control          Turn off control server.
"""

__author__ = "Brent Shaw"
__copyright__ = "Copyright 2018"
__credits__ = ["Brent Shaw"]
__license__ = "GPL"
__version__ = "0.1.0"
__maintainer__ = "Brent Shaw"
__email__ = "shaw@live.co.za"
__status__ = "Development"

import os
import sys
import dpkt
import time
import socket
import argparse
import geoip2.database
from pythonosc import dispatcher
from pythonosc import osc_server
from pythonosc import osc_message_builder
from pythonosc import udp_client
from dpkt.compat import compat_ord
from multiprocessing import Process, Value, Queue

def mac_addr(address):
    """Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet):
    """Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

class PacketStreamer(object):
    def __init__(self, f):
        """
        Specify which CSV will be iterated over
        """
        self.file = f

    def __iter__(self):
        """
        Allows one to row that boat gently down the stream.

        Iterable interface reads in a CSV and lazily yields each row so that it can be processed.
        """
        with open(self.file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for timestamp, buffer in pcap:
                yield (timestamp, buffer)

# OSC Message handlers
# These are called upon receival of each OSC message type
# Queue messaging format
#  - Basic string in format <command>/<value>

def play_hander(unused_addr, args):
    command_queue.put("playback/play")

def pause_hander(unused_addr, args):
    command_queue.put("playback/pause")

def tempo_hander(unused_addr, args):
    scaler = args
    command_queue.put("scale/"+str(scaler))

# Start and run server forever
def process_OSC(q, server):
    server.serve_forever()

# Process PCAP
# Reads one packet at a time from the PCAP Steam Iterator
def process_PCAP(cap, ip, port, command_queue, start_state):
    state = start_state
    scale = 1
    count = 0

    data = {}
    timings = []
    count = 0

    command = ["playback", "pause"]

    reader = geoip2.database.Reader('geoip/GeoLite2-City.mmdb')

    client = udp_client.UDPClient(ip, port)

    packetStream = PacketStreamer(cap)

    last = None

    # For each packet in the pcap process the contents
    for packet in packetStream:

        # This is not pretty, but it works
        
        if command_queue.empty() is False:
            command = command_queue.get().split("/") # Separate the command and value
        if command[0] == "playback":
            if command[1] == "play":
                state = True
            if command[1] == "pause":
                state = False
        if command[0] == "scale":
            scale = float(command[1])

        while not state:
            if command_queue.empty() is False:
                command = command_queue.get().split("/") # Separate the command and value
                if command[0] == "playback":
                    if command[1] == "play":
                        state = True
                    if command[1] == "pause":
                        state = False
                if command[0] == "scale":
                    scale = float(command[1])
            time.sleep(0.1)
            pass
        
        timestamp = packet[0]
        buf = packet[1]

        if last == None:
            last = timestamp
        else:
            delay = timestamp-last

            time.sleep(delay/scale)
            try:

                eth = dpkt.ethernet.Ethernet(buf)

                # Make sure the Ethernet data contains an IP packet
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                #ip data
                ip = eth.data
                sourceip = inet_to_str(ip.src)
                destip = inet_to_str(ip.dst)

                #geo data
                response = reader.city(sourceip)
                iso = response.country.iso_code
                lat = response.location.latitude
                lon = response.location.longitude
                print("Timestamp: " + str(timestamp) + ", ISO: " +iso+" - Latitude: "+str(lat)+", Longitude: "+str(lon) + ", Delayed: " + str(delay))

                #build ADSR curve
                #TODO: Finish this. Is not currently used
                adsr = sourceip.replace(".", " ")

                msg = osc_message_builder.OscMessageBuilder(address="/adsr")
                msg.add_arg(adsr)
                msg = msg.build()
                client.send(msg)

                msg = osc_message_builder.OscMessageBuilder(address="/country")
                msg.add_arg(iso)
                msg = msg.build()
                client.send(msg)

                msg = osc_message_builder.OscMessageBuilder(address="/freq")
                msg.add_arg(ip.data.dport)
                msg = msg.build()
                client.send(msg)

                msg = osc_message_builder.OscMessageBuilder(address="/delay")
                msg.add_arg(ip.p)
                msg = msg.build()
                client.send(msg)

                msg = osc_message_builder.OscMessageBuilder(address="/lat")
                msg.add_arg(lat)
                msg = msg.build()
                client.send(msg)

                msg = osc_message_builder.OscMessageBuilder(address="/lon")
                msg.add_arg(lon)
                msg = msg.build()
                client.send(msg)

                last = timestamp

            except Exception as e:
                #print(e)
                pass

if __name__ == '__main__':
    # Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("input_pcap",
        type=str, default="test.pcap", help="PCAP input file.")
    parser.add_argument("-i", "--ip",
        default="127.0.0.1", help="The ip to listen on. Default: 127.0.0.1")
    parser.add_argument("-p", "--port",
        type=int, default=5005, help="The port to listen on. Default: 5005")
    parser.add_argument("--no-control",
        help="Turn off control server.", action="store_false")
    args = parser.parse_args()

    # Autoplay / controlled server
    if args.no_control:
        start_state = False
    else:
        start_state = True

    # Queue for interprocess communication
    command_queue = Queue()

    # OSC message handler dispatchers
    dispatcher = dispatcher.Dispatcher()
    dispatcher.map("/play", play_hander)
    dispatcher.map("/pause", pause_hander)
    dispatcher.map("/scale", tempo_hander)

    # Create threading OSC server
    threading_server = osc_server.ThreadingOSCUDPServer(("127.0.0.1", 5005), dispatcher)
    print("Listening on {}".format(threading_server.server_address))

    # Start processes
    Process(target=process_OSC, args=(command_queue,threading_server)).start()
    Process(target=process_PCAP, args=(args.input_pcap, args.ip, args.port, command_queue,start_state)).start()