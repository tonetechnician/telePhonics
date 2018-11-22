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
from dpkt.compat import compat_ord
from multiprocessing import Process, Value, Queue

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
def process_PCAP(command_queue, start_state):
    state = start_state
    scale = 1
    count = 0
    while True:
        time.sleep(0.5/scale)
        if command_queue.empty() is False:
            command = command_queue.get().split("/") # Separate the command and value
            if command[0] == "playback":
                if command[1] == "play":
                    state = True
                if command[1] == "pause":
                    state = False
            if command[0] == "scale":
                scale = float(command[1])
        if state:
            print("Packet "+str(count)+". Playback @ "+str(scale)+"x scaling")
            count = count + 1

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
    print("Serving on {}".format(threading_server.server_address))

    # Start processes
    Process(target=process_OSC, args=(command_queue,threading_server)).start()
    Process(target=process_PCAP, args=(command_queue,start_state)).start()