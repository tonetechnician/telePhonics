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

import argparse
from pythonosc import osc_message_builder
from pythonosc import udp_client

def show_commands():
    print()
    print("Use the following commands to control the streaming server:")
    print("  1: Play")
    print("  2: Pause")
    print("  3 <scale factor>: Scale by value. eg: '3 2' for 2x scaling")
    print("  H: Show commands again")
    print("  X: Exit")
    print()

def controll(ip,port):
    client = udp_client.SimpleUDPClient(ip, port)

    print("Basic OSC control client")
    show_commands()

    while True:
        x = input()
        if x[0] == "1":
            client.send_message("/play", 1)
        if x[0] == "2":
            client.send_message("/pause", 0)
        if x[0] == "3":
            client.send_message("/scale", x.split(" ")[1])
        if x[0] == "H":
            show_commands()
        if x[0] == "X":
            client.send_message("/close", 1)
            break


if __name__ == '__main__':
    # Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip",
        default="127.0.0.1", help="The ip to listen on. Default: 127.0.0.1")
    parser.add_argument("-p", "--port",
        type=int, default=5005, help="The port to listen on. Default: 5005")
    args = parser.parse_args()

    controll(ip="127.0.0.1", port=5005)