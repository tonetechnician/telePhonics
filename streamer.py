#!/usr/bin/env python

"""pcap_streamer.py: Build CSV from initial telescope data"""

"""
Currently the data is not publically avaialble. Contact for access.
"""

__author__ = "Brent Shaw"
__copyright__ = "Copyright 2018"
__credits__ = ["Brent Shaw"]
__license__ = "GPL"
__version__ = "0.1.0"
__maintainer__ = "Brent Shaw"
__email__ = "shaw@live.co.za"
__status__ = "Development"

import time
import dpkt
import datetime
from dpkt.compat import compat_ord
import socket
import geoip2.database
import sys
import keyboard


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

data = {}
timings = []
count = 0

reader = geoip2.database.Reader('geoip/GeoLite2-City.mmdb')

#client = udp_client.UDPClient('10.0.0.4', 7400)

cap = 'test.pcap'

packetStream = PacketStreamer(cap)

last = None

# For each packet in the pcap process the contents
for packet in packetStream:
    timestamp = packet[0]
    buf = packet[1]

    if last == None:
        last = timestamp
    else:
        delay = timestamp-last

        time.sleep(delay/100)
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

            last = timestamp

        except:
            pass