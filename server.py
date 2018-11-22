#!/usr/bin/env python

"""CapToCSV.py: Build CSV from initial telescope data"""

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

from pythonosc import osc_message_builder
from pythonosc import udp_client
import time
import dpkt
import datetime
from dpkt.compat import compat_ord
import socket
import geoip2.database

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

def print_packets(pcap):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """

    data = {}
    timings = []
    count = 0

    reader = geoip2.database.Reader('geoip/GeoLite2-City.mmdb')

    client = udp_client.UDPClient('10.0.0.4', 7400)

    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
        time.sleep(0.15)
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
            print(iso+" - Latitude: "+str(lat)+", Longitude: "+str(lon))

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
            print('Time: %f' % (end-start))

        except:
            pass

    geolite2.close()

def test():
    """Open up a test pcap file and print out the packets"""
    with open('test.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap)

if __name__ == '__main__':
    test()
