# -*- coding: utf-8 -*-

#
# name: streamer.py
# vers: 0.1
# if scan.py aleady gathered data, we may want to replay (visualize)
# scan process in Gephi
#

# standard libs
import time
import hashlib
import textwrap
import random
import string
import operator

# you will need Python class 'gephistreamer' for streaming to Gephi
# https://github.com/totetmatt/GephiStreamer
from gephistreamer import graph
from gephistreamer import streamer

# replay params
OBFUSCATE_IPv4 = True
REPLAY_SPEED = .05 # 50ms

# where the scan.py data are
network_scan_result_file = 'C:\\XYZ\\SCANS.csv'


def generate_salt(length):
    ''' generate salt to use with IPv4 data obfuscation '''
    letters = string.hexdigits
    return ''.join(random.choice(letters) for i in range(length))


def obfuscateIPv4(data_content):
    ''' obfuscate IPv4  '''
    addr = hashlib.md5(SALT.encode('utf-8') + data_content.encode('utf-8')).hexdigest()
    addr_wrapp = textwrap.wrap(addr, 3)
    addr = addr_wrapp[0] + '.' + addr_wrapp[1] + '.' + addr_wrapp[2] + '.' + addr_wrapp[3]
    return addr


def gephi_file_stream_read():
    ''' read scan results from a file  '''
    with open(network_scan_result_file, "r") as scan_file:
        content = scan_file.readlines()
        content = [x.strip() for x in content]
        return content


def gephi_push_data(stream, item):
    ''' push data to gephi  '''
    data_type, data_content = item.split(':')

    if data_type == 'node':
        ''' node data processing '''
        if OBFUSCATE_IPv4 == True:
            addr = obfuscateIPv4(data_content)
        else:
            addr = data_content

        print(data_type + ':' + addr)
        uniq_systems.append(addr)
        addr_node = graph.Node(addr, size=10, custom_property=1)
        stream.add_node(addr_node)

    if data_type == 'edge':
        ''' edge data processing '''
        addr, open_tcp_port = data_content.split('>')

        if OBFUSCATE_IPv4 == True:
            addr = obfuscateIPv4(addr)

        print(data_type + ':' + addr + '>' + open_tcp_port)
        uniq_services.append(open_tcp_port)

        try:
            uniq_services_count[open_tcp_port] = uniq_services_count[open_tcp_port] + 1
        except KeyError:
            uniq_services_count[open_tcp_port] = 1
        open_tcp_port_node = graph.Node(open_tcp_port, custom_property=64)
        stream.add_node(open_tcp_port_node)

        open_tcp_port_edge = graph.Edge(\
                                        addr, open_tcp_port_node, \
                                        custom_property="TCP IPv4 service: " \
                                        + str(open_tcp_port))
        stream.add_edge(open_tcp_port_edge)


if __name__ == '__main__':
    ''' replay scan in Gephi '''

    # anonymize source scan data (IPv4s)
    SALT = generate_salt(32)

    # placeholders
    uniq_systems = []
    uniq_services = []
    uniq_services_count = {}

    # make sure your gephi workspace is 0
    stream = streamer.Streamer(streamer.GephiREST(hostname="localhost", port=8080, workspace="workspace0"))

    for item in gephi_file_stream_read():
        gephi_push_data(stream, item)
        time.sleep(REPLAY_SPEED)

    # print statistics, aka. total hosts and unique services/ports open
    print('------------------------------')
    print('[i]  unique systems: ', len(set(uniq_systems)))
    print('[i] unique services: ', len(set(uniq_services)))

    sorted_uniq_services_count = sorted(uniq_services_count.items(), \
                                        key=operator.itemgetter(1))
    print('------------------------------')
    print(sorted_uniq_services_count)
