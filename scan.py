# -*- coding: utf-8 -*-

# name: scan.py
# vers: 0.1 
# multithreaded IPv4 port-scanner, scans low-ports (0-1023) for a networks given
# in .xls file. scan.py saves open TCP ports to a file and also streams 
# results to to gephi for RT scan visualization (each graph node is a service or 
# host, graph edges are TCP ports).
# scans.pyuses standard CONNECT method, therefore it can be run with ordinary
# user rights, good for env. wher use is restricted and NMAP won't run
# (ie. NMAP may need to access iface in RAW access mode).

import sys
import threading
import socket
from multiprocessing import Queue
import csv
import ipaddress

# you will need Python classes for streaming graph to gephi
# https://github.com/totetmatt/GephiStreamer
from gephistreamer import graph
from gephistreamer import streamer

# options
DEBUG = False
PUSH2GRAPH = False

# where to put scan.py data
NETWORK_FILE = 'C:\\Users\\JNEMEC4\\Desktop\\LAN\\In\\RANGES.csv'
NETWORK_SCAN_RESULTS_FILE = 'C:\\Users\\JNEMEC4\\Desktop\\LAN\\Out\\SCANS.csv'

# data structure (.xls) should look like this:
#
# network friendly name; network name; ip_range_w_mask; comment; vlan_type; vlan_id
# i.e.:
#
# lokalni sit doma     ; None        ; 172.16.124.0/24; None;    None     ; None
#
# networks with vlan_type == U is alweays EXCLUDED from the scan


class LookupThread(threading.Thread):
    ''' IPv4 DNS lookup class '''
    def __init__(self, addr, result_queue, pool):
        self.addr = addr
        self.result_queue = result_queue
        self.pool = pool
        
        threading.Thread.__init__(self)

    def run(self):
        self.pool.acquire()
        try:
            self.lookup()
        finally:
            self.pool.release()

    def lookup(self):
        print('Lookup for: ', str(self.addr))
        try:
            hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(self.addr)
        except socket.herror:
            hostname, aliaslist, ipaddrlist = None, None, None
        result_queue.put([hostname, aliaslist, ipaddrlist])


class ScannerIPv4Thread(threading.Thread):
    ''' scanning thread class '''
    def __init__(self, addr, result_queue, pool):
        self.addr = addr
        self.result_queue = result_queue
        self.pool = pool
        
        threading.Thread.__init__(self)
        
    def run(self):
        self.pool.acquire()
        try:
            self.scan()
        finally:
            self.pool.release()
        
    def scan(self):
        try:
            report_open = []
            portlist = range(0, 1023)
            
            for port in portlist:
                port = int(port)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(.01)
                result = sock.connect_ex((self.addr, port))
                sock.close()
            
                if result == 0:
                    report_open.append(port)

            result_queue.put([self.addr, report_open])
                
        except KeyboardInterrupt:
            sys.exit()


def dump_queue(queue):
    items = []
    maxItemsToRetreive = queue.qsize()

    for numOfItemsRetrieved in range(0, maxItemsToRetreive):
        try:
            if numOfItemsRetrieved == maxItemsToRetreive:
                break
            items.append(queue.get_nowait())
        except:
            break
    return items


def gephi_commit_scan(stream, items):    
    with open(NETWORK_SCAN_RESULTS_FILE, "a") as scan_file:
        for item in items:
            addr, open_tcp_ports = item
            if len(open_tcp_ports) != 0:
                scan_file.write('node:' + str(addr) + '\n')
                for open_tcp_port in open_tcp_ports:       
                    scan_file.write('edge:' + str(addr) + '>' + str(open_tcp_port)+ '\n')

    for item in items:
        addr, open_tcp_ports = item
        if DEBUG == True:
            print('ipv4: ', addr, 'open TCP ports: ',  open_tcp_ports)
        if len(open_tcp_ports) != 0:
            if DEBUG == True:
                print('ipv4: ', addr, 'open TCP ports: ',  open_tcp_ports)
            addr_node = graph.Node(addr, size=10, custom_property=1)
            stream.add_node(addr_node)
            print('open port@' + str(addr) + ' ' + str(open_tcp_ports))
            for open_tcp_port in open_tcp_ports:
                open_tcp_port_node = graph.Node(open_tcp_port, size=40, custom_property=64)
                stream.add_node(open_tcp_port_node)
                open_tcp_port_edge = graph.Edge(addr_node, open_tcp_port_node, custom_property="TCP IPv4 service: " + str(open_tcp_port))
                stream.add_edge(open_tcp_port_edge)
        else:
            print('  no port@' + str(addr))
                
    stream.commit() 

def csv_ip_open(csv_path):
    network_nodes = []
    with open(csv_path) as csvfile:
        readCSV = csv.reader(csvfile, delimiter=';')
        for row in readCSV:
            if row[4] == 'U':
                print('[i] skipping [U] aka user segment ', row[2])
            else:
                network_nodes.append([ [row[0]], [row[1]], [row[2]],  [row[3]], [row[4]], [row[5]] ])

    return network_nodes


def perform_scan(ip_addresses):
        ''' to scan the network faster we use multithreading 
            (not multiprocessing)
        '''
        threads = []
        for addr in ip_addresses:
            
            threads.append(ScannerIPv4Thread(addr, result_queue, pool))
        
        for thread in threads:

            if DEBUG == True:
                print('Starting Thread: ', thread.getName())
            thread.start()

        # wait until all threads stop
        for thread in threads:
            if DEBUG == True:
                print('Stopping Thread: ', thread)

            thread.join()
            # dump queue collects result from threads
            items = dump_queue(result_queue)
            if DEBUG == True:
                print(items)

            # send result to gephi for visualization
            gephi_commit_scan(stream, items)
    
        print('All threads stopped...')  
        

if __name__ == '__main__':
    
    # open csv with network ranges
    network_nodes =  csv_ip_open(NETWORK_FILE)
    
    result_queue = Queue()
    stream = streamer.Streamer(streamer.GephiREST(hostname="localhost", port=8080, workspace="workspace0"))    
    pool = threading.BoundedSemaphore(128)
    
    continue_flag = False
    
    # for each network range from the list; do
    for network in network_nodes:
        print(network)
        
        # wait for input - DEBUG
        if continue_flag is not True:
            user_input = input("Should I stop now or continue? [yes/no/continue]")
            if user_input == 'y' or user_input== 'yes':
                break
            if user_input == 'c' or user_input == 'continue':
                continue_flag = True
        
        # reset ip_addresses
        ip_addresses = []
        
        # expand network range to list of IPV4 addresses
        # fix IPv4 ranges if there is no subnet mask given or other typo
        try:
            network[2][0] = network[2][0].replace(' ', '')
            _, _ = network[2][0].replace(' ', '').split('/')
        except ValueError:
                try:
                    # make sure the last octet is 0
                    oct_A, oct_B, oct_C, _ = network[2][0].split('.')
                    network[2][0] = oct_A + '.' + oct_B + '.' + oct_C + '.0/24'
                
                except ValueError:
                    print('bad network definition:', network[2][0])

        try:
            for item in list(ipaddress.ip_network(network[2][0]).hosts()):
                ip_addresses.append(str(item))
            
            # call the scan function
            print(ip_addresses)
            perform_scan(ip_addresses)
            
        except ValueError:
            print('bad network definition:', network[2][0])        
