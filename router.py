import socket
import time
import sys
import select
from copy import deepcopy

'''
Authors: Robert Dumbleton, Clinton Walker
Date:    02/05/2022
Description: This is a router program that impletments the RIPv2 routing protocol
'''


def read_config(filename):
    ''' Reads the lines from the context file and discards any empty lines'''
    file = open(filename, "r")
    data = file.readlines()
    lines = []
    for i in range(len(data)-1):
        #ignore any blank lines in the file
        if(len(data[i].strip()) >= 1):
            lines.append(data[i].strip())
    routerId, inputPorts, outputPorts, timerValues = extractConfig(lines)
    file.close()
    return (routerId, inputPorts, outputPorts, timerValues)

def extractConfig(lines):
    ''' Takes lines from read_config and extracts all of the necessary values for the router to function
        if no timer values are detected or are seen as errornous then the default vales 30,180,120 will be given'''
    inputPorts = []
    outputPorts = []
    timerValues = []
    routerId = 0    
    line = 0
    #Loop through each line of the read config
    while line < (len(lines)):
        lines[line] = lines[line].strip()
        lines[line] = lines[line].split()
        #if a router-id decleration is found, check if the following value is correct
        if((lines[line][0]) == "router-id"):
            try:
                if(1 <= int(lines[line][1]) <= 64000 and len(lines[line]) == 2):
                    routerId = int(lines[line][1])
                else:
                    raise Exception("Router-id not in expected range 1-64000 or too many values provided")
            except:
                raise Exception("Router-id incorrectly specified")
        
        #if an imput-ports decleration is found, check if the following values are correct
        if(lines[line][0] == "input-ports"):
            try:
                #exclude the 'input-ports' decleration to isolate the needed values
                for port in lines[line][1:]:
                    if(1024 <= int(port) <= 64000 and int(port) not in inputPorts):
                        #if the given port is correct add it to the list
                        inputPorts.append(int(port))
                    else: raise Exception("Input-ports incorrectly specified")
            except:
                raise Exception("Input-ports incorrectly specified")

        #if an outputs decleration is found, check if the following values are correct
        if(lines[line][0] == "outputs"):
            try:
                #exclude the 'outputs' decleration to isolate the needed values
                for port in lines[line][1:]:
                    outputPort = []
                    port = port.split("-")
                    #send the port to check_ports to ensure the given port is not in use somewhere else
                    if check_ports(port, outputPorts, inputPorts):
                            for i in port:
                                outputPort.append(int(i))
                    outputPorts.append(outputPort)
            except:
                raise Exception("Output-ports incorrectly specified")
                
        #if a timer-values decleration is found, check if the following values are correct
        if(lines[line][0] == "timer-values"):
            try:
                timerVals = lines[line][1].split("-")
                if(int(timerVals[1]) / int(timerVals[0]) == 6 and int(timerVals[2]) / int(timerVals[0]) == 4 and len(timerVals) == 3):
                    for time in timerVals:
                        timerValues.append(int(time))
                else:
                    timerValues = [30, 80, 120]
            except:
                pass
            
        line += 1
    #if 'timer-values' was missing from the config file then default to timing [30, 180, 120]
    if(timerValues == []): timerValues = [30, 80, 120]
    return (routerId, inputPorts, outputPorts, timerValues)


def check_ports(port, outputPorts, inputPorts):
    '''Checks the values of the given output port'''
    try:
        #check the port doesnt exist in inputPorts
        if(len(port) == 3 and int(port[0]) not in inputPorts):
            #check the port numbers are within range
            if (1 <= int(port[2]) <= 64000 and 1 <= int(port[1]) <= 15 and 1024 <= int(port[0]) <= 64000):
                #check the port does not exist in outputPorts
                if len(outputPorts) > 0:
                    for i in outputPorts:
                        if i[0] == int(port[0]): raise Exception("Output ports incorrectly specified")
                        else: return True
                #if outputPorts is empty then there wont be a conflict
                else: return True
    except:
        raise Exception("Output ports incorrectly specified")
        
        
class Router:
    def __init__(self, config_file):
        # router constants
        self.BUFFER_SIZE = 1024
        # initialize nessecary variables
        self.routing_table = {}
        self.queue = []
        self.router_id, self.input_ports, self.output_ports, self.timer_values = read_config(config_file)
        self.update_timer, self.timeout_timer, self.garbage_timer = self.timer_values
        self.reset_update_timer()
        self.input_sockets = self.create_sockets(self.input_ports)
        self.output_socket = [self.input_sockets[0]]
        self.last_triggered_update = time.time()

        # print out config info
        print("Router ID:", self.router_id)
        print("Input Ports:", end=" ")
        for i in self.input_ports: print(i, end=", ")
        print()
        print("Output Ports:", end=" ")
        for i in self.output_ports: print(i, end=", ")
        print()
        print("Timer Values:", self.timer_values)

        while True:
            self.tick()
    
    def create_sockets(self, input_ports):
        input_sockets = []
        for port in input_ports:
            try:
                UDP_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
                UDP_socket.bind(('localhost', port))
                input_sockets.append(UDP_socket)
            except:
                print("Error opening a socket on port " + str(port))
                sys.exit()
        return input_sockets

    def reset_update_timer(self):
        self.next_update = time.time() + self.update_timer

    def reset_timeout(self, router_id):
        self.routing_table[router_id]["timeout"] = time.time() + self.timeout_timer
        self.routing_table[router_id]["garbage"] = False

    def set_garbage_timer(self, router_id):
        self.routing_table[router_id]["metric"] = 16
        self.routing_table[router_id]["garbage"] = True
        self.routing_table[router_id]["timeout"] = time.time() + self.garbage_timer
        

    def check_timeout(self, router_id):
        # if the garbage flag is true
        if self.routing_table[router_id]["garbage"]:
            # if timer has gone off
            if time.time() >= self.routing_table[router_id]["timeout"]:
                # delete the entry 
                del(self.routing_table[router_id])
        else:
            # timer has gone off
            if time.time() >= self.routing_table[router_id]["timeout"]:
                self.set_garbage_timer(router_id)
    
    def send_update(self, triggered_update_flag):
        self.reset_update_timer()
        if triggered_update_flag:
            # dont send an update if one has been sent in the last 5 seconds
            if not time.time() >= self.last_triggered_update + 5:
                return
            else: 
                self.last_triggered_update = time.time()
        for port in self.output_ports:
            update_packet = self.create_update_packet(port[2], triggered_update_flag)
            self.output_socket[0].sendto(update_packet, ('localhost', port[0]))

    def tick(self):
        read, write, special = select.select(self.input_sockets, self.output_socket, [])
        for i in read:
            try:
                data, addr = i.recvfrom(self.BUFFER_SIZE)
                self.queue.append((data, addr))
            except:
                print("Error recieving a packet")

        if time.time() >= self.next_update:
            print("Router ID:", self.router_id)
            self.print_table()
            self.send_update(triggered_update_flag=False)
                
        for message in self.queue:
            data, addr = self.queue.pop(0)
            port = addr[1]
            self.process_packet(port, data)

        triggered_update = False
        for route in self.routing_table:
            if(self.routing_table[route]["deleted_route"] == True):
                triggered_update = True
        if triggered_update:
            self.send_update(True)
            for i in self.routing_table: self.routing_table[route]["deleted_route"] = False

        for entry in deepcopy(self.routing_table):
            self.check_timeout(entry)

    
    def create_update_packet(self, destination_id, triggered_update=False):
        packet = bytearray()
        COMMAND = 2
        VERSION = 2
        packet.append(COMMAND.to_bytes(1, 'big')[0])
        packet.append(VERSION.to_bytes(1, 'big')[0])
        sender_id_bytes = self.router_id.to_bytes(2, 'big')

        for byte in sender_id_bytes:
            packet.append(byte)

        for link, data in self.routing_table.items():
            if triggered_update:
                if data["deleted_route"]:
                    self.create_rip_entry(packet, link, destination_id)
            else:
                self.create_rip_entry(packet, link, destination_id)

        return packet

    def create_rip_entry(self, packet, route_id, destination_id):
        AFI = 2
        AFI_bytes = AFI.to_bytes(2, 'big')
        for i in AFI_bytes: packet.append(i)
        for i in range(0, 2): packet.append(0x00)
        route_id_bytes = route_id.to_bytes(4, 'big')
        for i in route_id_bytes: packet.append(i)
        for i in range(0, 8): packet.append(0x00)
        # split horizon with poison reverse
        if(self.routing_table[route_id]["next_hop_id"] == destination_id):
            metric = 16
        else:
            metric = self.routing_table[route_id]["metric"]

        metric_bytes = metric.to_bytes(4, 'big')
        for i in metric_bytes: packet.append(i)


    def print_table(self):
        print(  " +-------------+--------+----------+-------------+---------+---------+\n",
            "| Destination | Metric | Next Hop | Next Hop ID | Timeout | Garbage |\n",
            "+-------------+--------+----------+-------------+---------+---------+")
        # copy table so it cant update during print
        copied_table = deepcopy(self.routing_table)
        for link in copied_table:
            data = copied_table[link]
            timeout = int(data["timeout"] - time.time())
            if data["garbage"]:
                garbage = timeout
                timeout = '-'
            else:
                garbage = '-'
            print(" |{0:^13}|{1:^8}|{2:^10}|{3:^13}|{4:^9}|{5:^9}|".format(link, data["metric"], data["next_hop"], data["next_hop_id"], timeout, garbage))
        print(" +-------------+--------+----------+-------------+---------+---------+")
    
    def check_packet(self, packet):
        entry_count = int((len(packet) - 4) / 20)
        if packet[0] != 2 and packet[1] != 2:
            return False
        entries = packet[4:]
        for i in range(entry_count):
            metric = bytearray()
            for j in range(16, 20):
                metric.append(entries[20 * i + j])
            metric = int.from_bytes(metric, "big")
            if metric < 1 or metric > 16:
                return False
        return True
        

    def create_table_entry(self, router_id, metric, next_hop_id, next_hop):
        data = {
            "metric" : metric,
            "next_hop": next_hop,
            "next_hop_id": next_hop_id,
            "timeout" : time.time() + self.timeout_timer,
            "garbage" : False,
            "deleted_route" : False
        }

        self.routing_table[router_id] = data

    def process_packet(self, sender_port, packet):
        # exit discard packet if not valid
        if not self.check_packet(packet):
            return
        entry_count = int((len(packet) - 4) / 20)
        entries = packet[4:]

        sender_id = int.from_bytes(packet[2:4], 'big')

        # lookup sender metric
        for neighbour_port, neighbour_metric, neighbour_id in self.output_ports:
           if(sender_id == neighbour_id):
                sender_metric = neighbour_metric

        # if no entry exists create one with given info
        if sender_id not in self.routing_table.keys():
            self.create_table_entry(sender_id, sender_metric, sender_id, sender_port)
        else:
            for neighbour_port, neighbour_metric, neighbour_id in self.output_ports:
                # if you are hearing from a neighbour, and you have a better metric for them, use it, as you have heard directly from them
                if sender_id == neighbour_id and neighbour_metric < self.routing_table[sender_id]['metric']:
                    self.routing_table[sender_id]['next_hop'] = neighbour_port
                    self.routing_table[sender_id]['metric'] = neighbour_metric
                    self.routing_table[sender_id]['next_hop_id'] = neighbour_id
            self.reset_timeout(sender_id)

        for i in range(entry_count):
            # TODO split up
            destination = bytearray()
            metric = bytearray()

            for j in range(4, 8):
                destination.append(entries[20 * i + j])
            for j in range(16, 20):
                metric.append(entries[20 * i + j])

            destination = int.from_bytes(destination, "big")
            metric = int.from_bytes(metric, "big")

            distance = sender_metric + metric

            if destination in self.routing_table.keys():
                # if distance better than current metric, or packet comes from a router along the route
                if distance < self.routing_table[destination]["metric"] or self.routing_table[destination]["next_hop_id"] == sender_id:
                    self.routing_table[destination]["metric"] = distance
                    self.routing_table[destination]["next_hop_id"] = sender_id
                    self.routing_table[destination]["next_hop"] = sender_port
                # if metric is worse, reset timer anyway TODO may need to do this above as well?
                if(distance < 16 and self.routing_table[destination]["next_hop_id"] == sender_id):
                    self.reset_timeout(destination)
            # if advertisment for a router you have not seen, create an entry
            elif(destination != self.router_id and not distance > 15):
                self.create_table_entry(destination, distance, sender_id, sender_port)

            # set route changed flag for destination if infinite metric
            try:
                if self.routing_table[destination]["metric"] > 15:
                    self.routing_table[destination]["metric"] = 16
                    if(self.routing_table[destination]["garbage"] == False):
                        self.set_garbage_timer(destination)
            except:
                continue


my_router = Router(sys.argv[1])
