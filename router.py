import socket
import time
import sys
import select
from copy import deepcopy

def read_config(filename):
    file = open(filename, "r")
    lines = file.readlines()
    for i in range(len(lines)-1):
        lines[i] = lines[i].strip()
    routerId, inputPorts, outputPorts, timerValues = extractConfig(lines)
    file.close()
    return (routerId, inputPorts, outputPorts, timerValues)

def extractConfig(lines):
    inputPorts = []
    outputPorts = []
    timerValues = []
    routerId = 0    
    line = 0
    while line < (len(lines)):
        lines[line] = lines[line].strip()
        lines[line] = lines[line].split()
        if((lines[line][0]) == "router-id"):
            if(1 <= int(lines[line][1]) <= 64000 and len(lines[line]) == 2):
                routerId = int(lines[line][1])
            else: 
                raise Exception("Router-id incorrectly specified")
            
        if(lines[line][0] == "input-ports"):
            for port in lines[line][1:]:
                if(1024 <= int(port) <= 64000 and int(port) not in inputPorts):
                    inputPorts.append(int(port))
                else: raise Exception("Input ports specified incorrectly")

        if(lines[line][0] == "outputs"):
            for port in lines[line][1:]:
                outputPort = []
                port = port.split("-")
                if check_ports(port, outputPorts, inputPorts):
                        for i in port:
                            outputPort.append(int(i))
                outputPorts.append(outputPort)

        if(lines[line][0] == "timer-values"):
            timerVals = lines[line][1].split("-")
            if(int(timerVals[1]) / int(timerVals[0]) == 6 and int(timerVals[2]) / int(timerVals[0]) == 4 and len(timerVals) == 3):
                for time in timerVals:
                    timerValues.append(int(time))
            else:
                timerValues = [30, 80, 120]
        line += 1
    if(timerValues == []): timerValues = [30, 80, 120]
    return (routerId, inputPorts, outputPorts, timerValues)

def check_ports(port, outputPorts, inputPorts):
    if(len(port) == 3 and int(port[0]) not in inputPorts and 1 <= int(port[2]) <= 64000 and 1 <= int(port[1]) <= 15 and 1024 <= int(port[0]) <= 64000):
        if len(outputPorts) > 0:
            for i in outputPorts:
                if i[0] == int(port[0]): raise Exception("Output ports incorrectly specified")
                else: return True
        else: return True
    else: raise Exception("Output ports incorrectly specified")

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
                del(self.routing_table[routerId])
        else:
            # timer has gone off
            if time.time() >= self.routing_table[router_id]["timeout"]:
                self.set_garbage_timer(router_id)
    
    def send_update(self, triggered_update_flag):
        self.reset_update_timer()
        print("Router ID:", self.router_id)
        self.print_table()
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
                if data["route_changed"]:
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
        print(  " +-------------+--------+----------+-------------+---------+---------+---------------------+\n",
            "| Destination | Metric | Next Hop | Next Hop ID | Timeout | Garbage | Infinite Route Flag |\n",
            "+-------------+--------+----------+-------------+---------+---------+---------------------+")
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
            if not data["deleted_route"]:
                deleted_route = "Not Set"
            else:
                deleted_route = "Set"
            print(" |{0:^13}|{1:^8}|{2:^10}|{3:^13}|{4:^9}|{5:^9}|{6:^21}|".format(link, data["metric"], data["next_hop"], data["next_hop_id"], timeout, garbage, deleted_route))
        print(" +-------------+--------+----------+-------------+---------+---------+---------------------+")
    
    def check_packet(self, packet):
        # TODO Packet checking
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

        for neighbour_port, neighbour_metric, neighbour_id in self.output_ports:
           if(sender_id == neighbour_id):
                sender_metric = neighbour_metric

        if sender_id not in self.routing_table.keys():
            self.create_table_entry(sender_id, sender_metric, sender_id, sender_port)
        else:
            for neighbour_port, neighbour_metric, neighbour_id in self.output_ports:
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
                if distance < self.routing_table[destination]["metric"] or self.routing_table[destination]["next_hop_id"] == sender_id:
                    self.routing_table[destination]["metric"] = distance
                    self.routing_table[destination]["next_hop_id"] = sender_id
                    self.routing_table[destination]["next_hop"] = sender_port
            
                if(distance < 16 and self.routing_table[destination]["next_hop_id"] == sender_id):
                    self.reset_timeout(destination)
            
            elif(destination != self.router_id and not distance > 15):
                self.create_table_entry(destination, distance, sender_id, sender_port)

            if destination!= self.router_id:
                if self.routing_table[destination]["metric"] > 15:
                    self.routing_table[destination]["metric"] = 16
                    self.routing_table[destination]["deleted_route"] = True                
                    if(self.routing_table[destination]["garbage"] == False):
                        self.set_garbage_timer(destination)


my_router = Router(sys.argv[1])