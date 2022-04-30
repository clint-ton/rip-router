import socket
import time
import sys
import select
from copy import deepcopy

# constants
COMMAND = 2
VERSION = 2
TIMEOUT = 0

# globals
routing_table = {}

def readConfig(filename):
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
    while line < (len(lines) - 1):
        lines[line] = lines[line].strip()
        lines[line] = lines[line].split()
        if(lines[line][0] == "router-id" and int(lines[line][1]) <= 64000 and len(lines[line]) == 2):
            if(int(lines[line][1]) <= 64000 and len(lines[line]) == 2):
                routerId = int(lines[line][1])
            else: raise Exception("Router-id incorrectly specified")
            
        if(lines[line][0] == "input-ports"):
            for port in lines[line][1:]:
                if(1024 <= int(port) <= 64000 and int(port) not in inputPorts):
                    inputPorts.append(int(port))
                else: raise Exception("Input ports specified incorrectly")

        if(lines[line][0] == "outputs"):
            for port in lines[line][1:]:
                outputPort = []
                port = port.split("-")
                if checkPorts(port, outputPorts, inputPorts):
                        for i in port:
                            outputPort.append(int(i))
                outputPorts.append(outputPort)
                
        if(lines[line][0] == "timer-values"):
            timerVals = lines[line][1].split("-")
            if(timerValues[1] / timerValues[0] == 6 and timerValues[2] / timerValues[0] == 4 and len(timerValues) == 3):
                for time in timerVals:
                    timerValues.append(int(time))
            else:
                timerValues = [30, 80, 120]
        else:
            timerValues = [30, 80, 120]
                
        line += 1

    return (routerId, inputPorts, outputPorts, timerValues)

def resetUpdateTimer(updateTimer):
    return time.time() + updateTimer

def checkPorts(port, outputPorts, inputPorts):
    if(len(port) == 3 and int(port[0]) not in inputPorts and 1 <= int(port[2]) <= 64000 and 1 <= int(port[1]) <= 15 and 1024 <= int(port[0]) <= 64000):
        if len(outputPorts) > 0:
            for i in outputPorts:
                if i[0] == int(port[0]): raise Exception("Output ports incorrectly specified")
                else: return True
        else: return True
    else: raise Exception("Output ports incorrectly specified")


def sendUpdate(updatePeriod, updateTimer, routerId, inputSockets, outputPorts, flag=False):
    if time.time() >= updatePeriod:
        updatePeriod = resetUpdateTimer(updateTimer)
        print("Router ID:", routerId)
        printTable()
        for socket in inputSockets:
            for port in outputPorts:
                updatePacket = create_update_packet(routerId, port[2], routing_table, flag)
                inputSockets[socket].sendto(updatePacket, ('localhost', port[0]))

def running(current_id, queue, updatePeriod, updateTimer, inputSockets, outputSocket):
    while True:
        read, write, special = select.select(inputSockets, outputSocket, [])
        for i in read:
            try:
                data, addr = i.recvfrom(BUFFER_SIZE)
                queue.append((data, addr))
            except:
                # print("Error recieving a packet")
                buffer = 0
        
        sendUpdate(updatePeriod, updateTimer, current_id, inputSockets, outputSocket)
        
        for message in queue:
            data, addr = queue.pop(0)
            port = addr[1]
            processPacket(port, data, timeoutTimer, garbageTimer, outputPorts, routerId)

        sendTriggeredUpdate = False
        for route in routing_table:
            if(routing_table[i]["infiniteRouteFlag"] == True):
                sendUpdate(updatePeriod, updateTimer, routerId, inputSockets, outputPorts, True)
                for i in routing_table: routing_table[i]["infiniteRouteFlag"] = False

        for entry in deepcopy(routing_table):
            checkTimeout(entry, timeoutTimer, garbageTimer)

        printTable()    

def create_sockets(input_ports):
    input_sockets = []
    for port in input_ports:
        try:
            UDP_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            UDP_socket.bind(('localhost', port))
            input_sockets.append(UDP_socket)
        except:
            print("Error opening a socket on port " + port)
    return input_sockets

def create_update_packet(sender_id, dest_id, routing_table, triggered_update=False):
    packet = bytearray()
    packet.append(COMMAND.to_bytes(1, 'big')[0])
    packet.append(VERSION.to_bytes(1, 'big')[0])
    sender_id_bytes = sender_id.to_bytes(2, 'big')

    for byte in sender_id_bytes:
        packet.append(byte)

    for key, value in routing_table.items():
       if triggered_update:
            if value["infiniteRouteFlag"]:
                create_route_entry(routing_table, packet, dest_id, key)
            else:
                create_route_entry(routing_table, packet, dest_id, key)

    return packet

def createRouteEntry(routing_table, packet, dest_id, route_id):
    AFI = 2
    AFIBytes = AFI.to_bytes(2, 'big')
    for i in AFIBytes: packet.append(i)
    for i in range(0, 2): packet.append(0x00)
    routeDestBytes = routeEntry.to_bytes(4, 'big')
    for i in routeDestBytes: packet.append(i)
    for i in range(0, 8): packet.append(0x00)
    # split horizon with poison reverse
    if(routing_table[routeEntry]["next_hop_id"] == dest_id):
        metric = 16
        metricBytes = metric.to_bytes(4, 'big')
    else:
        metricBytes = routingTable[routeEntry]["metric"].to_bytes(4, 'big')
    for i in metricBytes: packet.append(i)


def create_table_entry(router_id, metric, next_hop_id, next_hop):
    data = {
        "metric" : metric,
        "next_hop": next_hop,
       "next_hopId": next_hop_id,
        "timeout" : time.time() + self.timeout_timer,
        "garbage" : False,
        "infinite_route_flag" : False
    }

    routing_table[routerId] = data

def process_packet(packet, sender_port, current_router_id):
    # exit discard packet if not valid
    if not checkPacket(packet):
        return
    entry_count = int((len(packet) - 4) / 20)
    entries = packet[4:]

    sender_id = int.from_bytes(packet[2:4], 'big')

    for neighbour_port, neighbour_metric, neighbour_id in neighbours:
       if(sender_id == neighbour_id):
            sender_metric = neighbour_metric

    if sender_id not in routing_table.keys():
        createTableEntry(sender_id, sender_metric, sender_id, sender_port)
    else:
        for neighbour_port, neighbour_metric, neighbour_id in neighbours:
            if sender_id == neighbour_id and neighbour_metric < routing_table[sender_id]['metric']:
                routing_table[sender_id]['next_hop'] = neighbour_port
                routing_table[sender_id]['metric'] = neighbour_metric
                routing_table[sender_id]['next_hop_id'] = neighbour_id
        routing_table[sender_id]['garbage'] = False
        resetTimeout(sender_id, timeout)

    for i in range(entry_count):
        # TODO split up
        dest = bytearray()
        metric = bytearray()

        for j in range(4, 8):
            destination.append(entries[20 * i + j])
        for j in range(16, 20):
            metric.append(entries[20 * i + j])
    
        destination = int.from_bytes(destination, "big")
        metric = int.from_bytes(metric, "big")

        distance = sender_metric 

        if destination in self.routing_table.keys():
            if distance < routing_table[destination]["metric"] or routing_table[destination]["nextHopId"] == senderId:
                routing_table[destination]["infinite_route_flag"] = False
                routing_table[destination]["metric"] = distance
                routing_table[destination]["next_hop_id"] = senderId
                routing_table[destination]["next_hop"] = senderPort
            
            if(distance < 16 and routing_table[destination]["nextHopId"] == senderId):
                resetTimeout(destination, timeoutTimer)
                routing_table[destination]["garbage"] = False
            
        elif(destination != currentRouterId and not distance > 15):
            createTableEntry(destination, distance, senderId, senderPort, timeoutTimer)

        if destination!= current_router_id:
            if routing_table[destination]["metric"] > 15:
                routing_table[destination]["metric"] = 16
                routing_table[destination]["infiniteRouteFlag"] = True                
                if(routing_table[destination]["garbage"] == False):
                    setGarbage(destination, garbageTimer)

def printTable():
    print(  " +-------------+--------+----------+-------------+---------+---------+---------------------+\n",
            "| Destination | Metric | Next Hop | Next Hop ID | Timeout | Garbage | Infinite Route Flag |\n",
            "+-------------+--------+----------+-------------+---------+---------+---------------------+")
    # copy table so it cant update during print
    copied_table = deepcopy(routing_table)
    for link in copied_table:
        data = copied_table[link]
        timeout = int(data["timeout"] - time.time())
        if data["garbage"]:
            garbage = timeout
            timeout = '-'
        else:
            garbage = '-'
        if not data["infiniteRouteFlag"]:
            infiniteRouteFlag = "Not Set"
        else:
            infiniteRouteFlag = "Set"
        print(" |{0:^13}|{1:^8}|{2:^10}|{3:^13}|{4:^9}|{5:^9}|{6:^21}|".format(link, data["metric"], data["nextHop"], data["nextHopId"], timeout, garbage, infiniteRouteFlag))
    print(" +-------------+--------+----------+-------------+---------+---------+---------------------+")
    
def main():

    routerId, inputPorts, outputPorts, timerValues = readConfig(sys.argv[1])
    print("Router ID:", routerId)
    print("Input Ports:", end=" ")
    for i in inputPorts: print(i, end=", ")
    print()
    print("Output Ports:", end=" ")
    for i in outputPorts: print(i, end=", ")
    print()
    print("Timer Values:", timerValues)

    
    inputSockets = create_sockets(inputPorts)
    outputSocket = [inputSockets[0]]
    updateTimer, timeoutTimer, garbageTimer = timerValues
    update_period = resetUpdateTimer(updateTimer)
    queue = []
    # TODO maybe dont need to pass through timers?
    running(routerId, queue, update_period, updateTimer, inputSockets, outputSocket)
    


if __name__ == '__main__':
    main()

















