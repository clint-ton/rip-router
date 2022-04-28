import socket

# constants
COMMAND = 2
VERSION = 2


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

class Router:
    def __init__(self):
        self.routing_table = {"hello": "world"}
        # TODO actually add the portnumbers
        # self.input_sockets = create_sockets("idk man")
        # self.output_socket = self.input_sockets[0]

    def create_update_packet(self, sender_id, dest_id, routing_table, triggered_update=False):
        packet = bytearray()
        packet.append(COMMAND.to_bytes(1, 'big')[0])
        packet.append(VERSION.to_bytes(1, 'big')[0])
        packet.append(0x00)
        packet.append(0x00)

        for key, value in self.routing_table.items():
            if triggered_update:
                if value["infiniteRouteFlag"]:
                    createRouteEntry(routingTable, packet, destId, i)
            else:
                createRouteEntry(routingTable, packet, destId, i)

        return packet



                

router = Router()

router.create_update_packet(1, 2, 3, 4)




