import requests, json, sys
from socketIO_client import SocketIO, BaseNamespace


# Disable warnings about unverified certificates
if hasattr(requests, 'packages') and hasattr(requests.packages, 'urllib3'):
    requests.packages.urllib3.disable_warnings()

# Load from your config file
server_ip = "1.2.3.4"
northstar_username ="*****"
northstar_password = "******"
auth_header = {"Authentication":""}

def connect_to_northstar():

  # Get our NS authentication token
  print("Attempting to connect to Northstar: {ip}".format(ip=server_ip))
  northstar_url = "https://{server_ip}:8443/".format(server_ip=server_ip)

  auth_url = northstar_url + "oauth2/token"
  payload = {'grant_type': 'password', 'username': northstar_username, 'password': northstar_password}
  auth_tuple = (northstar_username, northstar_password)

  try:
    response = requests.post(auth_url, data=payload, auth=auth_tuple, verify=False)
    print payload
  except:
    print("Failed to connect to server")
  else:
    if response.status_code != 200:
      print("Failed to authenticate")
    else:
      auth_data = json.loads(response.text)
      print auth_data
      auth_header['Authorization'] = "{token_type} {access_token}".format(**auth_data)

# Get all of the data needed (Topology and LSP)
def gather_topology():
#def gather_topology(auth_header):


    print("Attempting to collect data")

    # Retrieve the topology
    northstar_url = "https://{server_ip}:8443/NorthStar/API/V2/tenant/1/topology/1".format(server_ip=server_ip)
    response_topology = requests.get(northstar_url, headers=auth_header, verify=False)

    # Retrieve the LSPs
    northstar_url = "https://{server_ip}:8443/NorthStar/API/V2/tenant/1/topology/1/te-lsps/".format(server_ip=server_ip)
    response_lsp_te = requests.get(northstar_url, headers=auth_header, verify=False)

    # Store our raw data in a dictionary
    data = {
      "topology": response_topology.json(),
      "lsp_te": response_lsp_te.json()

    }

    return data


class Topology():
    """
    class that repersents the overall network topology
    """

    def __init__(self, data):
        self.controller_ip = server_ip
        self.nodes = {}
        self.hostName_to_node = {}
        self.node_to_ip = {}
        self.ip_to_node = {}
        self.links = {}
        self.username = northstar_username
        self.password = northstar_password
        self.api_auth_key = auth_header
        self.graph = self.build_graph()
        self.connections = {}
        self.initialize_topology(data)

    def initialize_topology(self, topologyData):
        """
        Method that starts the Topology. This gets all nodes, links, default connections
        and populates their default values
        """
        # TODO Optimize these and their performance. Currently takes 2 minutes
        # for initization
        print("Initializing Topology...")
        self.get_and_build_nodes(topologyData['nodes'])
        self.get_and_build_links(topologyData['links'])
        self.build_node_connections(topologyData)
        self.update_links_status(topologyData['links'])
        self.update_latency()
        Connection(self, "Helena", "Detroit")
        Connection(self, "Detroit", "Helena")
        #for con in self.connections:
        #    for lsp in self.connections[con].possible_paths:
        #        lsp.update_lsp_metrics()
        #    self.connections[con].find_and_set_class_lsps()

    def converge_and_apply_lsp(self):
        """ Function that gets and converges the network to find optimum LSPs.
            calls::
                self.connections.find_and_set_class_lsps()
                self.update_links_status()
                self.update_latency()
        """
        print("Converging the Topology\n")

        for connection in self.connections:
            for path in self.connections[connection].possible_paths:
                path.update_lsp_metrics()
            self.connections[connection].find_and_set_class_lsps()
            # Send regular group
            self.send_lsp_update(
                "GROUP_NINE_" + self.connections[
                    connection].start + "_" + self.connections[
                        connection].end + "_LSP4", self.connections[
                            connection].regular_paths.ero_format)

            # Send plus group
            self.send_lsp_update(
                "GROUP_NINE_" + self.connections[
                    connection].start + "_" + self.connections[
                        connection].end + "_LSP3", self.connections[
                            connection].plus_paths.ero_format)
            # Send premium group
            i = 1
            for lsp in self.connections[connection].premium_paths:
                self.send_lsp_update(
                    "GROUP_NINE_" + self.connections[
                        connection].start + "_" + self.connections[
                            connection].end + "_LSP" + str(i), self.connections[
                                connection].premium_paths[lsp].ero_format)
                i = i + 1
            ping_vms()

    def send_lsp_update(self, lsp, new_path):
        print("Updating ", lsp['name'], "on NorthStar Controller")
        # Fill only the required fields
        ero = []
        for ip_address in new_path:
          hop = {
            "topoObjectType": "ipv4",
            "address": ip_address,
 #           "loose" : True,
          }
          ero.append(hop)
        new_lsp = {}
        for key in ('from', 'to', 'name', 'lspIndex', 'pathType', 'provisioningType'):
            new_lsp[key] = lsp[key]

        new_lsp['plannedProperties'] = {
            'ero': ero
        }

        northstar_url = "https://{server_ip}:8443/NorthStar/API/V2/tenant/1/topology/1/te-lsps/{index}".format(server_ip=server_ip, index=str(new_lsp['lspIndex']))
        response = requests.put(northstar_url, headers=auth_header, json=new_lsp, verify=False)
        if response.status_code != 200:
            print 'Update failed, ', response.status_code
        else:
            print("LSP Updated on NorthStar Controller")
        print '------'

    def build_graph(self):
        """
        Method builds the graphing dictionary for routing algorithms
        """
        graph = {}
        for node in self.nodes:
            graph.update(self.nodes[node].connections)
        return graph

    def get_and_build_nodes(self, nodeData):
        """
        Method that makes a api call into Northstar topology
        parses results and add unknown nodes into the topology node array
        """
        print("Building nodes...")
        for each in nodeData:
            node_name = (each["id"])
            if node_name not in self.nodes:
                node_ip = each["routerId"]
                node_lat = each["topology"]["coordinates"]["coordinates"][0]
                node_long = each["topology"]["coordinates"]["coordinates"][1]
                the_node = TopologyNode(
                        node_name, node_lat, node_long, node_ip, {node_name: []})
                self.nodes.update({node_name: the_node})
                self.node_to_ip.update({node_name: node_ip})
                self.ip_to_node.update({node_ip: node_name})
                self.hostName_to_node.update({each['hostName']: the_node})

    def build_node_connections(self, data):
        """ For each node collect what nodes it connects to """
        print("Building CE/PE Connections...")
        node_connections = {}
        for each in data['nodes']:
            node_name = (each["id"])
            node_connections.update({node_name: []})
            for links in data['links']:
                if links["endA"]["node"]["id"] == self.node_to_ip[node_name]:
                    node_connections[node_name].append(
                        self.ip_to_node[links['endZ']["node"]["id"]])
                if links["endZ"]["node"]["id"] == self.node_to_ip[node_name]:
                    node_connections[node_name].append(
                        self.ip_to_node[links['endA']["node"]["id"]])
        for node in node_connections:
            for nod3 in self.nodes:
                if node == nod3:
                    for n0de in node_connections[node]:
                        self.nodes[node].connections[node].append(n0de)

    def get_and_build_links(self, linkData):
        """
        Method the makes api call to get topology links
        Then creates link objects and adds to topology
        """
        print("Building links...")
        for each in linkData:
            if each['operationalStatus'] == 'Unknown' or not 'interfaceName' in each['endA'] or not 'interfaceName' in each['endZ']:
                continue
            from_node = each["endA"]["node"]["id"]
            from_ip = each["endA"]["ipv4Address"]["address"]
            from_interface = each['endA']['interfaceName']
            to_node = each["endZ"]["node"]["id"]
            to_ip = each["endZ"]["ipv4Address"]["address"]
            if to_node in self.node_to_ip:
                to_node = self.nodes[to_node]
            if from_node in self.node_to_ip:
                from_node = self.nodes[from_node]
            link_name = from_node.ip_address + "_to_" + to_node.ip_address
            if link_name not in self.links:
                the_link = TopologyLink(
                    from_node, from_ip, to_node, to_ip)
                from_node.links.update({from_interface: the_link})
                self.links.update({link_name: the_link})
            # And now in reverse :D
            from_node = each["endZ"]["node"]["id"]
            from_ip = each["endZ"]["ipv4Address"]["address"]
            from_interface = each['endZ']['interfaceName']
            to_node = each["endA"]["node"]["id"]
            to_ip = each["endA"]["ipv4Address"]["address"]
            if to_node in self.node_to_ip:
                to_node = self.nodes[to_node]
            if from_node in self.node_to_ip:
                from_node = self.nodes[from_node]
            link_name = from_node.ip_address + "_to_" + to_node.ip_address
            if link_name not in self.links:
                the_link = TopologyLink(
                    from_node, from_ip, to_node, to_ip)
                from_node.links.update({from_interface: the_link})
                self.links.update({link_name: the_link})

    def update_links_status(self, linkData):
        print("Updating Link Status...")
        """ Method makes API call into northstar and get link status """
        for link in linkData:
            self.update_link_status(link)

    def update_link_status(self, event):
        from_node = event['endA']['node']['id']
        to_node = event['endZ']['node']['id']
	status = event["operationalStatus"]
        if to_node in self.node_to_ip:
            to_node = self.node_to_ip[to_node]
        if from_node in self.node_to_ip:
            from_node = self.node_to_ip[from_node]
        link_name = from_node + "_to_" + to_node
        if link_name in self.links:
            self.links[link_name].current_status = status
        link_name = to_node + "_to_" + from_node
        if link_name in self.links:
            self.links[link_name].current_status = status

    # Gather network health statistics
    def gather_statistics(self, type, requested_fields):
        '''
        EXAMPLE FORMAT FOR REQUESTING DATA
        GETS "interface_stats.egress_stats.if_bps" & "interface_stats.ingress_stats.if_pps"
        requested_fields = {
          'endTime': 'now',
          'startTime': 'now-1h',
          'aggregation': 'avg',
          'interval': '1m',
          'counter': ['interface_stats.egress_stats.if_bps', 'interface_stats.ingress_stats.if_pps']
        }
        '''
        result = requests.post('https://{server_ip}:8443/NorthStar/API/v2/tenant/1/statistics/{type}/bulk'.format(server_ip=server_ip, type=type),
                               headers=auth_header, verify=False, data=requested_fields)
        return result.json()

    def update_latency(self):
        """ Method makes a redis call to get latency for each link """
        print("Updating Latency Metrics...")

        requested_fields_delay = {
          'endTime': 'now',
          'startTime': 'now-20m',
          'aggregation': 'max',
          #'aggregation': 'avg',
          'interval': '1m',
          'counter': [ 'max_rtt']
          #'counter': [ 'average_rtt']
          #'counter': [ 'max_rtt', 'average_rtt', 'loss_percent']
        }
        # Retrieve delay/loss related statistics for all interfaces
        delay_stats = self.gather_statistics('interfaces', requested_fields_delay)
        for latency in delay_stats:
            if not type(delay_stats[latency]) is dict:
                continue
            hostName = delay_stats[latency]['id']['node']['hostName']
            interface = delay_stats[latency]['id']['name']
            rtt = delay_stats[latency]['max_rtt'][0]
            #rtt = delay_stats[latency]['average_rtt'][0]
            if rtt == None:
                rtt = 0
            node = self.hostName_to_node[hostName]
            if interface in node.links:
                node.links[interface].current_latency = rtt


class TopologyNode():
    """ Class that repersents a node
        Attributes:
            name String
            Connections [] of sub class Links
    """

    def __init__(self, name, lat, longit, ip, connections):
        self.name = name
        self.ip_address = ip
        self.connections = connections
        self.latitude = lat
        self.longitude = longit
        # interface : TopologyLink
        self.links = {}

    def __str__(self):
        cons = ""
        for con in self.connections:
            cons = cons + con
        return "Node at: " + self.name + "Connects to " + cons

    def bugg_off_pylint(self):
        """ bugg off pylint
        """
        print("bugg off linter for ", self.name)


class TopologyLink():
    """ Class that repersents the Links belonging to a node
        Attributes:
            name
            fromNode
            toNode
            currentLatency
            currentStatus
    """

    def __init__(self, fromNode, from_int_ip, toNode, to_int_ip):
        self.name = fromNode.ip_address + "_to_" + toNode.ip_address
        self.from_node = fromNode.ip_address
        self.to_node = toNode.ip_address
        self.from_int_ip = from_int_ip
        self.to_int_ip = to_int_ip
        self.current_latency = 0
        self.current_status = str


class Connection():
    """
    Class repersents a pair of start and end nodes that will have LSPs.
    The Path is uni-directional. for bi-lateral paths there should be 2 objects A->B & B->A
    Class keeps attributes of the connection.
    Inputs:
        Topology
        start
        end
    """

    def __init__(self, topology, start, end):
        self.name = start + "_to_" + end
        self.start = start
        self.end = end
        self.premium_paths = {}
        self.plus_path = {}
        self.regular_path = {}
        self.possible_paths = []
        #paths = find_all_paths(topology.build_graph(), start, end)
        #for path in paths:
        #    self.possible_paths.append(PossibleLSP(topology, path, start, end))
        topology.connections.update({self.name: self})

    def find_and_set_class_lsps(self):
        # Find Premium One
        def find_premium1(topo):
            relevant_latency = 99999
            for possible in topo.possible_paths:
                if possible.up_status == "Up":
                    if possible.total_latency < relevant_latency:
                        premium_one = possible
                        return premium_one

        def find_premium2(topo, premium_one):
            # Find Premium Two
            relevant_latency = 99999
            for possible2 in topo.possible_paths:
                links_in = []
                if possible2 != premium_one:
                    if possible2.up_status == "Up":
                        for indx, link in enumerate(possible2.links_in_path):
                            if link in premium_one.links_in_path:
                                links_in.append("yes")
                            else:
                                links_in.append("no")
                            reverse = link.split("_to_")
                            if reverse[1] + "_to_" + reverse[0] in premium_one.links_in_path:
                                links_in.append("yes")
                            else:
                                links_in.append("no")
                        if "yes" not in links_in:
                            if possible2.total_latency < relevant_latency:
                                premium_two = possible2
                                return premium_two

        def find_plus(topo, premium_one, premium_two):
            # Find plus
            relevant_latency = 99999
            for possible3 in topo.possible_paths:
                if possible3 != premium_one:
                    if possible3 != premium_two:
                        if possible3.up_status == "Up":
                            if possible3.total_latency < relevant_latency:
                                plus = possible3
                                return plus

        def find_regular(topo, premium_one, premium_two, plus):
            # Find regular
            relevant_latency = 99999
            for possible4 in self.possible_paths:
                if possible4 != premium_one:
                    if possible4 != premium_two:
                        if possible4 != plus:
                            if possible4.up_status == "Up":
                                if possible4.total_latency < relevant_latency:
                                    regular = possible4
                                    return regular
        premium_one = find_premium1(self)
        premium_two = find_premium2(self, premium_one)
        plus = find_plus(self, premium_one, premium_two)
        regular = find_regular(self, premium_one, premium_two, plus)

        # Updates the class values
        self.premium_paths = {"premium_One": premium_one, "premium_Two": premium_two}
        self.plus_paths = plus
        self.regular_paths = regular
        print("**********")
        print("Optimum LSPs Found for ", self.name, ": ")
        print("premium 1 LSP:", premium_one.path)
        print("premium 2 LSP:", premium_two.path)
        print("plus LSP:", plus.path)
        print("regular LSP:", regular.path)

def get_all_paths(start_node, end_node, topology):
    """:param start_node:
    :param end_node:
    :return: list of path, sort by tot_latency
    """
    def get_paths(start, end, path, seen, tot, topology):
        if len(path) > 4: return

        if start.name == end.name:
            paths.append([tot] + path)
            return

        seen.add(start.ip_address)
        for interf in start.links:
            link = start.links[interf]
            if link.current_status == 'Down': continue
            if link.to_node in seen: continue
            path.append(str(link.to_int_ip))
            to_node = topology.nodes[topology.ip_to_node[link.to_node]]
            get_paths(to_node, end, path, seen, tot+link.current_latency, topology)
            path.pop()
        seen.discard(start.ip_address)



    paths = []
    get_paths(start_node, end_node, [], set(), 0, topology)
    return sorted(paths)


def update_lsps(TOPO):
    start = TOPO.nodes['0192.0168.0147']
    end = TOPO.nodes['0192.0168.0148']
    paths = get_all_paths(start, end, TOPO)
    paths_reverse = get_all_paths(end, start, TOPO)

    for lsp in data['lsp_te']:
        if lsp['name'] == 'SR-LSP-West-East-One':
            TOPO.send_lsp_update(lsp, paths[0][1:])
            print 'update ', lsp['name'], ' to path ', paths[0][1:]
        elif lsp['name'] == 'SR-LSP-West-East-Two':
            TOPO.send_lsp_update(lsp, paths[1][1:])
            print 'update ', lsp['name'], ' to path ', paths[1][1:]
        elif lsp['name'] == 'SR-LSP-West-East-Three':
            TOPO.send_lsp_update(lsp, paths[2][1:])
            print 'update ', lsp['name'], ' to path ', paths[2][1:]
        elif lsp['name'] == 'SR-LSP-West-East-Four':
            TOPO.send_lsp_update(lsp, paths[3][1:])
            print 'update ', lsp['name'], ' to path ', paths[3][1:]
        elif lsp['name'] == 'SR-LSP-East-West-One':
            TOPO.send_lsp_update(lsp, paths_reverse[0][1:])
            print 'update ', lsp['name'], ' to path ', paths_reverse[0][1:]
        elif lsp['name'] == 'SR-LSP-East-West-Two':
            TOPO.send_lsp_update(lsp, paths_reverse[1][1:])
            print 'update ', lsp['name'], ' to path ', paths_reverse[1][1:]
        elif lsp['name'] == 'SR-LSP-East-West-Three':
            TOPO.send_lsp_update(lsp, paths_reverse[2][1:])
            print 'update ', lsp['name'], ' to path ', paths_reverse[2][1:]
        elif lsp['name'] == 'SR-LSP-East-West-Four':
            TOPO.send_lsp_update(lsp, paths_reverse[3][1:])
            print 'update ', lsp['name'], ' to path ', paths_reverse[3][1:]

def reset_lsps(TOPO):
    start = TOPO.nodes['0192.0168.0147']
    end = TOPO.nodes['0192.0168.0148']
    path = ['10.147.5.2', '10.148.5.1']
    path_reverse = ['10.148.5.2', '10.147.5.1']

    for lsp in data['lsp_te']:
        if lsp['name'] == 'SR-LSP-West-East-One':
            TOPO.send_lsp_update(lsp, path)
            print 'update ', lsp['name'], ' to path ', path
        elif lsp['name'] == 'SR-LSP-West-East-Two':
            TOPO.send_lsp_update(lsp, path)
            print 'update ', lsp['name'], ' to path ', path
        elif lsp['name'] == 'SR-LSP-West-East-Three':
            TOPO.send_lsp_update(lsp, path)
            print 'update ', lsp['name'], ' to path ', path
        elif lsp['name'] == 'SR-LSP-West-East-Four':
            TOPO.send_lsp_update(lsp, path)
            print 'update ', lsp['name'], ' to path ', path
        elif lsp['name'] == 'SR-LSP-East-West-One':
            TOPO.send_lsp_update(lsp, path_reverse)
            print 'update ', lsp['name'], ' to path ', path_reverse
        elif lsp['name'] == 'SR-LSP-East-West-Two':
            TOPO.send_lsp_update(lsp, path_reverse)
            print 'update ', lsp['name'], ' to path ', path_reverse
        elif lsp['name'] == 'SR-LSP-East-West-Three':
            TOPO.send_lsp_update(lsp, path_reverse)
            print 'update ', lsp['name'], ' to path ', path_reverse
        elif lsp['name'] == 'SR-LSP-East-West-Four':
            TOPO.send_lsp_update(lsp, path_reverse)
            print 'update ', lsp['name'], ' to path ', path_reverse

connect_to_northstar()
data = gather_topology()
TOPO = Topology(data['topology'])

class NSNotificationNamespace(BaseNamespace):
  def on_connect(self):
    print('Connected to %s:8443/restNotifications-v2'%serverURL)
  def on_event(key,name,data):
    print "NorthStar Event: %r"%(name)
    if data['notificationType'] == 'link':
      print 'Got Link update: '
      obj = data['object']
      print 'id: ',obj['id']
      from_ = obj['endA']
      to = obj['endZ']
      print 'from ',from_['ipv4Address']['address']
      print 'to ',to['ipv4Address']['address']
      print 'status: ', obj['operationalStatus']
      TOPO.update_link_status(obj)
      TOPO.update_latency()
      update_lsps(TOPO)
    elif data['notificationType'] == 'node':
      print 'Got Node update'
    else:
      print 'Got Other update'
    print ''

if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == 'reset':
        reset_lsps(TOPO)
        sys.exit(0)
    for node in TOPO.nodes:
        print "Node: ", TOPO.nodes[node].name, " ", TOPO.nodes[node].ip_address
    print ''
    print ''
    for link in TOPO.links:
        l = TOPO.links[link]
        print 'link: ', l.name, ' from ', l.from_node, '|', l.from_int_ip, ' to ', l.to_node, '|', l.to_int_ip, ' latency ', l.current_latency, ' status ', l.current_status

    print ''
    print ''
    update_lsps(TOPO)

    print ''
    print ''

    serverURL = 'https://' + server_ip
    socketIO = SocketIO(serverURL, 8443,verify=False,headers= auth_header)
    ns = socketIO.define(NSNotificationNamespace, '/restNotifications-v2')
    socketIO.wait()
