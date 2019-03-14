import requests, json, sys
'''
This file will help you send the GET commend to the Juniper NorthStar controller
to reterive the latest node info, path info, traffic info to calculate the
weighted shortest path info.

This file will help you send the POST command to the Juniper NorthStar controller
to update the shortest path info.
'''

# Disable warnings about unverified certificates
if hasattr(requests, 'packages') and hasattr(requests.packages, 'urllib3'):
    requests.packages.urllib3.disable_warnings()

# Load from your config file.....
server_ip = "1.2.3.4"
northstar_username ="********"
northstar_password = "********"
auth_header = {"Authentication":""}

# Connect to your northstar server and return a token for authorization and future api calls
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

# Alter an existing LSP
def modify_lsp(lsp, new_path):
  '''
  :param name: Name of LSP
  :param path: A list of IPs/Hops that the LSP needs to traverse.
  :return:
  '''
  result = requests.get('https://{server_ip}:8443/NorthStar/API/v2/tenant/1/topology/1/te-lsps/{lsp}'.format(server_ip=server_ip, lsp=str(lsp['lspIndex'])), headers=auth_header, verify=False)
  lsp = result.json()
  print "??????????"
  print lsp
  print "??????????"

  new_lsp = {}

  # Clear the ERO Data
  new_lsp['from'] = lsp['from']
  new_lsp['to'] = lsp['to']
  new_lsp['name'] = lsp['name']
  new_lsp['pathType'] = lsp['pathType']
  new_lsp['lspIndex'] = lsp['lspIndex']
  
  ero = []

  # Build new ERO Data
  for ip_address in new_path:
    hop = {
      "topoObjectType": "ipv4",
      "address": ip_address,
 #     "loose" : True,
    }
    ero.append(hop)

  new_lsp['plannedProperties'] = {
#    'preferredEro' : ero
    #'ero' : ero
     'calculatedEro' : []
     #'calculatedEro' : ero
  }
  new_lsp = json.dumps(new_lsp)


  result = requests.put('https://{server_ip}:8443/NorthStar/API/v2/tenant/1/topology/1/te-lsps/817'.format(server_ip=server_ip), json=new_lsp, headers=auth_header, verify=False)
  #result = requests.put('https://{server_ip}:8443/NorthStar/API/v2/tenant/1/topology/1/te-lsps/{lsp}'.format(server_ip=server_ip, lsp=str(new_lsp['lspIndex'])), json=new_lsp, headers=auth_header, verify=False)
  print("@@@@@@@@@@@@@@@@@@@@@@")
  print(new_lsp)
  print lsp['lspIndex']
  print("@@@@@@@@@@@@@@@@@@@@@@")
  #result = requests.put('https://{server_ip}:8443/NorthStar/API/v2/tenant/1/topology/1/te-lsps/{lsp}'.format(server_ip=server_ip, lsp=str(lsp['lspIndex'])), json=lsp, headers=auth_header, verify=False)

  return result

def send_lsp_update(lsp_name, new_path):
    """ Sends the API call for updating ERO for LSPs
        Input is the ero array that is to be sent.
        expected format::
                ero= [
                                { 'topoObjectType': 'ipv4', 'address': '10.210.15.2'},
                                { 'topoObjectType': 'ipv4', 'address': '10.210.13.2'},
                                { 'topoObjectType': 'ipv4', 'address': '10.210.17.1'}
                               ]
    Updates the northstar controller with the new LSPs.
    ERO Name/ Number mapping to Class ranking (same for both directions):
    LSP1: Premium 1: The lowest Latency link.
              Intended for real time applications
    LSP2: Premium 2: The second lowest latency redundant link from gold One
              Intended for real time and business critical applications
    LSP3: Plus: The second lowest latency link that is not Gold Two
              Intended for business relevant applications
    LSP4: Regular: The third lowest latency link that is neither gold one, gold two or silver
              Intended for scavenger class applications
    """
    print("Updating ", lsp_name, "on NorthStar Controller")
    requs = requests.get(
        'https://' + server_ip +
        ':8443/NorthStar/API/v1/tenant/1/topology/1/te-lsps/',
        headers=auth_header, verify=False)
    dump = json.dumps(requs.json())
    lsp_list = json.loads(dump)
    # Find target LSP to use lspIndex
    for lsp in lsp_list:
        if lsp['name'] == lsp_name:
            break
    # Fill only the required fields
  #  ero = ero_input
    ero = []

    # Build new ERO Data

    print lsp
    for ip_address in new_path:
      hop = {
        "topoObjectType": "ipv4",
        "address": ip_address,
 #       "loose" : True,
      }
      ero.append(hop)
    new_lsp = {}
# "provisioningType":"SR"
    for key in ('from', 'to', 'name', 'lspIndex', 'pathType', 'provisioningType'):
        new_lsp[key] = lsp[key]

    new_lsp['plannedProperties'] = {
         "bandwidth": "100M",
        'ero': ero
 #       'calculatedEro' : []
         #'preferredEro' : ero
    }
    response = requests.put(
        'https://10.10.2.64:8443/NorthStar/API/v1/tenant/1/topology/1/te-lsps/' + str(new_lsp[
            'lspIndex']),
        json=new_lsp, headers=auth_header, verify=False)
    print("LSP Updated on NorthStar Controller")
    print response

def modify_lsp2(lsp, new_path):
  '''
  :param name: Name of LSP
  :param path: A list of IPs/Hops that the LSP needs to traverse.
  :return:
  '''


  lspIdx = lsp['lspIndex']
  print lspIdx
  dd = { 'op' : 'replace', "path": '/plannedProperties/ero', 'value':[] }
  body = []
  body.append(dd)

  # Build new ERO Data
  for ip_address in new_path:
    hop = {
      "topoObjectType": "ipv4",
      "address": ip_address,
      "loose" : True,
    }
    dd['value'].append(hop)

  result = requests.get('https://{server_ip}:8443/NorthStar/API/v2/tenant/1/topology/1/te-lsps/{lsp}'.format(server_ip=server_ip, lsp=str(lspIdx)), headers=auth_header, verify=False)
  print "LLLLLLL"
  print result
  print "LLLLLLL"
  result = requests.patch('https://{server_ip}:8443/NorthStar/API/v2/tenant/1/topology/1/te-lsps/{lsp}'.format(server_ip=server_ip, lsp=str(lspIdx)), json=body, headers=auth_header, verify=False)
  print("@@@@@@@@@@@@@@@@@@@@@@")
  print(body)
  print("@@@@@@@@@@@@@@@@@@@@@@")
  #result = requests.put('https://{server_ip}:8443/NorthStar/API/v2/tenant/1/topology/1/te-lsps/{lsp}'.format(server_ip=server_ip, lsp=str(lsp['lspIndex'])), json=lsp, headers=auth_header, verify=False)

  return result

# Gather what fields are available
def gather_api_fields():

  # Example dictionary for getting bandwidth statistics
  result = requests.post("https://{server_ip}:8443/NorthStar/API/V2/tenant/1/statistics/interfaces/fields".format(server_ip=server_ip), headers=auth_header, verify=False)
  interface_fields = result.json()
  print interface_fields

  # Example dictionary for getting delay statistics
  result = requests.post("https://{server_ip}:8443/NorthStar/API/V2/tenant/1/statistics/delay/fields".format(server_ip=server_ip), headers=auth_header, verify=False)
  delay_fields = result.json()
  print delay_fields

  return interface_fields, delay_fields

# Gather network health statistics
def gather_statistics(type, requested_fields):
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
    print "================="
#    print result.json()
    print "================="
    return result.json()


# Connect to Northstar
connect_to_northstar()

# Get topology information
data = gather_topology()


############ Telemetry Examples #############

# Pull all available fields for bandwidth and delay statistics
bandwidth_stats_fields, delay_stats_fields = gather_api_fields()

# Example dictionary for getting bandwidth statistics
requested_fields_bandwidth = {
  'endTime': 'now',
  'startTime': 'now-1h',
  'aggregation': 'avg',
  'interval': '1m',
  'counter': ['interface_stats.egress_stats.if_bps', 'interface_stats.ingress_stats.if_pps']
}
# Retrieve bandwidth related statistics for all interfaces
bandwidth_stats = gather_statistics('interfaces', requested_fields_bandwidth)

# Example dictionary for getting delay statistics
requested_fields_delay = {
  'endTime': 'now',
  'startTime': 'now-1h',
  'aggregation': 'avg',
  'interval': '1h',
  'counter': [ 'average_rtt']
  #'counter': [ 'max_rtt', 'average_rtt', 'loss_percent']
}
# Retrieve delay/loss related statistics for all interfaces
delay_stats = gather_statistics('interfaces', requested_fields_delay)

# Example dictionary for getting delay statistics
requested_fields_traffic = {
  'endTime': 'now',
  'startTime': 'now-1h',
  'aggregation': 'avg',
  'interval': '1h',
#  'counter': [ 'average_rtt']
  #'counter': [ 'max_rtt', 'average_rtt', 'loss_percent']
}
# Retrieve delay/loss related statistics for all interfaces
traffic_stats = gather_statistics('interfaces', requested_fields_traffic)


############ LSP Modification Example #############

# List of hops that the LSP must traverse.
# This is just a list of IPs
#new_path = ["10.147.5.2","10.148.5.1"]
new_path = ["10.147.6.2","10.210.11.1", "10.148.6.1"]
#new_path = ["10.147.6.1","10.147.6.2","10.146.6.2","10.148.6.1",]

# Find target LSP to use lspIndex
for lsp in data['lsp_te']:
  print lsp
  print "-------------------"
  if lsp['name'] == 'SR-LSP-West-East-Three':
    # Copy the LSP into a new dictionary
    result = modify_lsp(lsp, new_path)
    print(result)
    break

send_lsp_update('SR-LSP-West-East-Three', new_path)


########### Interface Status Example #############

data = gather_topology()
print "~~~~~~~~~~~~~~~~"
print data
for link in data['topology']['links']:
  #print "[][][][][][]["
  #print link
  print(link['operationalStatus'])

print "~~~~~~~~~~~~~~~"

print "***************"
#print delay_stats
for latency in delay_stats:
  print delay_stats[latency]
  print ''
print "::::::::::::::::"