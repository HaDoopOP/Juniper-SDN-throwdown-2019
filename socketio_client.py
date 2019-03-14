#!/usr/bin/env python
from socketIO_client import SocketIO, BaseNamespace 
import requests,json,sys

'''
This file suppose deploy on the docker container with python image
pre-configed. 
It will listen to the socketIO server side if there is any link event
such as node failure, link failure.
'''

# Disable warnings about unverified certificates
if hasattr(requests, 'packages') and hasattr(requests.packages, 'urllib3'):
    requests.packages.urllib3.disable_warnings()

# load from your config file plz...
serverURL = 'https://1.1.1.1' 
username = '*******'
password = '*******'

class NSNotificationNamespace(BaseNamespace): 
  def on_connect(self):
    print('Connected to %s:8443/restNotifications-v2'%serverURL) 
  def on_event(key,name,data):
    print "NorthStar Event: %r,data:%r"%(name,json.dumps(data))
    if data['notificationType'] == 'link': 
      print 'Got Link update: '
      obj = data['object']
      print 'id: ',obj['id']
      from_ = obj['endA']
      to = obj['endZ']
      print 'from ',from_['ipv4Address']['address']
      print 'to ',to['ipv4Address']['address']
      print 'status: ', obj['operationalStatus']
    elif data['notificationType'] == 'node':
      print 'Got Node update'
    else:
      print 'Got Unknown update'
    print ''
# First use NorhtStar OAuth2 authentication API to get a token
payload = {'grant_type': 'password','username': username,'password': password}
r = requests.post(serverURL + ':8443/oauth2/token',data=payload,verify=False,auth=(username, password))

data =r.json()
if "token_type" not in data or "access_token" not in data:
  print "Error: Invalid credentials"
  sys.exit(1)

headers= {'Authorization': "{token_type} {access_token}".format(**data)} 

socketIO = SocketIO(serverURL, 8443,verify=False,headers= headers)
ns = socketIO.define(NSNotificationNamespace, '/restNotifications-v2')
socketIO.wait()