from bottle import route, request, run
from requests import post 
from collections import OrderedDict
import json

lsnHost 	= 'localhost'							# host to listen to for SOL objects
lsnPort 	= 8888								# port to listen to for SOL objects
listnUrl 	= '/backup'							# URL topic to listen to for SOL objects
smUrl 		= 'http://localhost:8888/smartmeshipapi.json'			# SmartmeshIP URL topic to POST to commands 
headers 	= {'content-type': 'application/json'}				# headers for JSON dump

cntrlMac 	= '00-17-0d-00-00-38-1b-fb'					# MAC address to control
sensMac		= '00-17-0d-00-00-38-28-e8'					# MAC address that is sensing
cntrlVar 	= 'temperature'							# variable to use for control
cntrlType 	= 39								# SOL type to control on
cntrolThesh = 50.								# threshold to apply control

def macTolist(hexMac):
	'''converts hex MAC string to list
	hexMax: 	MAC address to convert (string)
	returns: 	list of MAC address integers''' 

	return [int(i,16) for i in hexMac.split('-')]

def cmdJson(dMac,dat):
	'''creates 'send data' command to specific MAC
	dMac: 		destination mac address (string)
	dat: 		payload data (string)
	returns: 	cmd, ordered dict (to convert to JSON)'''

	cmd = OrderedDict()
	cmd['commandArray'] 		= ['sendData']
	cmd['fields'] 			= OrderedDict()
	cmd['fields']['macAddress'] 	= dMac
	cmd['fields']['priority'] 	= 2 
	cmd['fields']['srcPort'] 	= '0xf0b9'
	cmd['fields']['dstPort'] 	= '0xf0b9'
	cmd['fields']['options'] 	= 0
	cmd['fields']['data'] 		= dat

	return cmd

@route(listnUrl, method = 'POST')
def control():
	'''infinitely listening for POSTS on lsnHost
	if recieved SOL packet meets cntrolThesh conditions,
	send POST to smartmesh serial with command to a MAC
	''' 

	solPl = request.json
	print 'incoming SOL object:' 
	print solPl
	if solPl['mac'] == sensMac and solPl['type'] == cntrlType:
		if solPl['value'][cntrlVar] < cntrolThesh:
			print 'outgoing command:'
			sndCmd = cmdJson(macTolist(cntrlMac),1)
			print json.dumps(sndCmd)
			#post(smUrl, data=json.dumps(pumpOn), headers=headers)

run(host=lsnHost, port=lsnPort)
