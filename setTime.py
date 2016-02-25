#!/usr/bin/python

# add the SmartMeshSDK/ folder to the path
import sys
import struct
import datetime
import os
here=sys.path[0]
sys.path.insert(0, os.path.join(here,'smartmeshsdk-master'))
sys.path.append('/root/basestation-fw/smartmeshsdk-master/SmartMeshSDK')
sys.path.append('/root/basestation-fw/smartmeshsdk-master/SmartMeshSDK/IpMgrConnectorSerial')

from ApiException      import CommandError, ConnectionError, CommandTimeoutError
from IpMgrConnectorSerial import IpMgrConnectorSerial

#============================ defines =========================================

NETWORK_NOTIF_SET_CLOCK             = 0x12
OAP_PORT                            = 0xf0b8
macArg = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

#============================ body ============================================

##
# \addtogroup NeoSetTime
# \{
#

def SetNetworkTime(connector,utcTimeFlag):
	print('\n\n================== Setting the mote time ==========================')

	#===== Set up the payload
	payload = []
	payload.append(NETWORK_NOTIF_SET_CLOCK)

	print('\n=====\nGet current mote time')
	moteTime = connector.dn_getTime()
	print moteTime.utcSecs

	print('\n=====\nGet current comp time')
	if(not utcTimeFlag): secDt =  datetime.datetime.today() - datetime.datetime.utcfromtimestamp(0)
	elif(utcTimeFlag): secDt =  datetime.datetime.utcnow() - datetime.datetime.utcfromtimestamp(0)
	epochSecs = secDt.total_seconds()
	print epochSecs

	print('\n=====\nGet time delta')
	timeDelta = round(epochSecs) - moteTime.utcSecs
	if(timeDelta>0):
		payload.append(0x0) # Add the delta.
	else:
		payload.append(0x1) # Subtract the delta.
		timeDelta *= -1
	print timeDelta

	payload.extend(struct.unpack('<BBBB',struct.pack('<I',timeDelta)) )
	#payload.extend([0xff,0xff]) # End of command.

	# Send the full packet
	connector.dn_sendData(macArg,
						  0x01,
						  OAP_PORT,
						  OAP_PORT,
						  0x00,
						  payload)

	print('\n=====\nSend set time packet')
	print(macArg, 0x01, OAP_PORT, OAP_PORT, 0x00, payload)

#============================ main ============================================

print '\n=====\nRetrieve the network info'
if __name__ == "__main__":

    print '\n=====\nConnecting to IP manager'

    connector = IpMgrConnectorSerial.IpMgrConnectorSerial()
    connectParams = {
        'port': '/dev/ttyS4',
    }
    try:
        connector.connect(connectParams)
    except ApiException as err:
        print err
        raw_input('\nScript ended. Press Enter to exit.')
        sys.exit(0)
    SetNetworkTime(connector,0)
    sys.exit(0)
    print 'done.'

raw_input('\nScript ended. Press Enter to exit.')
