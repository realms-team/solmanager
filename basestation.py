#!/usr/bin/python

#============================ adjust path =====================================

import sys
import os
if __name__ == "__main__":
    here = sys.path[0]
    sys.path.insert(0, os.path.join(here, 'smartmeshsdk-master'))

#============================ verify installation =============================

from SmartMeshSDK import SmsdkInstallVerifier
(goodToGo,reason) = SmsdkInstallVerifier.verifyComponents(
    [
        SmsdkInstallVerifier.PYTHON,
        SmsdkInstallVerifier.PYSERIAL,
    ]
)
if not goodToGo:
    print "Your installation does not allow this application to run:\n"
    print reason
    raw_input("Press any button to exit")
    sys.exit(1)

#============================ imports =========================================

import time
import threading
from   optparse                             import OptionParser

from   SmartMeshSDK                         import AppUtils,                   \
                                                   FormatUtils
from   SmartMeshSDK.ApiDefinition           import IpMgrDefinition
from   SmartMeshSDK.IpMgrConnectorSerial    import IpMgrConnectorSerial
from   SmartMeshSDK.IpMgrConnectorMux       import IpMgrConnectorMux,          \
                                                   IpMgrSubscribe
import basestation_version                  as ver
import OpenCli

#============================ defines =========================================

DEFAULT_PORT = 'COM14'

#============================ body ============================================

class notifClient(object):
    
    def __init__(self, connector, disconnectedCallback):
        
        # store params
        self.connector = connector
        self.disconnectedCallback = disconnectedCallback
        
        # variables
        self.data      = []
        self.dataLock  = threading.Lock()
        
        # subscriber
        self.subscriber = IpMgrSubscribe.IpMgrSubscribe(self.connector)
        self.subscriber.start()
        self.subscriber.subscribe(
            notifTypes =    [
                                IpMgrSubscribe.IpMgrSubscribe.NOTIFDATA,
                                IpMgrSubscribe.IpMgrSubscribe.NOTIFIPDATA,
                            ],
            fun =           self._notifData,
            isRlbl =        False,
        )
        self.subscriber.subscribe(
            notifTypes =    [
                                IpMgrSubscribe.IpMgrSubscribe.NOTIFEVENT,
                                IpMgrSubscribe.IpMgrSubscribe.NOTIFLOG, 
                                IpMgrSubscribe.IpMgrSubscribe.NOTIFHEALTHREPORT,
                            ],
            fun =           self._notifEvents,
            isRlbl =        True,
        )
        self.subscriber.subscribe(
            notifTypes =    [
                                IpMgrSubscribe.IpMgrSubscribe.ERROR,
                                IpMgrSubscribe.IpMgrSubscribe.FINISH,
                            ],
            fun =           self.disconnectedCallback,
            isRlbl =        True,
        )
    
    #======================== public ==========================================
    
    def disconnect(self):
        self.connector.disconnect()
    
    #======================== private =========================================
    
    def _notifData(self, notifName, notifParams):
        
        if notifName==IpMgrSubscribe.IpMgrSubscribe.NOTIFIPDATA:
            print 'ERROR: IP data notification unsupported!'
            return
        
        assert notifName==IpMgrSubscribe.IpMgrSubscribe.NOTIFDATA
        
        # extract the important data
        
        ts         = float(notifParams.utcSecs)+float(notifParams.utcUsecs/1000000.0)
        macAddress = notifParams.macAddress
        data       = notifParams.data
        
        # prepare string to print (TODO: publish to back-end system instead)
        
        output     = []
        output    += ['']
        output    += ['data notification']
        output    += ['- ts :         {0:.6f}'.format(ts)]
        output    += ['- macAddress : {0}'.format(FormatUtils.formatMacString(macAddress))]
        output    += ['- data :       {0}'.format(FormatUtils.formatBuffer(data))]
        output     = '\n'.join(output)
        
        print output
    
    def _notifEvents(self, notifName, notifParams):
        
        print "TODO _notifEvents"
        print notifName
        print notifParams

class Basestation(object):
    
    def __init__(self):
        
        # local variables
        self.apiDef             = IpMgrDefinition.IpMgrDefinition()
        self.notifClientHandler = None
        self.reconnectEvent     = threading.Event()
        self.dataLock           = threading.RLock()
    
    #======================== public ==========================================
    
    def connect(self,port):
        
        # store params
        self.port = port
        
        while True:
            
            try:
                print 'connecting to {0}...'.format(self.port),
                
                # connect to the manager
                self.connector          = IpMgrConnectorSerial.IpMgrConnectorSerial()
                self.connector.connect({
                    'port': self.port,
                })
                
                # start a notification client
                self.notifClientHandler = notifClient(
                    self.connector,
                    self._disconnected
                )
                
            except Exception as err:
                print 'FAIL.'
                
                try:
                   self.notifClientHandler.disconnect()
                except:
                   pass
                
                try:
                   self.connector.disconnect()
                except:
                   pass
                
                # wait to reconnect
                time.sleep(5)
                
            else:
                print 'PASS.'
                self.reconnectEvent.clear()
                self.reconnectEvent.wait()
    
    #======================== private =========================================
    
    def _disconnected(self,notifName,notifParams):
        
        if not self.reconnectEvent.isSet():
            self.reconnectEvent.set()
    
#============================ main ============================================

def quitCallback():
    print "TODO quitCallback"

def main(port):
    
    # create the basestation instance
    basestation = Basestation()
    
    # start the CLI interface
    OpenCli.OpenCli(
        "Basestation (c) REALMS team",
        (ver.VER_MAJOR,ver.VER_MINOR,ver.VER_PATCH,ver.VER_BUILD),
        quitCallback,
    )
    
    # connect the basestation
    basestation.connect(port)

if __name__ == '__main__':
    
    # parse the command line
    parser = OptionParser("usage: %prog [options]")
    parser.add_option("-p", "--port", dest="port", 
                      default=DEFAULT_PORT,
                      help="serial port to connect to")
    (options, args) = parser.parse_args()
    
    main(options.port)
