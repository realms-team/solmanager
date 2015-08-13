#!/usr/bin/python

#============================ adjust path =====================================

import sys
import os
if __name__ == "__main__":
    here = sys.path[0]
    sys.path.insert(0, os.path.join(here, 'smartmeshsdk-master'))
    sys.path.insert(0, os.path.join(here, '..', 'Sol'))

#============================ imports =========================================

import time
import threading
import json
from   optparse                             import OptionParser

import OpenCli
import basestation_version

# DustThread
from   SmartMeshSDK                         import HrParser,                   \
                                                   sdk_version
from   SmartMeshSDK.IpMgrConnectorSerial    import IpMgrConnectorSerial
from   SmartMeshSDK.IpMgrConnectorMux       import IpMgrSubscribe

# JsonThread
import bottle
import Sol
import SolVersion

#============================ defines =========================================

DEFAULT_SERIALPORT = 'COM14'
DEFAULT_TCPPORT    = 8080

#============================ classes =========================================

class DustThread(threading.Thread):
    
    def __init__(self, serialport):
        
        # store params
        self.serialport      = serialport
        
        # local variables
        self.reconnectEvent  = threading.Event()
        self.hrParser        = HrParser.HrParser()
        self.goOn            = True
        
        # start the thread
        threading.Thread.__init__(self)
        self.name            = 'DustThread'
        self.start()
    
    def run(self):
        
        while self.goOn:
            
            try:
                print 'Connecting to {0}...'.format(self.serialport),
                
                # connect to the manager
                self.connector          = IpMgrConnectorSerial.IpMgrConnectorSerial()
                self.connector.connect({
                    'port': self.serialport,
                })
                
                # subscribe to notifications
                self.subscriber = IpMgrSubscribe.IpMgrSubscribe(self.connector)
                self.subscriber.start()
                self.subscriber.subscribe(
                    notifTypes =    [
                                        IpMgrSubscribe.IpMgrSubscribe.NOTIFDATA,
                                    ],
                    fun =           self._notifData,
                    isRlbl =        False,
                )
                self.subscriber.subscribe(
                    notifTypes =    [
                                        IpMgrSubscribe.IpMgrSubscribe.NOTIFHEALTHREPORT,
                                        IpMgrSubscribe.IpMgrSubscribe.NOTIFEVENT,
                                    ],
                    fun =           self._notifEventAll,
                    isRlbl =        True,
                )
                self.subscriber.subscribe(
                    notifTypes =    [
                                        IpMgrSubscribe.IpMgrSubscribe.ERROR,
                                        IpMgrSubscribe.IpMgrSubscribe.FINISH,
                                    ],
                    fun =           self._notifDisconnected,
                    isRlbl =        True,
                )
                
            except Exception as err:
                print 'FAIL.'
                
                try:
                   self.connector.disconnect()
                except:
                   pass
                
                # wait to reconnect
                time.sleep(1)
                
            else:
                print 'PASS.'
                self.reconnectEvent.clear()
                self.reconnectEvent.wait()
    
    #======================== public ==========================================
    
    def close(self):
        
        try:
            self.connector.disconnect()
        except:
            pass
        
        self.goOn = False
    
    #======================== private =========================================
    
    def _notifData(self, notifName, notifParams):
        
        assert notifName==IpMgrSubscribe.IpMgrSubscribe.NOTIFDATA
        
        # extract the important data
        ts         = float(notifParams.utcSecs)+float(notifParams.utcUsecs/1000000.0)
        macAddress = notifParams.macAddress
        data       = notifParams.data
        
        # print content (TODO: publish to back-end system instead)
        output     = []
        output    += ['']
        output    += ['data notification']
        output    += ['- ts :         {0:.6f}'.format(ts)]
        output    += ['- macAddress : {0}'.format(FormatUtils.formatMacString(macAddress))]
        output    += ['- data :       {0}'.format(FormatUtils.formatBuffer(data))]
        output     = '\n'.join(output)
        print output
    
    def _notifEventAll(self, notifName, notifParams):
        
        if   notifName==IpMgrSubscribe.IpMgrSubscribe.NOTIFHEALTHREPORT:
            self._notifHealthreport(notifName,notifParams)
        else:
            self._notifEvent(notifName,notifParams)
    
    def _notifHealthreport(self,notifName,notifParams):
        
        # extract the important data
        macAddress = notifParams.macAddress
        hr         = self.hrParser.parseHr(notifParams.payload)
        
        # print content (TODO: publish to back-end system instead)
        output     = []
        output    += ['']
        output    += ['healthreport notification']
        output    += ['- macAddress : {0}'.format(FormatUtils.formatMacString(macAddress))]
        output    += ['- hr :         {0}'.format(self.hrParser.formatHr(hr))]
        output     = '\n'.join(output)
        print output
    
    def _notifEvent(self,notifName,notifParams):
        
        print "\n\nTODO _notifEvent"
        print notifName
        print notifParams
    
    def _notifDisconnected(self,notifName,notifParams):
        
        if not self.reconnectEvent.isSet():
            self.reconnectEvent.set()

class JsonThread(threading.Thread):
    
    def __init__(self,tcpport):
        
        # store params
        self.tcpport    = tcpport
        
        # initialize web server
        self.web        = bottle.Bottle()
        self.web.route(path='/api/v1/echo.json',   method='GET', callback=self._cb_echo_GET)
        self.web.route(path='/api/v1/status.json', method='GET', callback=self._cb_status_GET)
        
        # start the thread
        threading.Thread.__init__(self)
        self.name       = 'JsonThread'
        self.start()
    
    def run(self):
        self.web.run(
            host   = 'localhost',
            port   = self.tcpport,
            quiet  = False,
            debug  = True,
        )
    
    #======================== public ==========================================
    
    def close(self):
        print 'TODO JsonThread.close()'
    
    #======================== private ==========================================
    
    def _cb_echo_GET(self):
        bottle.response.status = 501
        bottle.response.content_type = 'application/json'
        return json.dumps({'error': 'Not Implemented yet :-('})
    
    def _cb_status_GET(self):
        bottle.response.status = 501
        bottle.response.content_type = 'application/json'
        return json.dumps({'error': 'Not Implemented yet :-('})

class Basestation(object):
    
    def __init__(self,serialport,tcpport):
        self.dustThread = DustThread(serialport)
        self.jsonThread = JsonThread(tcpport)
    
    def close(self):
        self.dustThread.close()
        self.jsonThread.close()

#============================ main ============================================

basestation = None

def quitCallback():
    global basestation
    
    basestation.close()

def main(serialport,tcpport):
    global basestation
    
    # create the basestation instance
    basestation = Basestation(
        serialport,
        tcpport,
    )
    
    # start the CLI interface
    OpenCli.OpenCli(
        "Basestation",
        basestation_version.VERSION,
        quitCallback,
        [
            ("SmartMesh SDK",sdk_version.VERSION),
            (
                "Sol",
                (
                    SolVersion.SOL_VERSION['SOL_VERSION_MAJOR'],
                    SolVersion.SOL_VERSION['SOL_VERSION_MINOR'],
                    SolVersion.SOL_VERSION['SOL_VERSION_PATCH'],
                    SolVersion.SOL_VERSION['SOL_VERSION_BUILD'],
                ),
            ),
        ],
    )

if __name__ == '__main__':
    
    # parse the command line
    parser = OptionParser("usage: %prog [options]")
    parser.add_option(
        "-s", "--serialport", dest="serialport", 
        default=DEFAULT_SERIALPORT,
        help="Serial port of the SmartMesh IP manager."
    )
    parser.add_option(
        "-t", "--tcpport", dest="tcpport", 
        default=DEFAULT_TCPPORT,
        help="TCP port to start the JSON API on."
    )
    (options, args) = parser.parse_args()
    
    main(
        options.serialport,
        options.tcpport,
    )
