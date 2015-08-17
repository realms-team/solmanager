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
import random
from   optparse                             import OptionParser

import OpenCli
import basestation_version

# DustThread
from   SmartMeshSDK                         import FormatUtils, \
                                                   HrParser,    \
                                                   sdk_version
from   SmartMeshSDK.IpMgrConnectorSerial    import IpMgrConnectorSerial
from   SmartMeshSDK.IpMgrConnectorMux       import IpMgrConnectorMux, \
                                                   IpMgrSubscribe

# JsonThread
import bottle
import Sol
import SolVersion
import SolDefines

#============================ defines =========================================

DEFAULT_SERIALPORT = 'COM14'
DEFAULT_TCPPORT    = 8080

#============================ helpers =========================================

def printCrash(threadName):
    import traceback
    output  = []
    output += ["CRASH in Thread {0}!".format(threadName)]
    output += [traceback.format_exc()]
    output  = '\n'.join(output)
    print output

#============================ classes =========================================

class DustThread(threading.Thread):
    
    def __init__(self,serialport,simulation=False):
        
        # store params
        self.serialport      = serialport
        self.simulation      = simulation
        
        # local variables
        self.reconnectEvent  = threading.Event()
        self.hrParser        = HrParser.HrParser()
        self.sol             = Sol.Sol()
        self.dataLock        = threading.RLock()
        self.goOn            = True
        
        # start the thread
        threading.Thread.__init__(self)
        self.name            = 'DustThread'
        self.start()
    
    def run(self):
        
        # wait for banner to print
        time.sleep(0.5)
        
        if self.simulation:
            self.runSimulation()
        else:
            self.runHardware()
    
    def runSimulation(self):
        
        FAKEMAC_MGR     = [0x0a]*8
        FAKEMAC_MOTE_1  = [1]*8
        FAKEMAC_MOTE_2  = [2]*8
        
        RANDOMACTION = [
            (
                self._notifData,
                IpMgrSubscribe.IpMgrSubscribe.NOTIFDATA,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_notifData(
                    utcSecs       = 0,
                    utcUsecs      = 0,
                    macAddress    = FAKEMAC_MGR,
                    srcPort       = 1234,
                    dstPort       = 1234,
                    data          = range(10),
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTCOMMANDFINISHED,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_eventCommandFinished(
                    eventId       = 0x11,
                    callbackId    = 0x22,
                    rc            = 0x33,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTPATHCREATE,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_eventPathCreate(
                    eventId       = 0x11,
                    source        = FAKEMAC_MOTE_1,
                    dest          = FAKEMAC_MOTE_2,
                    direction     = 0x33,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTPATHDELETE,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_eventPathDelete(
                    eventId       = 0x11,
                    source        = FAKEMAC_MOTE_1,
                    dest          = FAKEMAC_MOTE_2,
                    direction     = 0x33,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTPINGRESPONSE,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_eventPingResponse(
                    eventId       = 0x11,
                    callbackId    = 0x22,
                    macAddress    = FAKEMAC_MOTE_1,
                    delay         = 0x33,
                    voltage       = 0x44,
                    temperature   = 0x55,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTNETWORKTIME,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_eventNetworkTime(
                    eventId       = 0x11,
                    uptime        = 0x22,
                    utcSecs       = 0,
                    utcUsecs      = 0,
                    asn           = (1,1,1,1,1),
                    asnOffset     = 0x33,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTNETWORKRESET,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_eventNetworkReset(
                    eventId       = 0x11,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTMOTEJOIN,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_eventMoteJoin(
                    eventId       = 0x11,
                    macAddress    = FAKEMAC_MOTE_1,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTMOTECREATE,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_eventMoteCreate(
                    eventId       = 0x11,
                    macAddress    = FAKEMAC_MOTE_1,
                    moteId        = 0x22,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTMOTEDELETE,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_eventMoteDelete(
                    eventId       = 0x11,
                    macAddress    = FAKEMAC_MOTE_1,
                    moteId        = 0x22,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTMOTELOST,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_eventMoteLost(
                    eventId       = 0x11,
                    macAddress    = FAKEMAC_MOTE_1,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTMOTEOPERATIONAL,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_eventMoteOperational(
                    eventId       = 0x11,
                    macAddress    = FAKEMAC_MOTE_1,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTMOTERESET,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_eventMoteReset(
                    eventId       = 0x11,
                    macAddress    = FAKEMAC_MOTE_1,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTPACKETSENT,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_eventPacketSent(
                    eventId       = 0x11,
                    callbackId    = 0x22,
                    rc            = 0x33,
                ),
            ),
            (
                self._notifHealthReport,
                IpMgrSubscribe.IpMgrSubscribe.NOTIFHEALTHREPORT,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_notifHealthReport(
                    macAddress    = FAKEMAC_MOTE_1,
                    payload       = [1]*10,
                ),
            ),
            (
                self._notifIPData,
                IpMgrSubscribe.IpMgrSubscribe.NOTIFIPDATA,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_notifIpData(
                    utcSecs       = 0,
                    utcUsecs      = 0,
                    macAddress    = FAKEMAC_MOTE_1,
                    data          = [1]*10,
                ),
            ),
            (
                self._notifLog,
                IpMgrSubscribe.IpMgrSubscribe.NOTIFIPDATA,
                IpMgrConnectorMux.IpMgrConnectorMux.Tuple_notifLog(
                    macAddress    = FAKEMAC_MOTE_1,
                    logMsg        = [1]*10,
                ),
            ),
        ]
        
        # get (fake) MAC address of manager
        self.managerMac = FAKEMAC_MGR
        
        # sync (fake) network-UTC time
        self._syncNetTsToUtc(time.time())
        
        while self.goOn:
            
            # issues a random action
            (func,notifName,notifParams) = random.choice(RANDOMACTION)
            func(notifName,notifParams)
            
            # sleep some random time
            time.sleep(random.randint(1,1))
    
    def runHardware(self):
        
        while self.goOn:
            
            try:
                print 'Connecting to {0}...'.format(self.serialport),
                
                # connect to the manager
                self.connector          = IpMgrConnectorSerial.IpMgrConnectorSerial()
                self.connector.connect({
                    'port': self.serialport,
                })
                
                # get MAC address of manager
                temp = self.connector.dn_getSystemInfo()
                self.managerMac = temp.macAddress
                
                # sync network-UTC time
                temp  = self.connector.dn_getTime()
                netTs = self._calcNetTs(temp)
                self._syncNetTsToUtc(netTs)
                
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
                                        IpMgrSubscribe.IpMgrSubscribe.NOTIFEVENT,
                                    ],
                    fun =           self._notifEvent,
                    isRlbl =        True,
                )
                self.subscriber.subscribe(
                    notifTypes =    [
                                        IpMgrSubscribe.IpMgrSubscribe.NOTIFHEALTHREPORT,
                                    ],
                    fun =           self._notifHealthReport,
                    isRlbl =        True,
                )
                self.subscriber.subscribe(
                    notifTypes =    [
                                        IpMgrSubscribe.IpMgrSubscribe.NOTIFIPDATA,
                                    ],
                    fun =           self._notifIPData,
                    isRlbl =        False,
                )
                self.subscriber.subscribe(
                    notifTypes =    [
                                        IpMgrSubscribe.IpMgrSubscribe.NOTIFLOG,
                                    ],
                    fun =           self._notifLog,
                    isRlbl =        True,
                )
                self.subscriber.subscribe(
                    notifTypes =    [
                                        IpMgrSubscribe.IpMgrSubscribe.ERROR,
                                        IpMgrSubscribe.IpMgrSubscribe.FINISH,
                                    ],
                    fun =           self._notifErrorFinish,
                    isRlbl =        True,
                )
                
            except Exception as err:
                
                print err
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
                
                try:
                   self.connector.disconnect()
                except:
                   pass
    
    #======================== public ==========================================
    
    def close(self):
        
        try:
            self.connector.disconnect()
        except:
            pass
        
        self.goOn = False
    
    #======================== private =========================================
    
    #=== Dust API notifications
    
    def _notifData(self, notifName, notifParams):
        
        try:
            assert notifName==IpMgrSubscribe.IpMgrSubscribe.NOTIFDATA
            
            # extract the important data
            netTs      = self._calcNetTs(notifParams)
            macAddress = notifParams.macAddress
            srcPort    = notifParams.srcPort
            dstPort    = notifParams.dstPort
            data       = notifParams.data
            
            isSol = False
            
            if dstPort==SolDefines.SOL_PORT:
                # try to decode as objects
                try:
                    raise NotImplementedError()
                except:
                    pass
                else:
                    isSol = True
            
            if not isSol:
                
                # create sensor object (NOTIF_DATA_RAW)
                sobject = {
                    'mac':       macAddress,
                    'timestamp': self._netTsToEpoch(netTs),
                    'type':      SolDefines.SOL_TYPE_NOTIF_DATA_RAW,
                    'value':     self.sol.create_value_SOL_TYPE_NOTIF_DATA_RAW(
                        srcPort = srcPort,
                        dstPort = dstPort,
                        payload = data,
                    ),
                }
            
            # publish sensor object
            self._publishObject(sobject)
            
        except Exception:
            printCrash(self.name)
    
    def _notifEvent(self,notifName,notifParams):
        
        try:
            # create appropriate object
            
            sobject = {
                'mac':       self.managerMac,
                'timestamp': time.time(),
            }
            
            if   notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTCOMMANDFINISHED:
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_COMMANDFINISHED
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_COMMANDFINISHED(
                    callbackId    = notifParams.callbackId,
                    rc            = notifParams.rc,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTPATHCREATE:
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_PATHCREATE
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_PATHCREATE(
                    source        = notifParams.source,
                    dest          = notifParams.dest,
                    direction     = notifParams.direction,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTPATHDELETE:
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_PATHDELETE
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_PATHDELETE(
                    source        = notifParams.source,
                    dest          = notifParams.dest,
                    direction     = notifParams.direction,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTPINGRESPONSE:
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_PING
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_PING(
                    callbackId    = notifParams.callbackId,
                    macAddress    = notifParams.macAddress,
                    delay         = notifParams.delay,
                    voltage       = notifParams.voltage,
                    temperature   = notifParams.temperature,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTNETWORKTIME:
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_NETWORKTIME
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_NETWORKTIME(
                    uptime        = notifParams.uptime,
                    utcTimeSec    = notifParams.utcTimeSec,
                    utcTimeUsec   = notifParams.utcTimeUsec,
                    asn           = notifParams.asn,
                    asnOffset     = notifParams.asnOffset,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTNETWORKRESET:
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_NETWORKRESET
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_NETWORKRESET(
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTMOTEJOIN:
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_MOTEJOIN
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_MOTEJOIN(
                    macAddress    = notifParams.macAddress,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTMOTECREATE:
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_MOTECREATE
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_MOTECREATE(
                    macAddress    = notifParams.macAddress,
                    moteId        = notifParams.moteId,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTMOTEDELETE:
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_MOTEDELETE
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_MOTEDELETE(
                    macAddress    = notifParams.macAddress,
                    moteId        = notifParams.moteId,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTMOTELOST:
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_MOTELOST
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_MOTELOST(
                    macAddress    = notifParams.macAddress,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTMOTEOPERATIONAL:
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_MOTEOPERATIONAL
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_MOTEOPERATIONAL(
                    macAddress    = notifParams.macAddress,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTMOTERESET:
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_MOTERESET
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_MOTERESET(
                    macAddress    = notifParams.macAddress,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTPACKETSENT:
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_PACKETSENT
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_PACKETSENT(
                    callbackId    = notifParams.callbackId,
                    rc            = notifParams.rc,
                )
            else:
                raise SystemError("Unexpected notifName={0}".format(notifName))
            
            # publish sensor object
            self._publishObject(sobject)
            
        except Exception:
            printCrash(self.name)
    
    def _notifHealthReport(self,notifName,notifParams):
        
        try:
            assert notifName==IpMgrSubscribe.IpMgrSubscribe.NOTIFHEALTHREPORT 
            
            # extract the important data
            netTs      = self._calcNetTs(notifParams)
            macAddress = notifParams.macAddress
            data       = notifParams.data
            
            # create sensor object (SOL_TYPE_NOTIF_HEALTHREPORT)
            sobject = {
                'mac':       macAddress,
                'timestamp': self._netTsToEpoch(netTs),
                'type':      SolDefines.SOL_TYPE_NOTIF_HEALTHREPORT,
                'value':     data,
            }
            
            # publish sensor object
            self._publishObject(sobject)
            
        except Exception:
            printCrash(self.name)
    
    def _notifIPData(self, notifName, notifParams):
        
        try:
            assert notifName==IpMgrSubscribe.IpMgrSubscribe.NOTIFIPDATA
            
            # create sensor object (SOL_TYPE_NOTIF_IPDATA)
            sobject = {
                'mac':       macAddress,
                'timestamp': time.gmtime(),
                'type':      SolDefines.SOL_TYPE_NOTIF_IPDATA,
                'value':     data,
            }
            
            # publish sensor object
            self._publishObject(sobject)
            
        except Exception:
            printCrash(self.name)
    
    def _notifLog(self, notifName, notifParams):
        
        try:
            assert notifName==IpMgrSubscribe.IpMgrSubscribe.NOTIFLOG
            
            # extract the important data
            macAddress = notifParams.macAddress
            data       = notifParams.logMsg
            
            # create sensor object (SOL_TYPE_NOTIF_LOG)
            sobject = {
                'mac':       macAddress,
                'timestamp': time.time(),
                'type':      SolDefines.SOL_TYPE_NOTIF_LOG,
                'value':     data,
            }
            
            # publish sensor object
            self._publishObject(sobject)
            
        except Exception:
            printCrash(self.name)
    
    def _notifErrorFinish(self,notifName,notifParams):
        
        try:
            assert notifName in [
                IpMgrSubscribe.IpMgrSubscribe.ERROR,
                IpMgrSubscribe.IpMgrSubscribe.FINISH,
            ]
            
            if not self.reconnectEvent.isSet():
                self.reconnectEvent.set()
        except Exception:
            printCrash(self.name)
    
    #=== misc
    
    def _calcNetTs(self,notif):
        return float(notif.utcSecs)+float(notif.utcUsecs/1000000.0)
    
    def _syncNetTsToUtc(self,netTs):
        with self.dataLock:
            self.tsDiff = time.time()-netTs
    
    def _netTsToEpoch(self,netTs):
        with self.dataLock:
            return netTs+self.tsDiff
    
    def _publishObject(self,object):
        print "========== _publishObject {0}".format(SolDefines.solTypeToString(SolDefines,object['type']))

class FileThread(threading.Thread):
    def __init__(self):
        self.goOn = True
        # start the thread
        threading.Thread.__init__(self)
        self.name       = 'FileThread'
        self.start()
    def run(self):
        while self.goOn:
            time.sleep(1)
    def close(self):
        self.goOn = False

class SendThread(threading.Thread):
    def __init__(self):
        self.goOn = True
        # start the thread
        threading.Thread.__init__(self)
        self.name       = 'SendThread'
        self.start()
    def run(self):
        while self.goOn:
            time.sleep(1)
    def publish(self,o):
        pass
    def close(self):
        self.goOn = False

class JsonThread(threading.Thread):
    
    def __init__(self,tcpport):
        
        # store params
        self.tcpport    = tcpport
        
        # initialize web server
        self.web        = bottle.Bottle()
        self.web.route(path='/api/v1/echo.json',     method='POST', callback=self._cb_echo_POST)
        self.web.route(path='/api/v1/status.json',   method='GET',  callback=self._cb_status_GET)
        self.web.route(path='/api/v1/config.json',   method='POST', callback=self._cb_config_POST)
        self.web.route(path='/api/v1/config.json',   method='GET',  callback=self._cb_config_GET)
        self.web.route(path='/api/v1/flows.json',    method='GET',  callback=self._cb_flows_GET)
        self.web.route(path='/api/v1/flows.json',    method='POST', callback=self._cb_flows_POST)
        self.web.route(path='/api/v1/resend.json',   method='POST', callback=self._cb_resend_POST)
        self.web.route(path='/api/v1/snapshot.json', method='POST', callback=self._cb_snapshot_POST)
        
        # start the thread
        threading.Thread.__init__(self)
        self.name       = 'JsonThread'
        self.start()
    
    def run(self):
        
        # wait for banner to print
        time.sleep(0.5)
        
        self.web.run(
            host   = 'localhost',
            port   = self.tcpport,
            quiet  = True,
            debug  = False,
        )
    
    #======================== public ==========================================
    
    def close(self):
        print 'TODO JsonThread.close() (#5)'
    
    #======================== private ==========================================
    
    def _cb_echo_POST(self):
        bottle.response.content_type = bottle.request.content_type
        return bottle.request.body.read()
    
    def _cb_status_GET(self):
        # TODO: implement (#7)
        bottle.response.status = 501
        bottle.response.content_type = 'application/json'
        return json.dumps({'error': 'Not Implemented yet :-('})
    
    def _cb_config_POST(self):
        # TODO: implement (#8)
        bottle.response.status = 501
        bottle.response.content_type = 'application/json'
        return json.dumps({'error': 'Not Implemented yet :-('})
    
    def _cb_config_GET(self):
        # TODO: implement (#9)
        bottle.response.status = 501
        bottle.response.content_type = 'application/json'
        return json.dumps({'error': 'Not Implemented yet :-('})
    
    def _cb_flows_GET(self):
        # TODO: implement (#10)
        bottle.response.status = 501
        bottle.response.content_type = 'application/json'
        return json.dumps({'error': 'Not Implemented yet :-('})
    
    def _cb_flows_POST(self):
        # TODO: implement (#11)
        bottle.response.status = 501
        bottle.response.content_type = 'application/json'
        return json.dumps({'error': 'Not Implemented yet :-('})
    
    def _cb_resend_POST(self):
        # TODO: implement (#12)
        bottle.response.status = 501
        bottle.response.content_type = 'application/json'
        return json.dumps({'error': 'Not Implemented yet :-('})
    
    def _cb_snapshot_POST(self):
        # TODO: implement (#13)
        bottle.response.status = 501
        bottle.response.content_type = 'application/json'
        return json.dumps({'error': 'Not Implemented yet :-('})

class Basestation(object):
    
    def __init__(self,serialport,tcpport):
        self.dustThread = DustThread(serialport,simulation=True)
        self.fileThread = FileThread()
        self.sendThread = SendThread()
        self.jsonThread = JsonThread(tcpport)
    
    def close(self):
        self.dustThread.close()
        self.fileThread.close()
        self.sendThread.close()
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
            ("Sol",SolVersion.VERSION),
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
