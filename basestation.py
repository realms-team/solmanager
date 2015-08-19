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
import pickle
import random
import traceback
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

# SendThread
import requests

# JsonThread
import bottle
import Sol
import SolVersion
import SolDefines

#============================ defines =========================================

FLOW_DEFAULT                      = 'default'
FLOW_ON                           = 'on'
FLOW_OFF                          = 'off'

DEFAULT_SERIALPORT                = 'COM14'
DEFAULT_TCPPORT                   = 8080
DEFAULT_FILECOMMITDELAY_S         = 60

DEFAULT_CRASHLOG                  = 'basestation.crashlog'
DEFAULT_BACKUPFILE                = 'basestation.backup'
# config
DEFAULT_LOGFILE                   = 'basestation.sol'
DEFAULT_SERVER                    = 'localhost:8081'
DEFAULT_SERVERTOKEN               = 'DEFAULT_SERVERTOKEN'
DEFAULT_BASESTATIONTOKEN          = 'DEFAULT_BASESTATIONTOKEN'
DEFAULT_SYNCPERIODMINUTES         = 0.1

# stats
STAT_NUM_JSON_UNAUTHORIZED        = 'NUM_JSON_UNAUTHORIZED'
STAT_NUM_JSON_REQ                 = 'NUM_JSON_REQ'
STAT_NUM_CRASHES                  = 'NUM_CRASHES'
STAT_NUM_DUST_DISCONNECTS         = 'NUM_DUST_DISCONNECTS'
STAT_NUM_DUST_NOTIFDATA           = 'NUM_DUST_NOTIFDATA'
STAT_NUM_DUST_EVENTCOMMANDFINISHED= 'NUM_DUST_EVENTCOMMANDFINISHED'
STAT_NUM_DUST_EVENTPATHCREATE     = 'NUM_DUST_EVENTPATHCREATE'
STAT_NUM_DUST_EVENTPATHDELETE     = 'NUM_DUST_EVENTPATHDELETE'
STAT_NUM_DUST_EVENTPINGRESPONSE   = 'NUM_DUST_EVENTPINGRESPONSE'
STAT_NUM_DUST_EVENTNETWORKTIME    = 'NUM_DUST_EVENTNETWORKTIME'
STAT_NUM_DUST_EVENTNETWORKRESET   = 'NUM_DUST_EVENTNETWORKRESET'
STAT_NUM_DUST_EVENTMOTEJOIN       = 'NUM_DUST_EVENTMOTEJOIN'
STAT_NUM_DUST_EVENTMOTECREATE     = 'NUM_DUST_EVENTMOTECREATE'
STAT_NUM_DUST_EVENTMOTEDELETE     = 'NUM_DUST_EVENTMOTEDELETE'
STAT_NUM_DUST_EVENTMOTELOST       = 'NUM_DUST_EVENTMOTELOST'
STAT_NUM_DUST_EVENTMOTEOPERATIONAL= 'NUM_DUST_EVENTMOTEOPERATIONAL'
STAT_NUM_DUST_EVENTMOTERESET      = 'NUM_DUST_EVENTMOTERESET'
STAT_NUM_DUST_EVENTPACKETSENT     = 'NUM_DUST_EVENTPACKETSENT'
STAT_NUM_DUST_NOTIFHEALTHREPORT   = 'NUM_DUST_NOTIFHEALTHREPORT'
STAT_NUM_DUST_NOTIFIPDATA         = 'NUM_DUST_NOTIFIPDATA'
STAT_NUM_DUST_NOTIFLOG            = 'NUM_DUST_NOTIFLOG'
STAT_NUM_DUST_TIMESYNC            = 'NUM_DUST_TIMESYNC'
STAT_NUM_OBJECTS_RECEIVED         = 'NUM_OBJECTS_RECEIVED'
STAT_NUM_LOGFILE_UPDATES          = 'NUM_LOGFILE_UPDATES'
STAT_NUM_SERVER_SENDATTEMPTS      = 'NUM_SERVER_SENDATTEMPTS'
STAT_NUM_SERVER_UNREACHABLE       = 'NUM_SERVER_UNREACHABLE'
STAT_NUM_SERVER_SENDOK            = 'NUM_SERVER_SENDOK'
STAT_NUM_SERVER_STATUSFAIL        = 'NUM_SERVER_STATUSFAIL'
STAT_BACKLOG_FILETHREAD           = 'BACKLOG_FILETHREAD'
STAT_BACKLOG_SENDTHREAD           = 'BACKLOG_SENDTHREAD'

#============================ helpers =========================================

def logCrash(threadName,err):
    output  = []
    output += ["==============================================================="]
    output += [time.strftime("%m/%d/%Y %H:%M:%S UTC",time.gmtime())]
    output += [""]
    output += ["CRASH in Thread {0}!".format(threadName)]
    output += [""]
    output += ["=== exception type ==="]
    output += [str(type(err))]
    output += [""]
    output += ["=== traceback ==="]
    output += [traceback.format_exc()]
    output  = '\n'.join(output)
    # update stats
    AppData().incrStats(STAT_NUM_CRASHES)
    print output
    with open(DEFAULT_CRASHLOG,'a') as f:
        f.write(output)

#============================ classes =========================================

class AppData(object):
    _instance = None
    _init     = False
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(AppData,cls).__new__(cls, *args, **kwargs)
        return cls._instance
    def __init__(self):
        if self._init:
            return
        self._init      = True
        self.dataLock   = threading.RLock()
        try:
            with open(DEFAULT_BACKUPFILE,'r') as f:
                self.data = pickle.load(f)
        except:
            self.data = {
                'stats' : {},
                'config' : {
                    'logfile':              DEFAULT_LOGFILE,
                    'server':               DEFAULT_SERVER,
                    'servertoken':          DEFAULT_SERVERTOKEN,
                    'basestationtoken':     DEFAULT_BASESTATIONTOKEN,
                    'syncperiodminutes':    DEFAULT_SYNCPERIODMINUTES,
                },
                'flows' : {
                    FLOW_DEFAULT:           FLOW_ON,
                },
            }
            self._backupData()
    def incrStats(self,statName):
        with self.dataLock:
            if statName not in self.data['stats']:
                self.data['stats'][statName] = 0
            self.data['stats'][statName] += 1
    def getStats(self):
        with self.dataLock:
            stats = self.data['stats'].copy()
        stats[STAT_BACKLOG_FILETHREAD] = FileThread().getBacklogLength()
        stats[STAT_BACKLOG_SENDTHREAD] = SendThread().getBacklogLength()
        return stats
    def getConfig(self,key):
        with self.dataLock:
            return self.data['config'][key]
    def getAllConfig(self):
        with self.dataLock:
            return self.data['config'].copy()
    def setConfig(self,key,value):
        with self.dataLock:
            self.data['config'][key] = value
        self._backupData()
    def getFlows(self):
        with self.dataLock:
            return self.data['flows'].copy()
    def setFlow(self,key,value):
        with self.dataLock:
            self.data['flows'][key] = value
        self._backupData()
    def _backupData(self):
        with self.dataLock:
            with open(DEFAULT_BACKUPFILE,'w') as f:
                pickle.dump(self.data,f)

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
        try:        
            # wait for banner
            time.sleep(0.5)
            
            if self.simulation:
                self.runSimulation()
            else:
                self.runHardware()
        except Exception as err:
            logCrash(self.name,err)
    
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
                IpMgrSubscribe.IpMgrSubscribe.NOTIFLOG,
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
        
        lastActionIndex = 0
        
        while self.goOn:
            
            # issues a random action
            #(func,notifName,notifParams) = random.choice(RANDOMACTION)
            (func,notifName,notifParams) = RANDOMACTION[lastActionIndex]
            lastActionIndex = (lastActionIndex+1)%len(RANDOMACTION)
            if 'utcSecs' in notifParams:
                notifParams.utcSecs = time.time()
            func(notifName,notifParams)
            
            # sleep some random time
            #time.sleep(random.randint(1,6))
            time.sleep(0.5)
    
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
                
                # update stats
                AppData().incrStats(STAT_NUM_DUST_DISCONNECTS)
                
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
                
                # update stats
                AppData().incrStats(STAT_NUM_DUST_DISCONNECTS)
                
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
            # update stats
            AppData().incrStats(STAT_NUM_DUST_NOTIFDATA)
                
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
            
        except Exception as err:
            logCrash(self.name,err)
    
    def _notifEvent(self,notifName,notifParams):
        
        try:
            # create appropriate object
            sobject = {
                'mac':       self.managerMac,
                'timestamp': int(time.time()),
            }
            
            if   notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTCOMMANDFINISHED:
                # update stats
                AppData().incrStats(STAT_NUM_DUST_EVENTCOMMANDFINISHED)
                
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_COMMANDFINISHED
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_COMMANDFINISHED(
                    callbackId    = notifParams.callbackId,
                    rc            = notifParams.rc,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTPATHCREATE:
                # update stats
                AppData().incrStats(STAT_NUM_DUST_EVENTPATHCREATE)
                
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_PATHCREATE
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_PATHCREATE(
                    source        = notifParams.source,
                    dest          = notifParams.dest,
                    direction     = notifParams.direction,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTPATHDELETE:
                # update stats
                AppData().incrStats(STAT_NUM_DUST_EVENTPATHDELETE)
                
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_PATHDELETE
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_PATHDELETE(
                    source        = notifParams.source,
                    dest          = notifParams.dest,
                    direction     = notifParams.direction,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTPINGRESPONSE:
                # update stats
                AppData().incrStats(STAT_NUM_DUST_EVENTPINGRESPONSE)
                
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_PING
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_PING(
                    callbackId    = notifParams.callbackId,
                    macAddress    = notifParams.macAddress,
                    delay         = notifParams.delay,
                    voltage       = notifParams.voltage,
                    temperature   = notifParams.temperature,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTNETWORKTIME:
                # update stats
                AppData().incrStats(STAT_NUM_DUST_EVENTNETWORKTIME)
                
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_NETWORKTIME
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_NETWORKTIME(
                    uptime        = notifParams.uptime,
                    utcSecs       = notifParams.utcSecs,
                    utcUsecs      = notifParams.utcUsecs,
                    asn           = notifParams.asn,
                    asnOffset     = notifParams.asnOffset,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTNETWORKRESET:
                # update stats
                AppData().incrStats(STAT_NUM_DUST_EVENTNETWORKRESET)
                
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_NETWORKRESET
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_NETWORKRESET(
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTMOTEJOIN:
                # update stats
                AppData().incrStats(STAT_NUM_DUST_EVENTMOTEJOIN)
                
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_MOTEJOIN
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_MOTEJOIN(
                    macAddress    = notifParams.macAddress,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTMOTECREATE:
                # update stats
                AppData().incrStats(STAT_NUM_DUST_EVENTMOTECREATE)
                
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_MOTECREATE
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_MOTECREATE(
                    macAddress    = notifParams.macAddress,
                    moteId        = notifParams.moteId,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTMOTEDELETE:
                # update stats
                AppData().incrStats(STAT_NUM_DUST_EVENTMOTEDELETE)
                
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_MOTEDELETE
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_MOTEDELETE(
                    macAddress    = notifParams.macAddress,
                    moteId        = notifParams.moteId,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTMOTELOST:
                # update stats
                AppData().incrStats(STAT_NUM_DUST_EVENTMOTELOST)
                
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_MOTELOST
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_MOTELOST(
                    macAddress    = notifParams.macAddress,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTMOTEOPERATIONAL:
                # update stats
                AppData().incrStats(STAT_NUM_DUST_EVENTMOTEOPERATIONAL)
                
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_MOTEOPERATIONAL
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_MOTEOPERATIONAL(
                    macAddress    = notifParams.macAddress,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTMOTERESET:
                # update stats
                AppData().incrStats(STAT_NUM_DUST_EVENTMOTERESET)
                
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_MOTERESET
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_MOTERESET(
                    macAddress    = notifParams.macAddress,
                )
            elif notifName==IpMgrSubscribe.IpMgrSubscribe.EVENTPACKETSENT:
                # update stats
                AppData().incrStats(STAT_NUM_DUST_EVENTPACKETSENT)
                
                sobject['type']   = SolDefines.SOL_TYPE_NOTIF_EVENT_PACKETSENT
                sobject['value']  = self.sol.create_value_SOL_TYPE_NOTIF_EVENT_PACKETSENT(
                    callbackId    = notifParams.callbackId,
                    rc            = notifParams.rc,
                )
            else:
                raise SystemError("Unexpected notifName={0}".format(notifName))
            
            # publish sensor object
            self._publishObject(sobject)
            
        except Exception as err:
            logCrash(self.name,err)
    
    def _notifHealthReport(self,notifName,notifParams):
        
        try:
            # update stats
            AppData().incrStats(STAT_NUM_DUST_NOTIFHEALTHREPORT)
            
            assert notifName==IpMgrSubscribe.IpMgrSubscribe.NOTIFHEALTHREPORT 
            
            # extract the important data
            macAddress = notifParams.macAddress
            payload    = notifParams.payload
            
            # create sensor object (SOL_TYPE_NOTIF_HEALTHREPORT)
            sobject = {
                'mac':       macAddress,
                'timestamp': int(time.time()),
                'type':      SolDefines.SOL_TYPE_NOTIF_HEALTHREPORT,
                'value':     payload,
            }
            
            # publish sensor object
            self._publishObject(sobject)
            
        except Exception as err:
            logCrash(self.name,err)
    
    def _notifIPData(self, notifName, notifParams):
        
        try:
            # update stats
            AppData().incrStats(STAT_NUM_DUST_NOTIFIPDATA)
            
            assert notifName==IpMgrSubscribe.IpMgrSubscribe.NOTIFIPDATA
            
            # extract the important data
            netTs      = self._calcNetTs(notifParams)
            macAddress = notifParams.macAddress
            data       = notifParams.data
            
            # create sensor object (SOL_TYPE_NOTIF_IPDATA)
            sobject = {
                'mac':       macAddress,
                'timestamp': self._netTsToEpoch(netTs),
                'type':      SolDefines.SOL_TYPE_NOTIF_IPDATA,
                'value':     data,
            }
            
            # publish sensor object
            self._publishObject(sobject)
            
        except Exception as err:
            logCrash(self.name,err)
    
    def _notifLog(self, notifName, notifParams):
        
        try:
            # update stats
            AppData().incrStats(STAT_NUM_DUST_NOTIFLOG)
            
            assert notifName==IpMgrSubscribe.IpMgrSubscribe.NOTIFLOG
            
            # extract the important data
            macAddress = notifParams.macAddress
            data       = notifParams.logMsg
            
            # create sensor object (SOL_TYPE_NOTIF_LOG)
            sobject = {
                'mac':       macAddress,
                'timestamp': int(time.time()),
                'type':      SolDefines.SOL_TYPE_NOTIF_LOG,
                'value':     data,
            }
            
            # publish sensor object
            self._publishObject(sobject)
            
        except Exception as err:
            logCrash(self.name,err)
    
    def _notifErrorFinish(self,notifName,notifParams):
        
        try:
            assert notifName in [
                IpMgrSubscribe.IpMgrSubscribe.ERROR,
                IpMgrSubscribe.IpMgrSubscribe.FINISH,
            ]
            
            if not self.reconnectEvent.isSet():
                self.reconnectEvent.set()
        except Exception as err:
            logCrash(self.name,err)
    
    #=== misc
    
    def _calcNetTs(self,notif):
        return int(float(notif.utcSecs)+float(notif.utcUsecs/1000000.0))
    
    def _syncNetTsToUtc(self,netTs):
        # update stats
        AppData().incrStats(STAT_NUM_DUST_TIMESYNC)
        with self.dataLock:
            self.tsDiff = time.time()-netTs
    
    def _netTsToEpoch(self,netTs):
        with self.dataLock:
            return int(netTs+self.tsDiff)
    
    def _isActiveFlow(self,type):
        flows = AppData().getFlows()
        returnVal = flows.get(type,flows['default'])
        return returnVal==FLOW_ON
    
    def _publishObject(self,object):
        
        assert sorted(object.keys()) == sorted(['mac','type','timestamp','value'])
        assert type(object['mac'])==list
        for b in object['mac']:
            assert type(b)==int
        assert type(object['type'])==int
        assert type(object['timestamp'])==int
        assert type(object['value'])==list
        for b in object['value']:
            assert type(b)==int
        
        # update stats
        AppData().incrStats(STAT_NUM_OBJECTS_RECEIVED)
        
        # publish
        FileThread().publish(object)
        if self._isActiveFlow(object['type']):
            SendThread().publish(object)

class PublishThread(threading.Thread):
    def __init__(self):
        self.goOn            = True
        self.objectsToCommit = []
        self.dataLock        = threading.RLock()
        # start the thread
        threading.Thread.__init__(self)
        self.name            = 'PublishThread'
        self.start()
    def run(self):
        try:
            self.currentDelay = 5
            while self.goOn:
                self.currentDelay -= 1
                if self.currentDelay==0:
                    self.commit()
                    self.currentDelay = 60*AppData().getConfig('syncperiodminutes')
                time.sleep(1)
        except Exception as err:
            logCrash(self.name,err)
    def getBacklogLength(self):
        with self.dataLock:
            return len(self.objectsToCommit)
    def close(self):
        self.goOn = False
    def publish(self,object):
        with self.dataLock:
            # TODO: insert in order
            self.objectsToCommit += [object]

class FileThread(PublishThread):
    _instance = None
    _init     = False
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(FileThread,cls).__new__(cls, *args, **kwargs)
        return cls._instance
    def __init__(self):
        if self._init:
            return
        self._init           = True
        self.commitDelay     = DEFAULT_FILECOMMITDELAY_S
        self.sol             = Sol.Sol()
        PublishThread.__init__(self)
        self.name            = 'FileThread'
    def commit(self):
        # update stats
        AppData().incrStats(STAT_NUM_LOGFILE_UPDATES)
        with self.dataLock:
            self.sol.dumpToFile(
                self.objectsToCommit,
                DEFAULT_LOGFILE,
            )
            self.objectsToCommit = []

class SendThread(PublishThread):
    _instance = None
    _init     = False
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SendThread,cls).__new__(cls, *args, **kwargs)
        return cls._instance
    def __init__(self):
        if self._init:
            return
        self._init           = True
        self.sol             = Sol.Sol()
        PublishThread.__init__(self)
        self.name       = 'SendThread'
    def commit(self):
        # stop if nothing to publish
        if not self.objectsToCommit:
            return
        
        # prepare payload
        with self.dataLock:
            payload = self.sol.dicts_to_json(self.objectsToCommit,mode="minimal")
        
        # send payload to server
        try:
            # update stats
            AppData().incrStats(STAT_NUM_SERVER_SENDATTEMPTS)
            requests.packages.urllib3.disable_warnings()
            r = requests.put(
                'https://{0}/api/v1/o.json'.format(AppData().getConfig('server')),
                headers = {'X-REALMS-Token': AppData().getConfig('servertoken')},
                json    = payload,
                verify  = 'server.cert',
            )
        except requests.exceptions.RequestException as err:
            # update stats
            AppData().incrStats(STAT_NUM_SERVER_UNREACHABLE)
            # happens when could not contact server
            pass
        else:
            # server answered
            
            # clear objects
            if r.status_code==200:
                # update stats
                AppData().incrStats(STAT_NUM_SERVER_SENDOK)
                self.objectsToCommit = []
            else:
                # update stats
                AppData().incrStats(STAT_NUM_SERVER_STATUSFAIL)

class CherryPySSL(bottle.ServerAdapter):
    def run(self, handler):
        from cherrypy import wsgiserver
        from cherrypy.wsgiserver.ssl_pyopenssl import pyOpenSSLAdapter
        server = wsgiserver.CherryPyWSGIServer((self.host, self.port), handler)
        server.ssl_adapter = pyOpenSSLAdapter(
            certificate           = "basestation.cert",
            private_key           = "basestation.ppk",
        )
        try:
            server.start()
        finally:
            server.stop()

class JsonThread(threading.Thread):
    
    def __init__(self,tcpport):
        
        # store params
        self.tcpport    = tcpport
        
        # local variables
        self.sol                  = Sol.Sol()
        
        # initialize web server
        self.web        = bottle.Bottle()
        self.web.route(path='/api/v1/echo.json',           method='POST', callback=self._cb_echo_POST)
        self.web.route(path='/api/v1/status.json',         method='GET',  callback=self._cb_status_GET)
        self.web.route(path='/api/v1/config.json',         method='GET',  callback=self._cb_config_GET)
        self.web.route(path='/api/v1/config.json',         method='POST', callback=self._cb_config_POST)
        self.web.route(path='/api/v1/flows.json',          method='GET',  callback=self._cb_flows_GET)
        self.web.route(path='/api/v1/flows.json',          method='POST', callback=self._cb_flows_POST)
        self.web.route(path='/api/v1/resend.json',         method='POST', callback=self._cb_resend_POST)
        self.web.route(path='/api/v1/snapshot.json',       method='POST', callback=self._cb_snapshot_POST)
        self.web.route(path='/api/v1/smartmeshipapi.json', method='POST', callback=self._cb_smartmeshipapi_POST)
        
        # start the thread
        threading.Thread.__init__(self)
        self.name       = 'JsonThread'
        self.daemon     = True
        self.start()
    
    def run(self):
        try:
            # wait for banner
            time.sleep(0.5)
            
            self.web.run(
                host   = 'localhost',
                port   = self.tcpport,
                server = CherryPySSL,
                quiet  = True,
                debug  = False,
            )
        except Exception as err:
            logCrash(self.name,err)
    
    #======================== public ==========================================
    
    def close(self):
        # bottle thread is daemon, it will close when main thread closes
        pass
    
    #======================== private ==========================================
    
    #=== JSON request handler
    
    def _cb_echo_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_NUM_JSON_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # answer with same Content-Type/body
            bottle.response.content_type = bottle.request.content_type
            return bottle.request.body.read()
        
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    def _cb_status_GET(self):
        try:
            # update stats
            AppData().incrStats(STAT_NUM_JSON_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # format response
            returnVal = {}
            returnVal['version basestation']    = basestation_version.VERSION
            returnVal['version SmartMesh SDK']  = sdk_version.VERSION
            returnVal['version Sol']            = SolVersion.VERSION
            returnVal['uptime computer']        = self._exec_cmd('uptime')
            returnVal['utc']                    = int(time.time())
            returnVal['date']                   = time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime())
            returnVal['last reboot']            = self._exec_cmd('last reboot')
            returnVal['stats']                  = AppData().getStats()
            
            # send response
            bottle.response.content_type        = 'application/json'
            return json.dumps(returnVal)
        
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    def _cb_config_GET(self):
        try:
            # update stats
            AppData().incrStats(STAT_NUM_JSON_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # handle
            allConfig = AppData().getAllConfig()
            for hidden in ['logfile','servertoken','basestationtoken']:
                if hidden in allConfig.keys():
                    del allConfig[hidden]
            return allConfig
            
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    def _cb_config_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_NUM_JSON_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # abort if malformed JSON body
            if bottle.request.json==None:
                raise bottle.HTTPResponse(
                    body   = json.dumps({'error': 'Malformed JSON body'}),
                    status = 400,
                    headers= {'Content-Type': 'application/json'},
                )
            
            # handle
            for (k,v) in bottle.request.json.items():
                AppData().setConfig(k,v)
            
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    def _cb_flows_GET(self):
        try:
            # update stats
            AppData().incrStats(STAT_NUM_JSON_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # handle
            return AppData().getFlows()
            
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    def _cb_flows_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_NUM_JSON_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # abort if malformed JSON body
            if bottle.request.json==None:
                raise bottle.HTTPResponse(
                    body   = json.dumps({'error': 'Malformed JSON body'}),
                    status = 400,
                    headers= {'Content-Type': 'application/json'},
                )
            
            # handle
            for (k,v) in bottle.request.json.items():
                try:
                    k = int(k)
                except:
                    pass
                assert v in [FLOW_ON,FLOW_OFF]
                AppData().setFlow(k,v)
            
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    def _cb_resend_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_NUM_JSON_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # TODO: implement (#12)
            raise bottle.HTTPResponse(
                body   = json.dumps({'error': 'Not Implemented yet :-('}),
                status = 501,
                headers= {'Content-Type': 'application/json'},
            )
            
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    def _cb_snapshot_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_NUM_JSON_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # TODO: implement (#13)
            raise bottle.HTTPResponse(
                body   = json.dumps({'error': 'Not Implemented yet :-('}),
                status = 501,
                headers= {'Content-Type': 'application/json'},
            )
            
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    def _cb_smartmeshipapi_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_NUM_JSON_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # TODO: implement (#13)
            raise bottle.HTTPResponse(
                body   = json.dumps({'error': 'Not Implemented yet :-('}),
                status = 501,
                headers= {'Content-Type': 'application/json'},
            )
            
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    #=== misc
    
    def _authorizeClient(self):
        if bottle.request.headers.get('X-REALMS-Token')!=AppData().getConfig('basestationtoken'):
            AppData().incrStats(STAT_NUM_JSON_UNAUTHORIZED)
            raise bottle.HTTPResponse(
                body   = json.dumps({'error': 'Unauthorized'}),
                status = 401,
                headers= {'Content-Type': 'application/json'},
            )
    
    def _exec_cmd(self,cmd):
        returnVal = None
        try:
            returnVal = subprocess.check_output(cmd, shell=False)
        except:
            returnVal = "ERROR"
        return returnVal

class Basestation(object):
    
    def __init__(self,serialport,tcpport):
        AppData()
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

def cli_cb_stats(params):
    stats = AppData().getStats()
    output = []
    for k in sorted(stats.keys()):
        output += ['{0:<30}: {1}'.format(k,stats[k])]
    output = '\n'.join(output)
    print output

def main(serialport,tcpport):
    global basestation
    
    # create the basestation instance
    basestation = Basestation(
        serialport,
        tcpport,
    )
    
    # start the CLI interface
    cli = OpenCli.OpenCli(
        "Basestation",
        basestation_version.VERSION,
        quitCallback,
        [
            ("SmartMesh SDK",sdk_version.VERSION),
            ("Sol",SolVersion.VERSION),
        ],
    )
    cli.registerCommand(
        'stats',
        's',
        'print the stats',
        [],
        cli_cb_stats
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
