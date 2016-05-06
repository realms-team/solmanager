#!/usr/bin/python

#============================ adjust path =====================================

import sys
import os

if __name__ == "__main__":
    here = sys.path[0]
    sys.path.insert(0, os.path.join(here, '..', 'sol'))
    sys.path.insert(0, os.path.join(here, '..', 'sol','smartmeshsdk','libs'))

#============================ imports =========================================

import time
import threading
import json
import subprocess
import pickle
import random
import traceback
from   optparse                             import OptionParser
from   ConfigParser                         import SafeConfigParser
import logging
import logging.config

import OpenCli
import solmanager_version

# DustThread
from   SmartMeshSDK                         import sdk_version, \
                                                   ApiException
from   SmartMeshSDK.protocols.Hr            import HrParser
from   SmartMeshSDK.IpMgrConnectorSerial    import IpMgrConnectorSerial
from   SmartMeshSDK.IpMgrConnectorMux       import IpMgrSubscribe
from SmartMeshSDK.protocols.oap             import OAPNotif

# SendThread
import requests

# JsonThread
import bottle
import Sol
import SolVersion
import SolDefines

#============================ logging =========================================

logging.config.fileConfig('logging.conf')
log = logging.getLogger('solserver')
log.setLevel(logging.DEBUG)

#============================ defines =========================================

#===== defines

FLOW_DEFAULT                   = 'default'
FLOW_ON                        = 'on'
FLOW_OFF                       = 'off'

DEFAULT_CONFIGFILE             = 'solmanager.config'
LOGFILE                        = ''
BACKUPFILE                     = ''
SERIALPORT                     = ''
TCPPORT                        = 0
FILECOMMITDELAY_S              = 0
SENDPERIODMINUTES              = 0
FILEPERIODMINUTES              = 0

#===== configuration

SOLSERVER_HOST                 = ''
SOLSERVER_TOKEN                = ''
SOLSERVER_CERT                 = ''
SOLMANAGER_TOKEN               = ''
SOLMANAGER_PRIVKEY             = ''
SOLMANAGER_CERT                = ''

#===== stats
#== admin
STAT_ADM_NUM_CRASHES                   = 'ADM_NUM_CRASHES'
#== connection to manager
STAT_MGR_NUM_CONNECT_ATTEMPTS          = 'MGR_NUM_CONNECT_ATTEMPTS'
STAT_MGR_NUM_CONNECT_OK                = 'MGR_NUM_CONNECT_OK'
STAT_MGR_NUM_DISCONNECTS               = 'MGR_NUM_DISCONNECTS'
STAT_MGR_NUM_TIMESYNC                  = 'MGR_NUM_TIMESYNC'
#== notifications from manager
# note: we count the number of notifications form the manager, for each time, e.g. NUMRX_NOTIFDATA
# all stats start with "NUMRX_"
#== publication
STAT_PUB_TOTAL_SENTTOPUBLISH           = 'PUB_TOTAL_SENTTOPUBLISH'
# to file
STAT_PUBFILE_BACKLOG                   = 'PUBFILE_BACKLOG'
STAT_PUBFILE_WRITES                    = 'PUBFILE_WRITES'
# to server
STAT_PUBSERVER_BACKLOG                 = 'PUBSERVER_BACKLOG'
STAT_PUBSERVER_SENDATTEMPTS            = 'PUBSERVER_SENDATTEMPTS'
STAT_PUBSERVER_UNREACHABLE             = 'PUBSERVER_UNREACHABLE'
STAT_PUBSERVER_SENDOK                  = 'PUBSERVER_SENDOK'
STAT_PUBSERVER_SENDFAIL                = 'PUBSERVER_SENDFAIL'
#== snapshot
STAT_SNAPSHOT_NUM_STARTED              = 'SNAPSHOT_NUM_STARTED'
STAT_SNAPSHOT_LASTSTARTED              = 'SNAPSHOT_LASTSTARTED'
STAT_SNAPSHOT_NUM_OK                   = 'SNAPSHOT_NUM_OK'
STAT_SNAPSHOT_NUM_FAIL                 = 'SNAPSHOT_NUM_FAIL'
#== JSON interface
STAT_JSON_NUM_REQ                      = 'JSON_NUM_REQ'
STAT_JSON_NUM_UNAUTHORIZED             = 'JSON_NUM_UNAUTHORIZED'

#============================ helpers =========================================

def currentUtcTime():
    return time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime())

def logCrash(threadName,err):
    output  = []
    output += ["============================================================="]
    output += [currentUtcTime()]
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
    AppData().incrStats(STAT_ADM_NUM_CRASHES)
    print output
    log.critical(output)

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
            with open(BACKUPFILE,'r') as f:
                self.data = pickle.load(f)
        except (EnvironmentError, pickle.PickleError):
            self.data = {
                'stats' : {},
                'config' : {
                    'logfile':              LOGFILE,
                    'server':               SOLSERVER_HOST,
                    'servertoken':          SOLSERVER_TOKEN,
                    'solmanagertoken':      SOLMANAGER_TOKEN,
                    'sendperiodminutes':    SENDPERIODMINUTES,
                    'fileperiodminutes':    FILEPERIODMINUTES,
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
    def updateStats(self,k,v):
        with self.dataLock:
            self.data['stats'][k] = v
    def getStats(self):
        with self.dataLock:
            stats = self.data['stats'].copy()
        stats[STAT_PUBFILE_BACKLOG]   = FileThread().getBacklogLength()
        stats[STAT_PUBSERVER_BACKLOG] = SendThread().getBacklogLength()
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
            with open(BACKUPFILE,'w') as f:
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
        self.connector       = None
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
        
        SIMACTIONS = [
            (
                self._notifData,
                IpMgrSubscribe.IpMgrSubscribe.NOTIFDATA,
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_notifData(
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
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_eventCommandFinished(
                    eventId       = 0x11,
                    callbackId    = 0x22,
                    rc            = 0x33,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTPATHCREATE,
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_eventPathCreate(
                    eventId       = 0x11,
                    source        = FAKEMAC_MOTE_1,
                    dest          = FAKEMAC_MOTE_2,
                    direction     = 0x33,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTPATHDELETE,
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_eventPathDelete(
                    eventId       = 0x11,
                    source        = FAKEMAC_MOTE_1,
                    dest          = FAKEMAC_MOTE_2,
                    direction     = 0x33,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTPINGRESPONSE,
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_eventPingResponse(
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
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_eventNetworkTime(
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
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_eventNetworkReset(
                    eventId       = 0x11,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTMOTEJOIN,
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_eventMoteJoin(
                    eventId       = 0x11,
                    macAddress    = FAKEMAC_MOTE_1,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTMOTECREATE,
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_eventMoteCreate(
                    eventId       = 0x11,
                    macAddress    = FAKEMAC_MOTE_1,
                    moteId        = 0x22,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTMOTEDELETE,
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_eventMoteDelete(
                    eventId       = 0x11,
                    macAddress    = FAKEMAC_MOTE_1,
                    moteId        = 0x22,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTMOTELOST,
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_eventMoteLost(
                    eventId       = 0x11,
                    macAddress    = FAKEMAC_MOTE_1,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTMOTEOPERATIONAL,
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_eventMoteOperational(
                    eventId       = 0x11,
                    macAddress    = FAKEMAC_MOTE_1,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTMOTERESET,
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_eventMoteReset(
                    eventId       = 0x11,
                    macAddress    = FAKEMAC_MOTE_1,
                ),
            ),
            (
                self._notifEvent,
                IpMgrSubscribe.IpMgrSubscribe.EVENTPACKETSENT,
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_eventPacketSent(
                    eventId       = 0x11,
                    callbackId    = 0x22,
                    rc            = 0x33,
                ),
            ),
            (
                self._notifHealthReport,
                IpMgrSubscribe.IpMgrSubscribe.NOTIFHEALTHREPORT,
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_notifHealthReport(
                    macAddress    = FAKEMAC_MOTE_1,
                    payload       = [1]*10,
                ),
            ),
            (
                self._notifIPData,
                IpMgrSubscribe.IpMgrSubscribe.NOTIFIPDATA,
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_notifIpData(
                    utcSecs       = 0,
                    utcUsecs      = 0,
                    macAddress    = FAKEMAC_MOTE_1,
                    data          = [1]*10,
                ),
            ),
            (
                self._notifLog,
                IpMgrSubscribe.IpMgrSubscribe.NOTIFLOG,
                IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_notifLog(
                    macAddress    = FAKEMAC_MOTE_1,
                    logMsg        = [1]*10,
                ),
            ),
        ]
        
        # get (fake) MAC address of manager
        self.macManager = FAKEMAC_MGR
        
        # sync (fake) network-UTC time
        self._syncNetTsToUtc(time.time())
        
        lastActionIndex = 0
        
        while self.goOn:
            
            # issues the next action
            (func,notifName,notifParams) = SIMACTIONS[lastActionIndex]
            lastActionIndex = (lastActionIndex+1)%len(SIMACTIONS)
            try:
                notifParams = notifParams._replace(
                                utcSecs=int(time.time())-60+random.randint(0,60))
            except ValueError:
                pass
            func(notifName,notifParams)
            
            # sleep some time
            time.sleep(0.5)
    
    def runHardware(self):
        
        while self.goOn:
            
            try:
                # update stats
                AppData().incrStats(STAT_MGR_NUM_CONNECT_ATTEMPTS)
                
                print 'Connecting to {0}...'.format(self.serialport),
                
                # connect to the manager
                self.connector = IpMgrConnectorSerial.IpMgrConnectorSerial()
                self.connector.connect({
                    'port': self.serialport,
                })
                
                # update stats
                AppData().incrStats(STAT_MGR_NUM_CONNECT_OK)
                
                # get MAC address of manager
                temp = self.connector.dn_getSystemInfo()
                self.macManager = temp.macAddress
                
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
                    fun =           self._notifAll,
                    isRlbl =        False,
                )
                self.subscriber.subscribe(
                    notifTypes =    [
                                        IpMgrSubscribe.IpMgrSubscribe.NOTIFEVENT,
                                        IpMgrSubscribe.IpMgrSubscribe.NOTIFHEALTHREPORT,
                                        IpMgrSubscribe.IpMgrSubscribe.NOTIFIPDATA,
                                        IpMgrSubscribe.IpMgrSubscribe.NOTIFLOG,
                                    ],
                    fun =           self._notifAll,
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
                AppData().incrStats(STAT_MGR_NUM_DISCONNECTS)
                
                try:
                    self.connector.disconnect()
                except Exception:
                    pass
                
                # wait to reconnect
                time.sleep(1)
                
            else:
                print 'PASS.'
                self.reconnectEvent.clear()
                self.reconnectEvent.wait()
                
                # update stats
                AppData().incrStats(STAT_MGR_NUM_DISCONNECTS)
                
                try:
                    self.connector.disconnect()
                except Exception:
                    pass
    
    #======================== public ==========================================
    
    def close(self):
        
        try:
            self.connector.disconnect()
        except Exception:
            pass
        
        self.goOn = False
    
    #======================== private =========================================
    
    #=== Dust API notifications
    
    def _notifAll(self, notifName, dust_notif):

        try:
            if notifName==IpMgrConnectorSerial.IpMgrConnectorSerial.NOTIFHEALTHREPORT:
                hr_exists       = True
                dust_notifs     = []
                hr_currptr  = 0
                hr_nextptr  = dust_notif.payload[1]+2
                while hr_exists:
                    # add HR notification to list
                    dust_notifs.append(
                        IpMgrConnectorSerial.IpMgrConnectorSerial.Tuple_notifHealthReport(
                            macAddress = dust_notif.macAddress,
                            payload    = dust_notif.payload[hr_currptr:hr_nextptr],
                        )
                    )
                    # check if other notifs are present
                    hr_currptr = hr_nextptr
                    if (hr_currptr+2 in dust_notif.payload and
                            len(dust_notif.payload) >= dust_notif.payload[hr_currptr+1:1]+2):
                        hr_nextptr = hr_nextptr + dust_notif.payload[hr_currptr+1] + 2
                    else:
                        hr_exists = False

                else:
                    dust_notifs = [dust_notif]
            else:
                dust_notifs = [dust_notif]

            for d_n in dust_notifs:
                # update stats
                AppData().incrStats('NUMRX_{0}'.format(notifName.upper()))

                # convert dust notification to JSON SOL Object
                sol_json = self.sol.dust_to_json(
                    d_n,
                    macManager = self.macManager,
                )

                # publish JSON SOL Object
                self._publishSolJson(sol_json)

        except Exception as err:
            logCrash(self.name,err)

    def _notifErrorFinish(self,notifName,dust_notif):
        
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
        AppData().incrStats(STAT_MGR_NUM_TIMESYNC)
        with self.dataLock:
            self.tsDiff = time.time()-netTs
    
    def _netTsToEpoch(self,netTs):
        with self.dataLock:
            return int(netTs+self.tsDiff)
    
    def _isActiveFlow(self,flow_type):
        flows = AppData().getFlows()
        flowState = flows.get(flow_type,flows['default'])
        return flowState==FLOW_ON
    
    def _publishSolJson(self,sol_json):
        
        # update stats
        AppData().incrStats(STAT_PUB_TOTAL_SENTTOPUBLISH)
        
        # publish
        FileThread().publish(sol_json)
        if self._isActiveFlow(sol_json['type']):
            SendThread().publish(sol_json)

class SnapshotThread(threading.Thread):
    _instance = None
    _init     = False
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SnapshotThread,cls).__new__(cls, *args, **kwargs)
        return cls._instance
    def __init__(self,dustThread=None):
        if self._init:
            return
        self._init      = True
        
        assert dustThread
        
        # store params
        self.dustThread      = dustThread
        
        # local variables
        self.doSnapshotSem   = threading.Semaphore(0)
        self.sol             = Sol.Sol()
        self.goOn            = True
        
        # start thread
        threading.Thread.__init__(self)
        self.name            = 'SnapshotThread'
        self.start()
        
    def run(self):
        while self.goOn:
            self.doSnapshotSem.acquire()
            if not self.goOn:
                break
            self._doSnapshot()
    
    #======================== public ==========================================
    
    def doSnapshot(self):
        self.doSnapshotSem.release()
    
    def close(self):
        self.goOn = False
        self.doSnapshotSem.release()
    
    #======================== private =========================================
    
    def _doSnapshot(self):
        try:
            # update stats
            AppData().incrStats(STAT_SNAPSHOT_NUM_STARTED)
            AppData().updateStats(
                STAT_SNAPSHOT_LASTSTARTED,
                currentUtcTime(),
            )
            
            # retrieve connector from DustThread
            connector = self.dustThread.connector
            
            snapshotSummary = []
            
            # get MAC addresses of all motes
            currentMac     = (0,0,0,0,0,0,0,0) # start getMoteConfig() iteration with the 0 MAC addr
            continueAsking = True
            while continueAsking:
                try:
                    res = connector.dn_getMoteConfig(currentMac,True)
                except ApiException.APIError:
                    continueAsking = False
                else:
                    snapshotSummary += [
                        {
                            'macAddress':       res.macAddress,
                            'moteId':           res.moteId,
                            'isAP':             res.isAP,
                            'state':            res.state,
                            'isRouting':        res.isRouting,
                        }
                    ]
                    currentMac = res.macAddress
            
            # getMoteInfo on all motes
            for s in snapshotSummary:
                res = connector.dn_getMoteInfo(s['macAddress'])
                s.update({
                    'numNbrs':                   res.numNbrs,
                    'numGoodNbrs':               res.numGoodNbrs,
                    'requestedBw':               res.requestedBw,
                    'totalNeededBw':             res.totalNeededBw,
                    'assignedBw':                res.assignedBw,
                    'packetsReceived':           res.packetsReceived,
                    'packetsLost':               res.packetsLost,
                    'avgLatency':                res.avgLatency,
                })
            
            # get path info on all paths of all motes
            for s in snapshotSummary:
                s['paths'] = []
                currentPathId  = 0
                continueAsking = True
                while continueAsking:
                    try:
                        res = connector.dn_getNextPathInfo(s['macAddress'],0,currentPathId)
                    except ApiException.APIError:
                        continueAsking = False
                    else:
                        currentPathId  = res.pathId
                        s['paths'] += [
                            {
                                'dest':          res.dest,
                                'direction':     res.direction,
                                'numLinks':      res.numLinks,
                                'quality':       res.quality,
                                'rssiSrcDest':   res.rssiSrcDest,
                                'rssiDestSrc':   res.rssiDestSrc,
                            }
                        ]
            
        except Exception as err:
            AppData().incrStats(STAT_SNAPSHOT_NUM_FAIL)
        else:
            AppData().incrStats(STAT_SNAPSHOT_NUM_OK)
            
            # create sensor object
            sobject = {
                'mac':       self.dustThread.macManager,
                'timestamp': int(time.time()),
                'type':      SolDefines.SOL_TYPE_DUST_SNAPSHOT,
                'value':     self.sol.pack_obj_value(
                    SolDefines.SOL_TYPE_DUST_SNAPSHOT,
                    summary = snapshotSummary,
                ),
            }
            
            # publish sensor object
            self.dustThread._publishSolJson(sobject)
            
class PublishThread(threading.Thread):
    def __init__(self):
        self.goOn                      = True
        self.solJsonObjectsToPublish   = []
        self.dataLock                  = threading.RLock()
        self.sol                       = Sol.Sol()
        # start the thread
        threading.Thread.__init__(self)
        self.name                      = 'PublishThread'
        self.start()
    def run(self):
        try:
            self.currentDelay = 5
            while self.goOn:
                self.currentDelay -= 1
                if self.currentDelay==0:
                    self.publishNow()
                    self.currentDelay = 60*AppData().getConfig(self.periodvariable)
                time.sleep(1)
        except Exception as err:
            logCrash(self.name,err)
    def getBacklogLength(self):
        with self.dataLock:
            return len(self.solJsonObjectsToPublish)
    def close(self):
        self.goOn = False
    def publish(self,sol_json):
        with self.dataLock:
            self.solJsonObjectsToPublish += [sol_json]

class FileThread(PublishThread):
    _instance = None
    _init     = False
    # we buffer objects for BUFFER_PERIOD second to ensure they are written to
    # file chronologically
    BUFFER_PERIOD = 60 
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(FileThread,cls).__new__(cls, *args, **kwargs)
        return cls._instance
    def __init__(self):
        if self._init:
            return
        self._init           = True
        self.periodvariable  = 'fileperiodminutes'
        PublishThread.__init__(self)
        self.name            = 'FileThread'
    def publishNow(self):
        # update stats
        AppData().incrStats(STAT_PUBFILE_WRITES)
        
        with self.dataLock:
            # order solJsonObjectsToPublish chronologically
            self.solJsonObjectsToPublish.sort(key=lambda i: i['timestamp'])
            
            # extract the JSON SOL objects heard more than BUFFER_PERIOD ago
            now = time.time()
            solJsonObjectsToWrite = []
            while True:
                if not self.solJsonObjectsToPublish:
                    break
                if now-self.solJsonObjectsToPublish[0]['timestamp']<self.BUFFER_PERIOD:
                    break
                solJsonObjectsToWrite += [self.solJsonObjectsToPublish.pop(0)]
        
        # write those to file
        if solJsonObjectsToWrite:
            self.sol.dumpToFile(
                solJsonObjectsToWrite,
                LOGFILE,
            )

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
        self.periodvariable  = 'sendperiodminutes'
        PublishThread.__init__(self)
        self.name            = 'SendThread'
    def publishNow(self):
        # stop if nothing to publish
        with self.dataLock:
            if not self.solJsonObjectsToPublish:
                return

        # convert all objects to publish to binary
        with self.dataLock:
            solBinObjectsToPublish = [self.sol.json_to_bin(o) for o in self.solJsonObjectsToPublish]
        
        # prepare http_payload
        http_payload = self.sol.bin_to_http(solBinObjectsToPublish)

        # send http_payload to server
        try:
            # update stats
            AppData().incrStats(STAT_PUBSERVER_SENDATTEMPTS)
            requests.packages.urllib3.disable_warnings()
            r = requests.put(
                'https://{0}/api/v1/o.json'.format(AppData().getConfig('server')),
                headers = {'X-REALMS-Token': AppData().getConfig('servertoken')},
                json    = http_payload,
                verify  = SOLSERVER_CERT,
            )
        except requests.exceptions.RequestException as err:
            # update stats
            AppData().incrStats(STAT_PUBSERVER_UNREACHABLE)
            # happens when could not contact server
            if type(err) == requests.exceptions.SSLError:
                traceback.print_exc()
        else:
            # server answered
            
            # clear objects
            if r.status_code==200:
                # update stats
                AppData().incrStats(STAT_PUBSERVER_SENDOK)
                with self.dataLock:
                    self.solJsonObjectsToPublish = []
            else:
                # update stats
                AppData().incrStats(STAT_PUBSERVER_SENDFAIL)
                print "Error HTTP response status: "+ str(r.status_code)

class CherryPySSL(bottle.ServerAdapter):
    def run(self, handler):
        from cherrypy import wsgiserver
        from cherrypy.wsgiserver.ssl_pyopenssl import pyOpenSSLAdapter
        server = wsgiserver.CherryPyWSGIServer((self.host, self.port), handler)
        server.ssl_adapter = pyOpenSSLAdapter(
            certificate           = SOLMANAGER_CERT,
            private_key           = SOLMANAGER_PRIVKEY,
        )
        try:
            server.start()
        finally:
            server.stop()

class JsonThread(threading.Thread):
    
    def __init__(self,tcpport,dustThread):
        
        # store params
        self.tcpport    = tcpport
        self.dustThread = dustThread
        
        # local variables
        self.sol        = Sol.Sol()
        
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
            AppData().incrStats(STAT_JSON_NUM_REQ)
            
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
            AppData().incrStats(STAT_JSON_NUM_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # format response
            returnVal = {}
            returnVal['version solmanager']     = solmanager_version.VERSION
            returnVal['version SmartMesh SDK']  = sdk_version.VERSION
            returnVal['version Sol']            = SolVersion.VERSION
            returnVal['uptime computer']        = self._exec_cmd('uptime')
            returnVal['utc']                    = int(time.time())
            returnVal['date']                   = currentUtcTime()
            returnVal['last reboot']            = self._exec_cmd('last reboot')
            returnVal['stats']                  = AppData().getStats()
            
            # send response
            raise bottle.HTTPResponse(
                status  = 200,
                headers = {'Content-Type': 'application/json'},
                body    = json.dumps(returnVal),
            )
        
        except bottle.HTTPResponse:
            raise
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    def _cb_config_GET(self):
        try:
            # update stats
            AppData().incrStats(STAT_JSON_NUM_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # handle
            allConfig = AppData().getAllConfig()
            for hidden in ['logfile','servertoken','solmanagertoken']:
                if hidden in allConfig.keys():
                    del allConfig[hidden]
            return allConfig
            
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    def _cb_config_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_JSON_NUM_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # abort if malformed JSON body
            if bottle.request.json==None:
                raise bottle.HTTPResponse(
                    status  = 400,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps({'error': 'Malformed JSON body'}),
                )
            
            # handle
            for (k,v) in bottle.request.json.items():
                AppData().setConfig(k,v)
            
            # send response
            raise bottle.HTTPResponse(
                status  = 200,
                headers = {'Content-Type': 'application/json'},
                body    = json.dumps({'status': 'config changed'}),
            )
        
        except bottle.HTTPResponse:
            raise            
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    def _cb_flows_GET(self):
        try:
            # update stats
            AppData().incrStats(STAT_JSON_NUM_REQ)
            
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
            AppData().incrStats(STAT_JSON_NUM_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # abort if malformed JSON body
            if bottle.request.json==None:
                raise bottle.HTTPResponse(
                    status  = 400,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps({'error': 'Malformed JSON body'}),
                )
            
            # handle
            for (k,v) in bottle.request.json.items():
                try:
                    k = int(k)
                except:
                    pass
                assert v in [FLOW_ON,FLOW_OFF]
                AppData().setFlow(k,v)
            
            # send response
            raise bottle.HTTPResponse(
                status  = 200,
                headers = {'Content-Type': 'application/json'},
                body    = json.dumps({'status': 'flows changed'}),
            )
        
        except bottle.HTTPResponse:
            raise        
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    def _cb_resend_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_JSON_NUM_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            print "TODO: implement (#12)"
            raise bottle.HTTPResponse(
                status  = 501,
                headers = {'Content-Type': 'application/json'},
                body    = json.dumps({'error': 'Not Implemented yet :-('}),
            )

        except bottle.HTTPResponse:
            raise            
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    def _cb_snapshot_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_JSON_NUM_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # start the snapshot
            SnapshotThread().doSnapshot()
            
            # send response
            raise bottle.HTTPResponse(
                status  = 200,
                headers = {'Content-Type': 'application/json'},
                body    = json.dumps({'status': 'snapshot requested'}),
            )
        
        except bottle.HTTPResponse:
            raise
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    def _cb_smartmeshipapi_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_JSON_NUM_REQ)
            
            # authorize the client
            self._authorizeClient()
            
            # abort if malformed JSON body
            if bottle.request.json==None or \
                    sorted(bottle.request.json.keys())!=sorted(["commandArray","fields"]):
                raise bottle.HTTPResponse(
                    status  = 400,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps({'error': 'Malformed JSON body'}),
                )
            
            # abort if trying to subscribe
            if bottle.request.json["commandArray"]==["subscribe"]:
                raise bottle.HTTPResponse(
                    status  = 403,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps({'error': 'You cannot issue a "subscribe" command'}),
                )
            
            # retrieve connector from DustThread
            connector = self.dustThread.connector
            
            # issue command
            try:
                res = connector.send(
                    commandArray = bottle.request.json["commandArray"],
                    fields       = bottle.request.json["fields"],
                )
            except ApiException.CommandError as err:
                raise bottle.HTTPResponse(
                    status  = 400,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps({'error': str(err)}),
                )
            except ApiException.APIError as err:
                raise bottle.HTTPResponse(
                    status  = 200,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps(
                        {
                            'commandArray': bottle.request.json["commandArray"],
                            'fields':       {
                                'RC':          err.rc,
                            },
                            'desc': str(err),
                        }
                    ),
                )
            
            raise bottle.HTTPResponse(
                status  = 200,
                headers = {'Content-Type': 'application/json'},
                body    = json.dumps(
                    {
                        'commandArray': bottle.request.json["commandArray"],
                        'fields': res,
                    }
                ),
            )
        
        except bottle.HTTPResponse:
            raise
        except Exception as err:
            logCrash(self.name,err)
            raise
    
    #=== misc
    
    def _authorizeClient(self):
        if bottle.request.headers.get('X-REALMS-Token')!=AppData().getConfig('solmanagertoken'):
            AppData().incrStats(STAT_JSON_NUM_UNAUTHORIZED)
            raise bottle.HTTPResponse(
                status  = 401,
                headers = {'Content-Type': 'application/json'},
                body    = json.dumps({'error': 'Unauthorized'}),
            )
    
    def _exec_cmd(self,cmd):
        returnVal = None
        try:
            returnVal = subprocess.check_output(cmd, shell=False)
        except:
            returnVal = "ERROR"
        return returnVal

class SolManager(object):
    
    def __init__(self,serialport,tcpport):
        AppData()
        self.dustThread      = DustThread(serialport,simulation=False)
        self.snapshotThread  = SnapshotThread(self.dustThread)
        self.fileThread      = FileThread()
        self.sendThread      = SendThread()
        self.jsonThread      = JsonThread(tcpport,self.dustThread)
    
    def close(self):
        self.dustThread.close()
        self.snapshotThread.close()
        self.fileThread.close()
        self.sendThread.close()
        self.jsonThread.close()

#============================ main ============================================

solmanager = None

def quitCallback():
    solmanager.close()

def returnStatsGroup(stats,prefix):
    keys = []
    for (k,v) in stats.items():
        if k.startswith(prefix):
            keys+=[k]
    returnVal = []
    for k in sorted(keys):
        returnVal += ['   {0:<30}: {1}'.format(k,stats[k])]
    return returnVal

def cli_cb_stats(params):
    stats = AppData().getStats()
    output  = []
    output += ['#== admin']
    output += returnStatsGroup(stats,'ADM_')
    output += ['#== connection to manager']
    output += returnStatsGroup(stats,'MGR_')
    output += ['#== notifications from manager']
    output += returnStatsGroup(stats,'NUMRX_')
    output += ['#== publication']
    output += returnStatsGroup(stats,'PUB_')
    output += ['# to file']
    output += returnStatsGroup(stats,'PUBFILE_')
    output += ['# to server']
    output += returnStatsGroup(stats,'PUBSERVER_')
    output += ['#== snapshot']
    output += returnStatsGroup(stats,'SNAPSHOT_')
    output += ['#== JSON interface']
    output += returnStatsGroup(stats,'JSON_')
    output = '\n'.join(output)
    print output

def main(serialport,tcpport):
    global solmanager
    
    # create the solmanager instance
    solmanager = SolManager(
        serialport,
        tcpport,
    )
    
    # start the CLI interface
    cli = OpenCli.OpenCli(
        "SolManager",
        solmanager_version.VERSION,
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
    # parse the config file
    cf_parser = SafeConfigParser()
    cf_parser.readfp(open(DEFAULT_CONFIGFILE))

    # application config
    LOGFILE             = cf_parser.get('application','logfile')
    BACKUPFILE          = cf_parser.get('application','backupfile')
    SERIALPORT          = cf_parser.get('application','serialport')
    TCPPORT             = cf_parser.get('application','tcpport')
    FILECOMMITDELAY_S   = cf_parser.getint('application', 'filecommitdelay')
    SENDPERIODMINUTES   = cf_parser.getint('application', 'sendperiodminutes')
    FILEPERIODMINUTES   = cf_parser.getint('application', 'fileperiodminutes')

    # solmanager config
    SOLMANAGER_TOKEN    = cf_parser.get('solmanager','token')
    SOLMANAGER_CERT     = cf_parser.get('solmanager','cert')
    SOLMANAGER_PRIVKEY  = cf_parser.get('solmanager','privkey')

    # solserver config
    SOLSERVER_HOST      = cf_parser.get('solserver','host')
    SOLSERVER_TOKEN     = cf_parser.get('solserver','token')
    SOLSERVER_CERT      = cf_parser.get('solserver','certfile')

    log.debug("Configuration:\n" +\
            "\tLOGFILE: %s\n"               +\
            "\tBACKUPFILE: %s\n"            +\
            "\tSERIALPORT: %s\n"            +\
            "\tTCPPORT: %s\n"               +\
            "\tSOLMANAGER_TOKEN: %s\n"      +\
            "\tSOLMANAGER_CERT: %s\n"       +\
            "\tSOLMANAGER_PRIVKEY: %s\n"    +\
            "\tSOL_SERVER_HOST: %s\n"       +\
            "\tSOLSERVER_TOKEN: %s\n"       +\
            "\tSOLSERVER_CERT:  %s\n"       ,
            LOGFILE,
            BACKUPFILE,
            SERIALPORT,
            TCPPORT,
            SOLMANAGER_TOKEN,
            SOLMANAGER_CERT,
            SOLMANAGER_PRIVKEY,
            SOLSERVER_HOST,
            SOLSERVER_TOKEN,
            SOLSERVER_CERT,
            )

    # parse the command line
    parser = OptionParser("usage: %prog [options]")
    parser.add_option(
        "-s", "--serialport", dest="serialport",
        default=SERIALPORT,
        help="Serial port of the SmartMesh IP manager."
    )
    parser.add_option(
        "-t", "--tcpport", dest="tcpport",
        default=TCPPORT,
        help="TCP port to start the JSON API on."
    )
    (options, args) = parser.parse_args()

    main(
        options.serialport,
        options.tcpport,
    )
