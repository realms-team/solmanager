#!/usr/bin/python

from __future__ import division # using python3 division to avoid truncation

#============================ adjust path =====================================

import sys
import os

if __name__ == "__main__":
    here = sys.path[0]
    sys.path.insert(0, os.path.join(here, '..', 'sol'))
    sys.path.insert(0, os.path.join(here, '..', 'smartmeshsdk', 'libs'))

#============================ imports =========================================

import time
import threading
import json
import subprocess
import pickle
import traceback
import ConfigParser
import logging.config

import requests
import OpenSSL
import bottle

import OpenCli
import solmanager_version
from   SmartMeshSDK                         import sdk_version, \
                                                   ApiException
from   solobjectlib                         import Sol, \
                                                   SolVersion, \
                                                   SolDefines

#============================ logging =========================================

logging.config.fileConfig('logging.conf', disable_existing_loggers=False)
log = logging.getLogger("solmanager")

#============================ defines =========================================

#===== defines

FLOW_DEFAULT                            = 'default'
FLOW_ON                                 = 'on'
FLOW_OFF                                = 'off'

CONFIGFILE                              = 'solmanager.config'

MAX_HTTP_SIZE                           = 1000 # send batches of 1KB (~30KB after )

#===== stats
#== admin
STAT_ADM_NUM_CRASHES                    = 'ADM_NUM_CRASHES'
#== connection to manager
STAT_MGR_NUM_CONNECT_ATTEMPTS           = 'MGR_NUM_CONNECT_ATTEMPTS'
STAT_MGR_NUM_CONNECT_OK                 = 'MGR_NUM_CONNECT_OK'
STAT_MGR_NUM_DISCONNECTS                = 'MGR_NUM_DISCONNECTS'
STAT_MGR_NUM_TIMESYNC                   = 'MGR_NUM_TIMESYNC'
#== notifications from manager
# note: we count the number of notifications form the manager, for each time, e.g. NUMRX_NOTIFDATA
# all stats start with "NUMRX_"
#== publication
STAT_PUB_TOTAL_SENTTOPUBLISH            = 'PUB_TOTAL_SENTTOPUBLISH'
# to file
STAT_PUBFILE_BACKLOG                    = 'PUBFILE_BACKLOG'
STAT_PUBFILE_WRITES                     = 'PUBFILE_WRITES'
# to server
STAT_PUBSERVER_BACKLOG                  = 'PUBSERVER_BACKLOG'
STAT_PUBSERVER_SENDATTEMPTS             = 'PUBSERVER_SENDATTEMPTS'
STAT_PUBSERVER_UNREACHABLE              = 'PUBSERVER_UNREACHABLE'
STAT_PUBSERVER_SENDOK                   = 'PUBSERVER_SENDOK'
STAT_PUBSERVER_SENDFAIL                 = 'PUBSERVER_SENDFAIL'
STAT_PUBSERVER_STATS                    = 'PUBSERVER_STATS'
STAT_PUBSERVER_PULLATTEMPTS             = 'PUBSERVER_PULLATTEMPTS'
STAT_PUBSERVER_PULLOK                   = 'PUBSERVER_PULLOK'
STAT_PUBSERVER_PULLFAIL                 = 'PUBSERVER_PULLFAIL'
#== snapshot
STAT_SNAPSHOT_NUM_STARTED               = 'SNAPSHOT_NUM_STARTED'
STAT_SNAPSHOT_LASTSTARTED               = 'SNAPSHOT_LASTSTARTED'
STAT_SNAPSHOT_NUM_OK                    = 'SNAPSHOT_NUM_OK'
STAT_SNAPSHOT_NUM_FAIL                  = 'SNAPSHOT_NUM_FAIL'
#== JSON interface
STAT_JSON_NUM_REQ                       = 'JSON_NUM_REQ'
STAT_JSON_NUM_UNAUTHORIZED              = 'JSON_NUM_UNAUTHORIZED'

#============================ helpers =========================================

def currentUtcTime():
    return time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime())

def logCrash(threadName, err):
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
            cls._instance = super(AppData, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self, statsfile=None):
        if self._init:
            return
        self._init      = True
        self.dataLock   = threading.RLock()
        self.statsfile  = statsfile
        try:
            with open(statsfile, 'r') as f:
                self.data = pickle.load(f)
                log.info("Stats recovered from file.")
        except (EnvironmentError, pickle.PickleError, EOFError) as e:
            self.data = {
                'stats': {},
                'flows': {
                    FLOW_DEFAULT:           FLOW_ON,
                },
            }
            log.info("Could not read stats file: %s", e)
            self._backupData()

    def incrStats(self, statName):
        with self.dataLock:
            if statName not in self.data['stats']:
                self.data['stats'][statName] = 0
            self.data['stats'][statName] += 1
        self._backupData()

    def updateStats(self, k, v):
        with self.dataLock:
            self.data['stats'][k] = v
        self._backupData()

    def getStats(self):
        with self.dataLock:
            stats = self.data['stats'].copy()
        stats[STAT_PUBFILE_BACKLOG]   = FileThread().getBacklogLength()
        stats[STAT_PUBSERVER_BACKLOG] = SendThread().getBacklogLength()
        return stats

    def getFlows(self):
        with self.dataLock:
            return self.data['flows'].copy()

    def setFlow(self, key, value):
        with self.dataLock:
            self.data['flows'][key] = value
        self._backupData()

    def _backupData(self):
        with self.dataLock:
            with open(self.statsfile, 'w') as f:
                pickle.dump(self.data, f)

class AppConfig(object):
    _instance = None
    _init     = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(AppConfig, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if self._init:
            return
        self._init = True

        # local variables
        self.dataLock   = threading.RLock()
        self.config     = {}

        config = ConfigParser.ConfigParser()
        config.read(CONFIGFILE)

        with self.dataLock:
            for (k,v) in config.items('config'):
                try:
                    self.config[k] = float(v)
                except ValueError:
                    try:
                        self.config[k] = int(v)
                    except ValueError:
                        self.config[k] = v

    def get(self,name):
        with self.dataLock:
            return self.config[name]

class MgrThread(object):

    def __init__(self):

        # local variables
        self.sol = Sol.Sol()
        self.mac = None
        self.serialport = None

    #======================== private =========================================

    def _handler_dust_notifs(self, dust_notif):
        try:

            # update stats
            AppData().incrStats('NUMRX_{0}'.format(dust_notif['name']))

            # convert dust notification to JSON SOL Object
            sol_jsonl = self.sol.dust_to_json(
                dust_notif  = dust_notif,
                mac_manager = self.getMacManager(),
                timestamp   = int(time.time()), # TODO get timestamp of when data was created
            )

            for sol_json in sol_jsonl:
                # update stats
                AppData().incrStats(STAT_PUB_TOTAL_SENTTOPUBLISH)

                # publish
                FileThread().publish(sol_json) # to the backup file
                SendThread().publish(sol_json) # to the solserver over the Internet

        except Exception as err:
            logCrash(self.name, err)

    def getMacManager(self):
        raise NotImplementedError('Not implemented')

class MgrSerialThread(MgrThread, threading.Thread):

    def __init__(self):
        raise NotImplementedError()

class MgrJsonServerThread(MgrThread, threading.Thread):

    def __init__(self):

        # initialize the parent class
        super(MgrJsonServerThread, self).__init__()

        # initialize web server
        self.web                = bottle.Bottle()
        self.web.route(
            path        = [
                '/hr',
                '/notifData',
                '/oap',
                '/notifLog',
                '/notifIpData',
                '/event',
            ],
            method      = 'POST',
            callback    = self._webhandler_all_POST
        )

        # start the thread
        threading.Thread.__init__(self)
        self.name       = 'MgrJsonServerThread'
        self.daemon     = True
        self.start()

    def run(self):
        try:
            # wait for banner
            time.sleep(0.5)
            self.web.run(
                host   = '0.0.0.0',
                port   = AppConfig().get("solmanager_jsonport"),
                quiet  = True,
                debug  = False,
            )
        except Exception as err:
            logCrash(self.name, err)

    def getMacManager(self):
        host = str(AppConfig().get("jsonserverhost"))

        # get JsonServer configuration
        try:
            path = "/api/v1/config"
            r = requests.get("http://" + host + path)
        except requests.exceptions.RequestException as e:
            logCrash(self.name, e)
        else:
            if len(r.json()["managers"]) > 1:
                log.error("More than one manager found in JsonServer")
            elif len(r.json()["managers"]) == 0:
                log.warn("No manager found in JsonServer")
            else:
                self.serialport = r.json()["managers"][0]
                self.mac = self._query_serialport()

        return self.mac

    def _query_serialport(self):
        host = str(AppConfig().get("jsonserverhost"))
        path = "/api/v1/raw"
        body = {
            "manager": self.serialport,
            "command": "getMoteConfig",
            "fields": {
                "macAddress": [0, 0, 0, 0, 0, 0, 0, 0],
                "next": True
            }
        }

        try:
            r = requests.post(
                url="http://" + host + path,
                json=body
            )
        except requests.exceptions.RequestException as e:
            logCrash(self.name, e)
        else:
            if "macAddress" in r.json():
                return r.json()["macAddress"]
            else:
                log.error("macAddress not found in JsonServer response: %s", r.json())

    def _webhandler_all_POST(self):
        super(MgrJsonServerThread, self)._handler_dust_notifs(
            json.loads(bottle.request.body.read()),
        )

class SnapshotThread(threading.Thread):

    _instance = None
    _init     = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SnapshotThread, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self, mgrThread=None):
        if self._init:
            return
        self._init      = True

        assert mgrThread

        # store params
        self.mgrThread       = mgrThread

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

            # retrieve connector from mgrThread
            connector = self.mgrThread.connector

            snapshotSummary = []

            # get MAC addresses of all motes
            #-- start getMoteConfig() iteration with the 0 MAC addr
            currentMac     = (0, 0, 0, 0, 0, 0, 0, 0)
            continueAsking = True
            while continueAsking:
                try:
                    res = connector.dn_getMoteConfig(currentMac, True)
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
                        res = connector.dn_getNextPathInfo(s['macAddress'], 0, currentPathId)
                    except ApiException.APIError:
                        continueAsking = False
                    else:
                        currentPathId  = res.pathId
                        s['paths'] += [
                            {
                                'macAddress':    res.dest,
                                'direction':     res.direction,
                                'numLinks':      res.numLinks,
                                'quality':       res.quality,
                                'rssiSrcDest':   res.rssiSrcDest,
                                'rssiDestSrc':   res.rssiDestSrc,
                            }
                        ]

        except Exception as err:
            AppData().incrStats(STAT_SNAPSHOT_NUM_FAIL)
            log.warning("Cannot do Snapshot: %s", err)
        else:
            if self.mgrThread.getMacManager() is not None:
                AppData().incrStats(STAT_SNAPSHOT_NUM_OK)

                # create sensor object
                sobject = {
                    'mac':       self.mgrThread.getMacManager(),
                    'timestamp': int(time.time()),
                    'type':      SolDefines.SOL_TYPE_DUST_SNAPSHOT,
                    'value':     snapshotSummary,
                }

                # publish sensor object
                FileThread().publish(sobject)
                SendThread().publish(sobject)

class PublishThread(threading.Thread):
    def __init__(self, periodvariable):
        self.goOn                       = True
        self.solJsonObjectsToPublish    = []
        self.dataLock                   = threading.RLock()
        self.sol                        = Sol.Sol()
        # start the thread
        threading.Thread.__init__(self)
        self.name                       = 'PublishThread'
        self.daemon                     = True
        self.periodvariable             = periodvariable*60
        self.currentDelay               = 0
        self.start()
    def run(self):
        try:
            self.currentDelay = 5
            while self.goOn:
                self.currentDelay -= 1
                if self.currentDelay == 0:
                    self.publishNow()
                    self.currentDelay = self.periodvariable
                time.sleep(1)
        except Exception as err:
            logCrash(self.name, err)
    def getBacklogLength(self):
        with self.dataLock:
            return len(self.solJsonObjectsToPublish)
    def close(self):
        self.goOn = False
    def publish(self, sol_json):
        with self.dataLock:
            self.solJsonObjectsToPublish += [sol_json]

class PeriodicSnapshotThread(PublishThread):
    _instance = None
    _init     = False
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(PeriodicSnapshotThread, cls).__new__(cls, *args, **kwargs)
        return cls._instance
    def __init__(self):
        if self._init:
            return
        self._init          = True
        PublishThread.__init__(self, AppConfig().get("period_snapshot_min"))
        self.name           = 'PeriodicSnapshotThread'
    def publishNow(self):
        SnapshotThread().doSnapshot()

class FileThread(PublishThread):

    _instance = None
    _init     = False

    # we buffer objects for BUFFER_PERIOD second to ensure they are written to
    # file chronologically

    BUFFER_PERIOD = 30
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(FileThread, cls).__new__(cls, *args, **kwargs)
        return cls._instance
    def __init__(self):
        if self._init:
            return
        self._init          = True
        PublishThread.__init__(self, AppConfig().get("period_filethread_min"))
        self.name           = 'FileThread'

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
                if now-self.solJsonObjectsToPublish[0]['timestamp'] < self.BUFFER_PERIOD:
                    break
                solJsonObjectsToWrite += [self.solJsonObjectsToPublish.pop(0)]

        # write those to file
        if solJsonObjectsToWrite:
            self.sol.dumpToFile(
                solJsonObjectsToWrite,
                AppConfig().get("backupfile"),
            )

class SendThread(PublishThread):
    _instance = None
    _init     = False
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SendThread, cls).__new__(cls, *args, **kwargs)
        return cls._instance
    def __init__(self):
        if self._init:
            return
        self._init              = True
        PublishThread.__init__(self, AppConfig().get("period_sendthread_min"))
        self.name               = 'SendThread'
    def publishNow(self):
        # stop if nothing to publish
        with self.dataLock:
            if not self.solJsonObjectsToPublish:
                return

        # convert objects to publish to binary until HTTP max size is reached
        object_id = 0
        with self.dataLock:
            solBinObjectsToPublish = []
            for object_id, o in enumerate(self.solJsonObjectsToPublish):
                solBinObjectsToPublish.append(self.sol.json_to_bin(o))
                if len(solBinObjectsToPublish) > MAX_HTTP_SIZE:
                    break

        # prepare http_payload
        http_payload = self.sol.bin_to_http(solBinObjectsToPublish)

        # send http_payload to server
        try:
            # update stats
            AppData().incrStats(STAT_PUBSERVER_SENDATTEMPTS)
            requests.packages.urllib3.disable_warnings()
            log.debug("sending objects, size:%dB", len(http_payload))
            r = requests.put(
                'https://{0}/api/v1/o.json'.format(AppConfig().get("solserver_host")),
                headers = {'X-REALMS-Token': AppConfig().get("solserver_token")},
                json    = http_payload,
                verify  = AppConfig().get("solserver_cert"),
            )
        except (requests.exceptions.RequestException, OpenSSL.SSL.SysCallError) as err:
            # update stats
            AppData().incrStats(STAT_PUBSERVER_UNREACHABLE)
            # happens when could not contact server
            log.warning("Error when sending http payload: %s", err)
        else:
            # server answered

            # clear objects
            if r.status_code == requests.codes.ok:
                # update stats
                AppData().incrStats(STAT_PUBSERVER_SENDOK)
                with self.dataLock:
                    self.solJsonObjectsToPublish = self.solJsonObjectsToPublish[object_id:]
            else:
                # update stats
                AppData().incrStats(STAT_PUBSERVER_SENDFAIL)
                print "Error HTTP response status: " + str(r.text)

class PullThread(PublishThread):
    """
    This thread periodically asks the server for actions and perform them.
    This is useful when the solmanager is not reachable by the solserver.
    """

    _instance = None
    _init     = False
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(PullThread, cls).__new__(cls, *args, **kwargs)
        return cls._instance
    def __init__(self):
        if self._init:
            return
        self._init          = True
        PublishThread.__init__(self, AppConfig().get("period_pullthread_min"))
        self.name           = 'PullThread'
    def publishNow(self):
        self.pull_server()
    def pull_server(self):
        # send http_payload to server
        try:
            # update stats
            AppData().incrStats(STAT_PUBSERVER_PULLATTEMPTS)
            requests.packages.urllib3.disable_warnings()
            r = requests.get(
                'https://{0}/api/v1/getactions/'.format(AppConfig().get("solserver_host")),
                headers = {'X-REALMS-Token': AppConfig().get("solserver_token")},
                verify  = AppConfig().get("solserver_cert"),
            )
        except (requests.exceptions.RequestException, OpenSSL.SSL.SysCallError) as err:
            # update stats
            AppData().incrStats(STAT_PUBSERVER_UNREACHABLE)
            # happens when could not contact server
            if type(err) == requests.exceptions.SSLError:
                traceback.print_exc()
        else:
            # server answered

            # clear objects
            if r.status_code == 200:
                # update stats
                AppData().incrStats(STAT_PUBSERVER_PULLOK)
                for action in r.json():
                    self.run_action(action['action'])
            else:
                # update stats
                AppData().incrStats(STAT_PUBSERVER_PULLFAIL)
                print "Error HTTP response status: " + str(r.status_code)

    def run_action(self, action):
        if action == "update":
            # get last repo version
            os.system("cd " + here + "/../sol/ && git checkout master && git pull origin master")
            os.system("cd " + here + " && git checkout master && git pull origin master")

            # restart program
            python = sys.executable
            os.execl(python, python, * sys.argv)

class StatsThread(PublishThread):
    '''
    This thread periodically publishes the solmanager statistics
    '''

    _instance = None
    _init     = False
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(StatsThread, cls).__new__(cls, *args, **kwargs)
        return cls._instance
    def __init__(self, mgrThread):
        if self._init:
            return
        self._init          = True
        PublishThread.__init__(self, AppConfig().get("period_statsthread_min"))
        self.name           = 'StatsThread'
        self.mgrThread      = mgrThread
        self.sol            = Sol.Sol()
    def publishNow(self):

        # create sensor object
        sobject = {
            'mac':       self.mgrThread.getMacManager(),
            'timestamp': int(time.time()),
            'type':      SolDefines.SOL_TYPE_SOLMANAGER_STATS,
            'value':     {
                'sol_version'           : list(SolVersion.VERSION),
                'solmanager_version'    : list(solmanager_version.VERSION),
                'sdk_version'           : list(sdk_version.VERSION)
            },
        }

        # publish
        FileThread().publish(sobject)
        SendThread().publish(sobject)

        # update stats
        AppData().incrStats(STAT_PUBSERVER_STATS)

class HTTPSServer(bottle.ServerAdapter):
    def run(self, handler):
        from cheroot.wsgi import Server as WSGIServer
        from cheroot.ssl.pyopenssl import pyOpenSSLAdapter
        server = WSGIServer((self.host, self.port), handler)
        server.ssl_adapter = pyOpenSSLAdapter(
            certificate = AppConfig().get("solmanager_cert"),
            private_key = AppConfig().get("solmanager_privkey"),
        )
        try:
            server.start()
            log.info("Server started")
        finally:
            server.stop()

class JsonThread(threading.Thread):

    def __init__(self, mgrThread):

        # store params
        self.mgrThread          = mgrThread

        # local variables
        self.sol                = Sol.Sol()

        # check if files exist
        fcert = open(AppConfig().get("solmanager_cert"))
        fcert.close()
        fkey = open(AppConfig().get("solmanager_privkey"))
        fkey.close()

        # initialize web server
        self.web                = bottle.Bottle()
        self.web.route(
            path        = '/api/v1/echo.json',
            method      = 'POST',
            callback    = self._webhandler_echo_POST,
        )
        self.web.route(
            path        = '/api/v1/status.json',
            method      = 'GET',
            callback    = self._webhandler_status_GET,
        )
        self.web.route(
            path        = '/api/v1/config.json',
            method      = 'GET',
            callback    = self._webhandler_config_GET,
        )
        self.web.route(
            path        = '/api/v1/config.json',
            method      = 'POST',
            callback    = self._webhandler_config_POST,
        )
        self.web.route(
            path        = '/api/v1/flows.json',
            method      = 'GET',
            callback    = self._webhandler_flows_GET,
        )
        self.web.route(
            path        = '/api/v1/flows.json',
            method      = 'POST',
            callback    = self._webhandler_flows_POST,
        )
        self.web.route(
            path        = '/api/v1/resend.json',
            method      = 'POST',
            callback    = self._webhandler_resend_POST,
        )
        self.web.route(
            path        = '/api/v1/snapshot.json',
            method      = 'POST',
            callback    = self._webhandler_snapshot_POST,
        )
        self.web.route(
            path        = '/api/v1/smartmeshipapi.json',
            method      = 'POST',
            callback    = self._webhandler_smartmeshipapi_POST,
        )

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
                host   = AppConfig().get("solmanager_host"),
                port   = AppConfig().get("solmanager_tcpport"),
                server = HTTPSServer,
                quiet  = True,
                debug  = False,
            )
        except Exception as err:
            logCrash(self.name, err)

    #======================== public ==========================================

    def close(self):
        self.web.close()

    #======================== private ==========================================

    #=== webhandlers

    def _webhandler_echo_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_JSON_NUM_REQ)

            # authorize the client
            self._authorizeClient()

            # answer with same Content-Type/body
            bottle.response.content_type = bottle.request.content_type
            return bottle.request.body.read()

        except Exception as err:
            logCrash(self.name, err)
            raise

    def _webhandler_status_GET(self):
        try:
            # update stats
            AppData().incrStats(STAT_JSON_NUM_REQ)

            # authorize the client
            self._authorizeClient()

            # format response
            returnVal = {'version solmanager': solmanager_version.VERSION,
                         'version SmartMesh SDK': sdk_version.VERSION,
                         'version Sol': SolVersion.VERSION,
                         'uptime computer': self._exec_cmd('uptime'),
                         'utc': int(time.time()),
                         'date': currentUtcTime(),
                         'last reboot': self._exec_cmd('last reboot'),
                         'stats': AppData().getStats()}

            # send response
            raise bottle.HTTPResponse(
                status  = 200,
                headers = {'Content-Type': 'application/json'},
                body    = json.dumps(returnVal),
            )

        except bottle.HTTPResponse:
            raise
        except Exception as err:
            logCrash(self.name, err)
            raise

    def _webhandler_config_GET(self):
        try:
            # update stats
            AppData().incrStats(STAT_JSON_NUM_REQ)

            # authorize the client
            self._authorizeClient()

            # handle
            raise NotImplementedError("getAllConfig() is not available anymore")

        except Exception as err:
            logCrash(self.name, err)
            raise

    def _webhandler_config_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_JSON_NUM_REQ)

            # authorize the client
            self._authorizeClient()

            # abort if malformed JSON body
            if bottle.request.json is None:
                raise bottle.HTTPResponse(
                    status  = 400,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps({'error': 'Malformed JSON body'}),
                )

            # handle
            raise NotImplementedError("setConfig() is not available anymore")

            # send response
            raise bottle.HTTPResponse(
                status  = 200,
                headers = {'Content-Type': 'application/json'},
                body    = json.dumps({'status': 'config changed'}),
            )

        except bottle.HTTPResponse:
            raise
        except Exception as err:
            logCrash(self.name, err)
            raise

    def _webhandler_flows_GET(self):
        try:
            # update stats
            AppData().incrStats(STAT_JSON_NUM_REQ)

            # authorize the client
            self._authorizeClient()

            # handle
            return AppData().getFlows()

        except Exception as err:
            logCrash(self.name, err)
            raise

    def _webhandler_flows_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_JSON_NUM_REQ)

            # authorize the client
            self._authorizeClient()

            # abort if malformed JSON body
            if bottle.request.json is None:
                raise bottle.HTTPResponse(
                    status  = 400,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps({'error': 'Malformed JSON body'}),
                )

            # handle
            for (k, v) in bottle.request.json.items():
                try:
                    k = int(k)
                except Exception as err:
                    log.warning("Error when posting flows: %s", err)
                assert v in [FLOW_ON, FLOW_OFF]
                AppData().setFlow(k, v)

            # send response
            raise bottle.HTTPResponse(
                status  = 200,
                headers = {'Content-Type': 'application/json'},
                body    = json.dumps({'status': 'flows changed'}),
            )

        except bottle.HTTPResponse:
            raise
        except Exception as err:
            logCrash(self.name, err)
            raise

    def _webhandler_resend_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_JSON_NUM_REQ)

            # authorize the client
            self._authorizeClient()

            # abort if malformed JSON body
            if bottle.request.json is None:
                raise bottle.HTTPResponse(
                    status  = 400,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps({'error': 'Malformed JSON body'}),
                )

            # verify all fields are present
            required_fields = ["action", "startTimestamp", "endTimestamp"]
            for field in required_fields:
                if field not in bottle.request.json:
                    raise bottle.HTTPResponse(
                        status  = 400,
                        headers = {'Content-Type': 'application/json'},
                        body    = json.dumps({'error': 'Missing field {0}'.format(field)}),
                    )

            # handle
            action          = bottle.request.json["action"]
            startTimestamp  = bottle.request.json["startTimestamp"]
            endTimestamp    = bottle.request.json["endTimestamp"]
            if action == "count":
                sol_jsonl = self.sol.loadFromFile(AppConfig().get("backupfile"), startTimestamp, endTimestamp)
                # send response
                raise bottle.HTTPResponse(
                    status  = 200,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps({'numObjects': len(sol_jsonl)}),
                )
            elif action == "resend":
                sol_jsonl = self.sol.loadFromFile(AppConfig().get("backupfile"), startTimestamp, endTimestamp)
                # publish
                for sobject in sol_jsonl:
                    SendThread().publish(sobject)
                # send response
                raise bottle.HTTPResponse(
                    status  = 200,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps({'numObjects': len(sol_jsonl)}),
                )
            else:
                raise bottle.HTTPResponse(
                    status  = 400,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps({'error': 'Unknown action {0}'.format(action)}),
                )

        except bottle.HTTPResponse:
            raise
        except Exception as err:
            logCrash(self.name, err)
            raise

    def _webhandler_snapshot_POST(self):
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
            logCrash(self.name, err)
            raise

    def _webhandler_smartmeshipapi_POST(self):
        try:
            # update stats
            AppData().incrStats(STAT_JSON_NUM_REQ)

            # authorize the client
            self._authorizeClient()

            # abort if malformed JSON body
            if bottle.request.json is None or \
                    sorted(bottle.request.json.keys()) != sorted(["commandArray", "fields"]):
                raise bottle.HTTPResponse(
                    status  = 400,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps({'error': 'Malformed JSON body'}),
                )

            # abort if trying to subscribe
            if bottle.request.json["commandArray"] == ["subscribe"]:
                raise bottle.HTTPResponse(
                    status  = 403,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps({'error': 'You cannot issue a "subscribe" command'}),
                )

            # retrieve connector from mgrThread
            connector = self.mgrThread.connector

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
            logCrash(self.name, err)
            raise

    #=== misc

    def _authorizeClient(self):
        if bottle.request.headers.get('X-REALMS-Token') != AppConfig().get("solmanager_token"):
            AppData().incrStats(STAT_JSON_NUM_UNAUTHORIZED)
            raise bottle.HTTPResponse(
                status  = 401,
                headers = {'Content-Type': 'application/json'},
                body    = json.dumps({'error': 'Unauthorized'}),
            )

    def _exec_cmd(self, cmd):
        returnVal = None
        try:
            returnVal = subprocess.check_output(cmd, shell=False)
        except:
            returnVal = "ERROR"
        return returnVal

class SolManager(threading.Thread):

    def __init__(self):
        self.goOn           = True
        self.threads        = {
            "mgrThread"           : None,
            "snapshotThread"      : None,
            "periodicSnapThread"  : None,
            "fileThread"          : None,
            "sendThread"          : None,
            "jsonThread"          : None,
        }
        AppData(AppConfig().get("statsfile"))

        # start myself
        threading.Thread.__init__(self)
        self.name                      = 'SolManager'
        self.start()

    def run(self):
        try:
            # start threads
            log.debug("Starting threads")
            if AppConfig().get('managerconnectionmode')=='serial':
                self.threads["mgrThread"]            = MgrSerialThread()       # connect through serial port
            else:
                self.threads["mgrThread"]            = MgrJsonServerThread()   # connect through JsonServer
            self.threads["snapshotThread"]           = SnapshotThread(
                mgrThread              = self.threads["mgrThread"],
            )
            self.threads["periodicSnapThread"]       = PeriodicSnapshotThread()
            self.threads["fileThread"]               = FileThread()
            self.threads["sendThread"]               = SendThread()
            self.threads["pullThread"]               = PullThread()
            self.threads["statsThread"]              = StatsThread(
                mgrThread              = self.threads["mgrThread"],
            )
            self.threads["jsonThread"]               = JsonThread(
                mgrThread              = self.threads["mgrThread"],
            )

            # wait for all threads to have start
            all_started = False
            while not all_started and self.goOn:
                all_started = True
                for t in self.threads.itervalues():
                    if not t.isAlive():
                        all_started = False
                        log.debug("Waiting for %s to start", t.name)
                time.sleep(5)
            log.debug("All threads started")

            # return as soon as one thread not alive
            while self.goOn:
                # verify that all threads are running
                all_running = True
                for t in self.threads.itervalues():
                    if not t.isAlive():
                        all_running = False
                        log.debug("Thread %s is not running. Quiting.", t.name)
                if not all_running:
                    self.goOn = False
                time.sleep(5)
        except Exception as err:
            logCrash(self.name, err)
        self.close()

    def close(self):
        for t in self.threads.itervalues():
            t.close()
        os._exit(0)  # bypass Cli thread

#============================ main ============================================

solmanager  = None
cli         = None

def quitCallback():
    log.info("Quitting.")
    solmanager.goOn = False

def returnStatsGroup(stats, prefix):
    keys = []
    for (k, v) in stats.items():
        if k.startswith(prefix):
            keys += [k]
    returnVal = []
    for k in sorted(keys):
        returnVal += ['   {0:<30}: {1}'.format(k, stats[k])]
    return returnVal

def cli_cb_stats(params):
    stats = AppData().getStats()
    output  = []
    output += ['#== admin']
    output += returnStatsGroup(stats, 'ADM_')
    output += ['#== connection to manager']
    output += returnStatsGroup(stats, 'MGR_')
    output += ['#== notifications from manager']
    output += returnStatsGroup(stats, 'NUMRX_')
    output += ['#== publication']
    output += returnStatsGroup(stats, 'PUB_')
    output += ['# to file']
    output += returnStatsGroup(stats, 'PUBFILE_')
    output += ['# to server']
    output += returnStatsGroup(stats, 'PUBSERVER_')
    output += ['#== snapshot']
    output += returnStatsGroup(stats, 'SNAPSHOT_')
    output += ['#== JSON interface']
    output += returnStatsGroup(stats, 'JSON_')
    output = '\n'.join(output)
    print output

def main():
    global solmanager

    # create the solmanager instance
    solmanager = SolManager()

    # start the CLI interface
    cli = OpenCli.OpenCli(
        "SolManager",
        solmanager_version.VERSION,
        quitCallback,
        [
            ("SmartMesh SDK", sdk_version.VERSION),
            ("Sol", SolVersion.VERSION),
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
    main()
