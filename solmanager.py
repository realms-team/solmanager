#!/usr/bin/python

#============================ adjust path =====================================

import sys
import os

if __name__ == "__main__":
    here = sys.path[0]
    sys.path.insert(0, os.path.join(here, '..', 'sol'))
    sys.path.insert(0, os.path.join(here, '..', 'smartmeshsdk', 'libs'))
    sys.path.insert(0, os.path.join(here, '..', 'duplex'))

#============================ imports =========================================

# from default Python
import time
import json
import subprocess
import threading
import traceback
import logging.config

# third-party packages
import OpenSSL
import bottle
import requests
import ibmiotf.gateway

# project-specific
import solmanager_version
from   SmartMeshSDK          import sdk_version
from   SmartMeshSDK.utils    import JsonManager, FormatUtils
from   dustCli               import DustCli
from   solobjectlib          import Sol, \
                                    SolVersion, \
                                    SolDefines, \
                                    SolExceptions, \
                                    SolUtils
from DuplexClient import DuplexClient

#============================ logging =========================================

logging.config.fileConfig('logging.conf', disable_existing_loggers=False)
log = logging.getLogger("solmanager")

#============================ defines =========================================

CONFIGFILE         = 'solmanager.config'
STATSFILE          = 'solmanager.stats'
BACKUPFILE         = 'solmanager.backup'

ALLSTATS           = [
    #== admin
    'ADM_NUM_CRASHES',
    #== connection to manager
    'MGR_NUM_CONNECT_ATTEMPTS',
    'MGR_NUM_CONNECT_OK',
    'MGR_NUM_DISCONNECTS',
    'MGR_NUM_TIMESYNC',
    #== notifications from manager
    # note: we count the number of notifications form the manager, for each time, e.g. NUMRX_NOTIFDATA
    # all stats start with "NUMRX_"
    #== publication
    'PUB_TOTAL_SENTTOPUBLISH',
    # to file
    'PUBFILE_BACKLOG',
    'PUBFILE_WRITES',
    # to server
    'PUBSERVER_BACKLOG',
    'PUBSERVER_SENDATTEMPTS',
    'PUBSERVER_UNREACHABLE',
    'PUBSERVER_SENDOK',
    'PUBSERVER_SENDFAIL',
    'PUBSERVER_STATS',
    'PUBSERVER_PULLATTEMPTS',
    'PUBSERVER_PULLOK',
    'PUBSERVER_PULLFAIL',
    #== snapshot
    'SNAPSHOT_NUM_STARTED',
    'SNAPSHOT_LASTSTARTED',
    'SNAPSHOT_NUM_OK',
    'SNAPSHOT_NUM_FAIL',
    #== JSON interface
    'JSON_NUM_REQ',
    'JSON_NUM_UNAUTHORIZED',
]

HTTP_CHUNK_SIZE      = 10 # send batches of 10 Sol objects

#============================ classes =========================================

#======== generic abstract classes


class DoSomethingPeriodic(threading.Thread):
    """
    Abstract DoSomethingPeriodic thread
    """
    def __init__(self, periodvariable):
        self.goOn                       = True
        # start the thread
        threading.Thread.__init__(self)
        self.name                       = 'DoSomethingPeriodic'
        self.daemon                     = True
        self.periodvariable             = periodvariable*60
        self.currentDelay               = 0

    def run(self):
        try:
            self.currentDelay = 5
            while self.goOn:
                self.currentDelay -= 1
                if self.currentDelay == 0:
                    self._doSomething()
                    self.currentDelay = self.periodvariable
                time.sleep(1)
        except Exception as err:
            SolUtils.logCrash(err, SolUtils.AppStats(), threadName=self.name)

    def close(self):
        self.goOn = False

    def _doSomething(self):
        raise SystemError()  # abstract method

#======== connecting to the SmartMesh IP manager


class MgrThread(object):
    """
    Asbtract class which connects to a SmartMesh IP manager, either over serial
    or through a JsonServer.
    """
    def __init__(self):

        # local variables
        self.sol = Sol.Sol()
        self.macManager = None
        self.dataLock = threading.RLock()

    def getMacManager(self):
        if self.macManager is None:
            resp = self.issueRawApiCommand(
                {
                    "manager": 0,
                    "command": "getMoteConfig",
                    "fields": {
                        "macAddress": [0, 0, 0, 0, 0, 0, 0, 0],
                        "next": True
                    }
                }
            )
            assert resp['isAP'] is True
            self.macManager = resp['macAddress']
        return self.macManager

    def _handler_dust_notifs(self, dust_notif):
        try:
            # filter raw HealthReport notifications
            if dust_notif['name'] == "notifHealthReport":
                return

            # update stats
            SolUtils.AppStats().increment('NUMRX_{0}'.format(dust_notif['name']))

            # get time
            epoch = None
            if hasattr(dust_notif, "utcSecs") and hasattr(dust_notif, "utcUsecs"):
                netTs = self._calcNetTs(dust_notif)
                epoch = self._netTsToEpoch(netTs)

            # convert dust notification to JSON SOL Object
            sol_jsonl = self.sol.dust_to_json(
                dust_notif  = dust_notif,
                mac_manager = self.getMacManager(),
                timestamp   = epoch,
            )

            for sol_json in sol_jsonl:
                # update stats
                SolUtils.AppStats().increment('PUB_TOTAL_SENTTOPUBLISH')

                # publish
                PubFileThread().publish(sol_json)  # to the backup file
                PubServerThread().publish(sol_json)  # to the solserver over the Internet
                WastonIotThread().publish(sol_json)  # to the mqtt server over the Internet

        except Exception as err:
            SolUtils.logCrash(err, SolUtils.AppStats())

    def close(self):
        pass

    # === misc

    def _calcNetTs(self, notif):
        return int(float(notif.utcSecs) + float(notif.utcUsecs / 1000000.0))

    def _syncNetTsToUtc(self, netTs):
        with self.dataLock:
            self.tsDiff = time.time() - netTs

    def _netTsToEpoch(self, netTs):
        with self.dataLock:
            return int(netTs + self.tsDiff)

class MgrThreadSerial(MgrThread):

    def __init__(self):

        # initialize the parent class
        super(MgrThreadSerial, self).__init__()

        # initialize JsonManager
        self.jsonManager          = JsonManager.JsonManager(
            serialport            = SolUtils.AppConfig().get("serialport"),
            notifCb               = self._notif_cb,
        )

    def issueRawApiCommand(self, json_payload):
        fields = {}
        if "fields" in json_payload:
            fields = json_payload["fields"]

        if "command" not in json_payload or "manager" not in json_payload:
            return json.dumps({'error': 'Missing parameter.'})

        return self.jsonManager.raw_POST(
            manager          = json_payload['manager'],
            commandArray     = [json_payload['command']],
            fields           = fields,
        )

    def _notif_cb(self, notifName, notifJson):
        super(MgrThreadSerial, self)._handler_dust_notifs(
            notifJson,
        )

class MgrThreadJsonServer(MgrThread, threading.Thread):

    def __init__(self):

        # initialize the parent class
        super(MgrThreadJsonServer, self).__init__()

        # initialize web server
        self.web            = bottle.Bottle()
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
        self.name       = 'MgrThreadJsonServer'
        self.daemon     = True
        self.start()

    def run(self):
        try:
            # wait for banner
            time.sleep(0.5)
            self.web.run(
                host   = '0.0.0.0',
                port   = SolUtils.AppConfig().get("solmanager_tcpport_jsonserver"),
                quiet  = True,
                debug  = False,
            )
        except Exception as err:
            SolUtils.logCrash(err, SolUtils.AppStats(), threadName=self.name)

    def issueRawApiCommand(self, json_payload):
        r = requests.post(
            'http://{0}/api/v1/raw'.format(SolUtils.AppConfig().get("jsonserver_host")),
            json    = json_payload,
        )
        return json.loads(r.text)

    def _webhandler_all_POST(self):
        super(MgrThreadJsonServer, self)._handler_dust_notifs(
            json.loads(bottle.request.body.read()),
        )

#======== publishers


class PubThread(DoSomethingPeriodic):
    """
    Abstract publish thread.
    """
    def __init__(self, periodvariable):
        self.solJsonObjectsToPublish    = []
        self.dataLock                   = threading.RLock()
        self.sol                        = Sol.Sol()
        # initialize parent class
        super(PubThread, self).__init__(periodvariable)
        self.name                       = 'PubThread'
        self.start()

    def getBacklogLength(self):
        with self.dataLock:
            return len(self.solJsonObjectsToPublish)

    def publish(self, sol_json):
        with self.dataLock:
            self.solJsonObjectsToPublish += [sol_json]

    def _doSomething(self):
        self._publishNow()


class PubFileThread(PubThread):
    """
    Singleton that writes Sol JSON objects to a file every period_pubfile_min.
    """
    _instance = None
    _init     = False

    # we buffer objects for BUFFER_PERIOD second to ensure they are written to
    # file chronologically
    BUFFER_PERIOD = 30

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(PubFileThread, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if self._init:
            return
        self._init          = True
        PubThread.__init__(self, SolUtils.AppConfig().get("period_pubfile_min"))
        self.name           = 'PubFileThread'

    def _publishNow(self):
        # update stats
        SolUtils.AppStats().increment('PUBFILE_WRITES')

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

            # update stats
            SolUtils.AppStats().update("PUBFILE_BACKLOG", len(self.solJsonObjectsToPublish))

        # write those to file
        if solJsonObjectsToWrite:
            self.sol.dumpToFile(
                solJsonObjectsToWrite,
                BACKUPFILE,
            )


class PubServerThread(PubThread):
    """
    Singleton that sends Sol JSON objects to the solserver every period_pubserver_min.
    """
    _instance = None
    _init     = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(PubServerThread, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if self._init:
            return
        self._init              = True
        PubThread.__init__(self, SolUtils.AppConfig().get("period_pubserver_min"))
        self.name               = 'PubServerThread'

    def _publishNow(self):
        # stop if nothing to publish
        with self.dataLock:
            if not self.solJsonObjectsToPublish:
                return

        # convert objects to publish to binary until HTTP max size is reached
        object_id = 0
        http_payload = []
        with self.dataLock:
            solBinObjectsToPublish = []
            for (object_id, o) in enumerate(self.solJsonObjectsToPublish):
                solBinObjectsToPublish.append(self.sol.json_to_bin(o))

        # split publish list into chunks
        for i in xrange(0, len(solBinObjectsToPublish), HTTP_CHUNK_SIZE):
            chunk = solBinObjectsToPublish[i: i + HTTP_CHUNK_SIZE]
            http_payload.append(self.sol.bin_to_http(chunk))

        # send http_payload to server
        try:
            # update stats
            SolUtils.AppStats().increment('PUBSERVER_SENDATTEMPTS')
            requests.packages.urllib3.disable_warnings()
            for payload in http_payload:
                log.debug("sending objects, size:%dB", len(payload))
                r = requests.put(
                    'https://{0}/api/v1/o.json'.format(SolUtils.AppConfig().get("solserver_host")),
                    headers = {'X-REALMS-Token': SolUtils.AppConfig().get("solserver_token")},
                    json    = payload,
                    verify  = SolUtils.AppConfig().get("solserver_certificate"),
                )
        except (requests.exceptions.RequestException, OpenSSL.SSL.SysCallError) as err:
            # update stats
            SolUtils.AppStats().increment('PUBSERVER_UNREACHABLE')
            # happens when could not contact server
            log.warning("Error when sending http payload: %s", err)
        else:
            # server answered

            # clear objects
            if r.status_code == requests.codes.ok:
                # update stats
                SolUtils.AppStats().increment('PUBSERVER_SENDOK')
                with self.dataLock:
                    self.solJsonObjectsToPublish = self.solJsonObjectsToPublish[object_id:]
                    SolUtils.AppStats().update("PUBSERVER_BACKLOG", len(self.solJsonObjectsToPublish))
            else:
                # update stats
                SolUtils.AppStats().increment('PUBSERVER_SENDFAIL')
                print "Error HTTP response status: " + str(r.text)
                log.debug(r)


class WastonIotThread(threading.Thread):
    """
    Singleton that directly sends Sol JSON objects to the WastonIoT mqtt server
    """
    _instance = None
    _init = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(WastonIotThread, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self, mgrThread=None, snapshot_thread=None):
        if self._init:
            return
        self._init = True
        threading.Thread.__init__(self)
        self.name = 'WastonIotThread'
        self.mgrThread = mgrThread
        self.snapshot_thread = snapshot_thread
        self.goOn = True
        self.mqtt_client = None

        # wait for mgrThread to be running
        while mgrThread is None or self.mgrThread.macManager is None:
            time.sleep(5)
            log.debug("Waiting for mgrThread to start")
            pass

        # connect to server and subscribe to commands
        self._connect()

        # start self thread
        self.start()

    def run(self):
        while self.goOn:
            self.subscribe()
            time.sleep(10)

    def close(self):
        self.goOn = False
        self.mqtt_client.disconnect()

    # ======================== public =========================================

    def publish(self, sol_object, mqtt_topic=None):
        if self.mqtt_client is None:
            return

        # set topic if not provided as argument
        if mqtt_topic is None:
            mqtt_topic = SolDefines.solTypeToTypeName(SolDefines, sol_object["type"])

        if self.mgrThread.macManager == sol_object["mac"]:
            res = self.mqtt_client.publishGatewayEvent(mqtt_topic,
                                                       "json",
                                                       {"g": sol_object})
        else:
            res = self.mqtt_client.publishDeviceEvent("mote",
                                                      sol_object["mac"],
                                                      mqtt_topic,
                                                      "json",
                                                      sol_object)
        if not res:
            log.warn("Could not publish to MQTT server")
        else:
            log.debug("Published to MQTT")

    def subscribe(self):
        self.mqtt_client.subscribeToGatewayCommands(command='SolManager', format='json', qos=2)
        self.mqtt_client.commandCallback = self._gateway_command_cb

    # ======================== private ========================================

    def _connect(self):
        try:
            options = {
                "org": SolUtils.AppConfig().get("mqtt_organization"),
                "type": "manager",
                "id": FormatUtils.formatBuffer(self.mgrThread.getMacManager()),
                "auth-method": "token",
                "auth-token": SolUtils.AppConfig().get("mqtt_token")
            }
            self.mqtt_client = ibmiotf.gateway.Client(options)
        except ibmiotf.ConnectionException as e:
            print e
        else:
            self.mqtt_client.connect()

    def _gateway_command_cb(self, command):
        log.debug("Id = %s (of type = %s) received the gateway command %s at %s" % (
                command.id, command.type, command.data, command.timestamp))
        if command.data["command"] == "snapshot":
            if self.snapshot_thread.last_snapshot:
                snapshot = self.snapshot_thread.last_snapshot
                snapshot["token"] = command.data["token"]
                WastonIotThread().publish(self.snapshot_thread.last_snapshot, "SolManagerResponse")
            else:
                self.snapshot_thread._doSnapshot()

#======== periodically do something

# publish network snapshot


class SnapshotThread(DoSomethingPeriodic):

    def __init__(self, mgrThread=None):
        assert mgrThread

        # store params
        self.mgrThread       = mgrThread

        # initialize parent class
        super(SnapshotThread, self).__init__(SolUtils.AppConfig().get("period_snapshot_min"))
        self.name            = 'SnapshotThread'
        self.start()

        # initialize local attributes
        self.last_snapshot = None

    def _doSomething(self):
        self._doSnapshot()

    def _doSnapshot(self):
        try:
            # update stats
            SolUtils.AppStats().increment('SNAPSHOT_NUM_STARTED')
            SolUtils.AppStats().update(
                'SNAPSHOT_LASTSTARTED',
                SolUtils.currentUtcTime(),
            )

            '''
            [
                {   'macAddress':          [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08],
                    'moteId':              0x090a,      # INT16U  H
                    'isAP':                0x0b,        # BOOL    B
                    'state':               0x0c,        # INT8U   B
                    'isRouting':           0x0d,        # BOOL    B
                    'numNbrs':             0x0e,        # INT8U   B
                    'numGoodNbrs':         0x0f,        # INT8U   B
                    'requestedBw':         0x10111213,  # INT32U  I
                    'totalNeededBw':       0x14151617,  # INT32U  I
                    'assignedBw':          0x18191a1b,  # INT32U  I
                    'packetsReceived':     0x1c1d1e1f,  # INT32U  I
                    'packetsLost':         0x20212223,  # INT32U  I
                    'avgLatency':          0x24252627,  # INT32U  I
                    'paths': [
                        {
                            'macAddress':   [0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18],
                            'direction':    0x2c,       # INT8U   B
                            'numLinks':     0x2d,       # INT8U   B
                            'quality':      0x2e,       # INT8U   B
                            'rssiSrcDest':  -1,         # INT8    b
                            'rssiDestSrc':  -2,         # INT8    b
                        },
                        {
                            'macAddress':   [0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28],
                            'direction':    0x2c,       # INT8U  B
                            'numLinks':     0x2d,       # INT8U  B
                            'quality':      0x2e,       # INT8U  B
                            'rssiSrcDest':  -1,         # INT8   b
                            'rssiDestSrc':  -2,         # INT8   b
                        },
                    ],
                },
                {
                    'macAddress':           [0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38],
                    'moteId':               0x090a,     # INT16U
                    'isAP':                 0x0b,       # BOOL
                    'state':                0x0c,       # INT8U
                    'isRouting':            0x0d,       # BOOL
                    'numNbrs':              0x0e,       # INT8U
                    'numGoodNbrs':          0x0f,       # INT8U
                    'requestedBw':          0x10111213, # INT32U
                    'totalNeededBw':        0x14151617, # INT32U
                    'assignedBw':           0x18191a1b, # INT32U
                    'packetsReceived':      0x1c1d1e1f, # INT32U
                    'packetsLost':          0x20212223, # INT32U
                    'avgLatency':           0x24252627, # INT32U
                    'paths': [
                        {
                            'macAddress':   [0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48],
                            'direction':    0x2c,       # INT8U
                            'numLinks':     0x2d,       # INT8U
                            'quality':      0x2e,       # INT8U
                            'rssiSrcDest':  -1,         # INT8
                            'rssiDestSrc':  -2,         # INT8
                        },
                    ],
                },
            ]
            '''

            snapshot = []

            # getMoteConfig() on all motes
            currentMac = [0]*8
            while True:
                resp = self.mgrThread.issueRawApiCommand(
                    {
                        "manager": 0,
                        "command": "getMoteConfig",
                        "fields": {
                            "macAddress": currentMac,
                            "next": True
                        }
                    }
                )
                if resp['RC'] != 0:
                    break
                snapshot    += [resp]
                currentMac   = resp['macAddress']

            # getMoteInfo() on all motes
            for mote in snapshot:
                resp = self.mgrThread.issueRawApiCommand(
                    {
                        "manager": 0,
                        "command": "getMoteInfo",
                        "fields": {
                            "macAddress": mote['macAddress'],
                        }
                    }
                )
                mote.update(resp)

            # getPathInfo() on all paths on all motes
            for mote in snapshot:
                mote['paths'] = []
                currentPathId  = 0
                while True:
                    resp = self.mgrThread.issueRawApiCommand(
                        {
                            "manager": 0,
                            "command": "getNextPathInfo",
                            "fields": {
                                "macAddress": mote['macAddress'],
                                "filter":     0,
                                "pathId":     currentPathId
                            }
                        }
                    )
                    if resp["RC"] != 0:
                        break
                    mote['paths'] += [
                        {
                            'macAddress':    resp["dest"],
                            'direction':     resp["direction"],
                            'numLinks':      resp["numLinks"],
                            'quality':       resp["quality"],
                            'rssiSrcDest':   resp["rssiSrcDest"],
                            'rssiDestSrc':   resp["rssiDestSrc"],
                        }
                    ]
                    currentPathId  = resp["pathId"]

        except Exception as err:
            SolUtils.AppStats().increment('SNAPSHOT_NUM_FAIL')
            log.warning("Cannot do Snapshot: %s", err)
            traceback.print_exc()
        else:
            if self.mgrThread.getMacManager() is not None:
                SolUtils.AppStats().increment('SNAPSHOT_NUM_OK')

                # create sensor object
                sobject = {
                    'mac':       self.mgrThread.getMacManager(),
                    'timestamp': int(time.time()),
                    'type':      SolDefines.SOL_TYPE_DUST_SNAPSHOT,
                    'value':     snapshot,
                }
                self.last_snapshot = sobject

                # publish sensor object
                PubFileThread().publish(sobject)
                PubServerThread().publish(sobject)
                WastonIotThread().publish(sobject)

# publish app stats


class StatsThread(DoSomethingPeriodic):
    """
    Publish application statistics every period_stats_min.
    """

    def __init__(self, mgrThread):

        # store params
        self.mgrThread       = mgrThread

        # initialize parent class
        super(StatsThread, self).__init__(SolUtils.AppConfig().get("period_stats_min"))
        self.name            = 'StatsThread'
        self.start()

    def _doSomething(self):

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
        PubFileThread().publish(sobject)
        PubServerThread().publish(sobject)

        # update stats
        SolUtils.AppStats().increment('PUBSERVER_STATS')

# poll for commands from JsonServer


class PollCmdsThread(DoSomethingPeriodic):
    """
    Poll server for commands every period_pollcmds_min.

    This is useful when the solmanager is not reachable by the solserver.
    """
    def __init__(self):
        # initialize parent class
        super(PollCmdsThread, self).__init__(SolUtils.AppConfig().get("period_pollcmds_min"))
        self.name                       = 'PollCmdsThread'
        self.start()

    def _doSomething(self):
        self._poll_server()

    def _poll_server(self):
        # send http_payload to server
        try:
            # update stats
            SolUtils.AppStats().increment('PUBSERVER_PULLATTEMPTS')
            requests.packages.urllib3.disable_warnings()
            r = requests.get(
                'https://{0}/api/v1/getactions/'.format(SolUtils.AppConfig().get("solserver_host")),
                headers = {'X-REALMS-Token': SolUtils.AppConfig().get("solserver_token")},
                verify  = SolUtils.AppConfig().get("solserver_certificate"),
            )
        except (requests.exceptions.RequestException, OpenSSL.SSL.SysCallError) as err:
            # update stats
            SolUtils.AppStats().increment('PUBSERVER_UNREACHABLE')
            # happens when could not contact server
            if type(err) == requests.exceptions.SSLError:
                traceback.print_exc()
        else:
            # server answered

            # clear objects
            if r.status_code == 200:
                # update stats
                SolUtils.AppStats().increment('PUBSERVER_PULLOK')
                for action in r.json():
                    self._handle_command(action['action'])
            else:
                # update stats
                SolUtils.AppStats().increment('PUBSERVER_PULLFAIL')
                print "Error HTTP response status: " + str(r.status_code)
                log.debug(r.json())

    def _handle_command(self, action):
        if action == "update":
            # get last repo version
            os.system("cd " + here + "/../sol/ && git checkout master && git pull origin master")
            os.system("cd " + here + " && git checkout master && git pull origin master")

            # restart program
            python = sys.executable
            os.execl(python, python, * sys.argv)

#======== adding a JSON API to trigger actions on the SolManager


class JsonApiThread(threading.Thread):

    class HTTPSServer(bottle.ServerAdapter):
        def run(self, handler):
            from cheroot.wsgi import Server as WSGIServer
            from cheroot.ssl.pyopenssl import pyOpenSSLAdapter
            server = WSGIServer((self.host, self.port), handler)
            server.ssl_adapter = pyOpenSSLAdapter(
                certificate = SolUtils.AppConfig().get("solmanager_certificate"),
                private_key = SolUtils.AppConfig().get("solmanager_private_key"),
            )
            try:
                server.start()
                log.info("Server started")
            finally:
                server.stop()

    def __init__(self, mgrThread):

        # store params
        self.mgrThread          = mgrThread

        # local variables
        self.sol                = Sol.Sol()

        # check if files exist
        fcert = open(SolUtils.AppConfig().get("solmanager_certificate"))
        fcert.close()
        fkey = open(SolUtils.AppConfig().get("solmanager_private_key"))
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
            path        = '/api/v1/resend.json',
            method      = 'POST',
            callback    = self._webhandler_resend_POST,
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
                host   = '0.0.0.0',
                port   = SolUtils.AppConfig().get("solmanager_tcpport_solserver"),
                server = self.HTTPSServer,
                quiet  = True,
                debug  = False,
            )
        except Exception as err:
            SolUtils.logCrash(err, SolUtils.AppStats(), threadName=self.name)

    #======================== public ==========================================

    def close(self):
        self.web.close()

    #======================== private ==========================================

    #=== webhandlers

    # decorator
    def _authorized_webhandler(func):
        def hidden_decorator(self):
            try:
                # update stats
                SolUtils.AppStats().increment('JSON_NUM_REQ')

                # authorize the client
                self._authorizeClient()

                # retrieve the return value
                returnVal = func(self)

                # send back answer
                return bottle.HTTPResponse(
                    status  = 200,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps(returnVal),
                )

            except SolExceptions.UnauthorizedError:
                return bottle.HTTPResponse(
                    status  = 401,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps({'error': 'Unauthorized'}),
                )
            except Exception as err:

                crashMsg = SolUtils.logCrash(err, SolUtils.AppStats())

                return bottle.HTTPResponse(
                    status  = 500,
                    headers = {'Content-Type': 'application/json'},
                    body    = json.dumps(crashMsg),
                )
        return hidden_decorator

    @_authorized_webhandler
    def _webhandler_echo_POST(self):
        return bottle.request.body.read()

    @_authorized_webhandler
    def _webhandler_status_GET(self):
        return {
            'version solmanager':     solmanager_version.VERSION,
            'version SmartMesh SDK':  sdk_version.VERSION,
            'version Sol':            SolVersion.VERSION,
            'uptime computer':        self._exec_cmd('uptime'),
            'utc':                    int(time.time()),
            'date':                   SolUtils.currentUtcTime(),
            'last reboot':            self._exec_cmd('last reboot'),
            'stats':                  SolUtils.AppStats().get(),
        }

    @_authorized_webhandler
    def _webhandler_resend_POST(self):
        # abort if malformed JSON body
        if bottle.request.json is None:
            return {'error': 'Malformed JSON body'}

        # verify all fields are present
        required_fields = ["action", "startTimestamp", "endTimestamp"]
        for field in required_fields:
            if field not in bottle.request.json:
                return {'error': 'Missing field {0}'.format(field)}

        # handle
        action          = bottle.request.json["action"]
        startTimestamp  = bottle.request.json["startTimestamp"]
        endTimestamp    = bottle.request.json["endTimestamp"]
        if action == "count":
            sol_jsonl = self.sol.loadFromFile(BACKUPFILE, startTimestamp, endTimestamp)
            # send response
            return {'numObjects': len(sol_jsonl)}
        elif action == "resend":
            sol_jsonl = self.sol.loadFromFile(BACKUPFILE, startTimestamp, endTimestamp)
            # publish
            for sobject in sol_jsonl:
                PubServerThread().publish(sobject)
            # send response
            return {'numObjects': len(sol_jsonl)}
        else:
            return {'error': 'Unknown action {0}'.format(action)}

    @_authorized_webhandler
    def _webhandler_smartmeshipapi_POST(self):
        return self.mgrThread.issueRawApiCommand(json.loads(bottle.request.json))

    #=== misc

    def _authorizeClient(self):
        if bottle.request.headers.get('X-REALMS-Token') != SolUtils.AppConfig().get("solmanager_token"):
            SolUtils.AppStats().increment('JSON_NUM_UNAUTHORIZED')
            raise SolExceptions.UnauthorizedError()

    def _exec_cmd(self, cmd):
        returnVal = None
        try:
            returnVal = subprocess.check_output(cmd, shell=False)
        except:
            returnVal = "ERROR"
        return returnVal

#======== main application thread


class SolManager(threading.Thread):

    def __init__(self):
        self.goOn           = True
        self.threads        = {
            "mgrThread"                : None,
            "pubFileThread"            : None,
            "pubServerThread"          : None,
            "wastonIotThread"          : None,
            "snapshotThread"           : None,
            "statsThread"              : None,
            "pollForCommandsThread"    : None,
            "jsonApiThread"            : None,
        }

        # init Singletons -- must be first init
        SolUtils.AppConfig(config_file=CONFIGFILE)
        SolUtils.AppStats(stats_file=STATSFILE, stats_list=ALLSTATS)

        # CLI interface
        self.cli                       = DustCli.DustCli("SolManager", self._clihandle_quit)
        self.cli.registerCommand(
            name                       = 'stats',
            alias                      = 's',
            description                = 'print the stats',
            params                     = [],
            callback                   = self._clihandle_stats,
        )
        self.cli.registerCommand(
            name                       = 'versions',
            alias                      = 'v',
            description                = 'print the versions of the different components',
            params                     = [],
            callback                   = self._clihandle_versions,
        )
        self.cli.registerCommand(
            name='tx',
            alias='tx',
            description='transmit to server',
            params=['msg'],
            callback=self._clihandle_tx,
        )

        self.cli.start()

        self.duplexClient = DuplexClient.from_url(
            server_url='http://127.0.0.1:8080/api/v1/o.json',
            id="test",
            token='mytoken',
            polling_period=1,
            from_server_cb=self.from_server_cb,
        )

        # start myself
        threading.Thread.__init__(self)
        self.name                      = 'SolManager'
        self.daemon                    = True
        self.start()

    def run(self):
        try:
            # start threads
            log.debug("Starting threads")
            if SolUtils.AppConfig().get('managerconnectionmode') == 'serial':
                self.threads["mgrThread"]            = MgrThreadSerial()
            else:
                self.threads["mgrThread"]            = MgrThreadJsonServer()
            self.threads["pubFileThread"]            = PubFileThread()
            # self.threads["pubServerThread"]          = PubServerThread()
            self.threads["snapshotThread"] = SnapshotThread(
                mgrThread=self.threads["mgrThread"],
            )
            # self.threads["wastonIotThread"]          = WastonIotThread(
            #     mgrThread              = self.threads["mgrThread"],
            #     snapshot_thread        = self.threads["snapshotThread"],
            # )
            self.threads["statsThread"]              = StatsThread(
                mgrThread              = self.threads["mgrThread"],
            )
            # self.threads["pollForCommandsThread"]    = PollCmdsThread()
            self.threads["jsonApiThread"]            = JsonApiThread(
                mgrThread              = self.threads["mgrThread"],
            )

            # wait for all threads to have started
            all_started = False
            while not all_started and self.goOn:
                all_started = True
                for t in self.threads.itervalues():
                    try:
                        if not t.isAlive():
                            all_started = False
                            log.debug("Waiting for %s to start", t.name)
                    except AttributeError:
                        pass  # happens when not a real thread
                time.sleep(5)
            log.debug("All threads started")

            # return as soon as one thread not alive
            while self.goOn:
                # verify that all threads are running
                all_running = True
                for t in self.threads.itervalues():
                    try:
                        if not t.isAlive():
                            all_running = False
                            log.debug("Thread {0} is not running. Quitting.".format(t.name))
                    except AttributeError:
                        pass  # happens when not a real thread
                if not all_running:
                    self.goOn = False
                time.sleep(5)
        except Exception as err:
            SolUtils.logCrash(err, SolUtils.AppStats(), threadName=self.name)
        self.close()

    def close(self):
        os._exit(0)  # bypass CLI thread

    def _clihandle_quit(self):
        time.sleep(.3)
        print "bye bye."
        # all threads as daemonic, will close automatically

    def _clihandle_stats(self, params):
        stats = SolUtils.AppStats().get()
        output  = []
        output += ['#== admin']
        output += self._returnStatsGroup(stats, 'ADM_')
        output += ['#== connection to manager']
        output += self._returnStatsGroup(stats, 'MGR_')
        output += ['#== notifications from manager']
        output += self._returnStatsGroup(stats, 'NUMRX_')
        output += ['#== publication']
        output += self._returnStatsGroup(stats, 'PUB_')
        output += ['# to file']
        output += self._returnStatsGroup(stats, 'PUBFILE_')
        output += ['# to server']
        output += self._returnStatsGroup(stats, 'PUBSERVER_')
        output += ['#== snapshot']
        output += self._returnStatsGroup(stats, 'SNAPSHOT_')
        output += ['#== JSON interface']
        output += self._returnStatsGroup(stats, 'JSON_')
        output = '\n'.join(output)
        print output

    def _clihandle_versions(self, params):
        output  = []
        for (k, v) in [
                ('SolManager',    solmanager_version.VERSION),
                ('Sol',           SolVersion.VERSION),
                ('SmartMesh SDK', sdk_version.VERSION),
            ]:
            output += ["{0:>15} {1}".format(k, '.'.join([str(b) for b in v]))]
        output = '\n'.join(output)
        print output

    def _clihandle_tx(self, params):
        msg = params[0]
        self.duplexClient.to_server([{'msg': msg}])

    def _returnStatsGroup(self, stats, prefix):
        keys = []
        for (k, v) in stats.items():
            if k.startswith(prefix):
                keys += [k]
        returnVal = []
        for k in sorted(keys):
            returnVal += ['   {0:<30}: {1}'.format(k, stats[k])]
        return returnVal

    def from_server_cb(self):
        pass

#============================ main ============================================


def main():
    solmanager = SolManager()


if __name__ == '__main__':
    main()
