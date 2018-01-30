#!/usr/bin/python

# =========================== adjust path =====================================

import sys
import os

if __name__ == "__main__":
    here = sys.path[0]
    sys.path.insert(0, os.path.join(here, '..', 'sol'))
    sys.path.insert(0, os.path.join(here, '..', 'smartmeshsdk', 'libs'))
    sys.path.insert(0, os.path.join(here, '..', 'duplex'))

# =========================== imports =========================================

# from default Python
import time
import json
import threading
import logging.config

# project-specific
import solmanager_version
from   SmartMeshSDK          import sdk_version
from   SmartMeshSDK.utils    import JsonManager, FormatUtils
from   dustCli               import DustCli
from   solobjectlib          import Sol, \
                                    SolVersion, \
                                    SolDefines, \
                                    SolUtils
from DuplexClient import DuplexClient

# =========================== logging =========================================

logging.config.fileConfig('logging.conf', disable_existing_loggers=False)
log = logging.getLogger("solmanager")

# =========================== defines =========================================

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

HTTP_CHUNK_SIZE     = 10  # send batches of 10 Sol objects

# =========================== classes =========================================

# ======= generic abstract classes

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

# ======= connecting to the SmartMesh IP manager

class MgrThread(object):
    """
    Thread to start the connection with the Dust Manager using the JsonManager
    """

    def __init__(self):

        # local variables
        self.sol = Sol.Sol()
        self.macManager = None
        self.dataLock = threading.RLock()

        # initialize JsonManager
        self.jsonManager = JsonManager.JsonManager(
            autoaddmgr      = False,
            autodeletemgr   = False,
            serialport      = SolUtils.AppConfig().get("serialport"),
            notifCb         = self._notif_cb,
        )

        # todo replace this by JsonManager method to know when a manager is ready
        while self.jsonManager.managerHandlers == {}:
            time.sleep(1)
        while self.jsonManager.managerHandlers[self.jsonManager.managerHandlers.keys()[0]].connector is None:
            time.sleep(1)

        self.macManager = self.get_mac_manager()

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
        self._handler_dust_notifs(
            notifJson,
            notifName
        )

    def get_mac_manager(self):
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
            self.macManager = FormatUtils.formatBuffer(resp['macAddress'])
        return self.macManager

    def _handler_dust_notifs(self, dust_notif, notif_name=""):
        if notif_name != "" and 'name' not in dust_notif:
            dust_notif['name'] = notif_name
        elif notif_name == "" and 'name' not in dust_notif:
            logging.warning("Cannot find notification name")
            return

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
                mac_manager = self.get_mac_manager(),
                timestamp   = epoch,
            )

            for sol_json in sol_jsonl:
                # update stats
                SolUtils.AppStats().increment('PUB_TOTAL_SENTTOPUBLISH')

                # publish
                PubFileThread().publish(sol_json)  # to the backup file
                PubServerThread().publish(sol_json)  # to the solserver over the Internet

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

# ======= publishers

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
        self.duplex_client      = None
    
    def setDuplexClient(self, duplex_client):
        with self.dataLock:
            self.duplex_client  = duplex_client
    
    def _publishNow(self):
        # stop if nothing to publish
        with self.dataLock:
            if not self.solJsonObjectsToPublish:
                return
        
        # stop if Duplexclient not configured yet
        with self.dataLock:
            if not self.duplex_client:
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

        # update stats
        res = False
        SolUtils.AppStats().increment('PUBSERVER_SENDATTEMPTS')
        for payload in http_payload:
            log.debug("sending objects, size:%dB", len(payload))
            res = self.duplex_client.to_server([payload])

        if res is False:
            SolUtils.AppStats().increment('PUBSERVER_SENDFAIL')
        else:  # server answered
            SolUtils.AppStats().increment('PUBSERVER_SENDOK')
            with self.dataLock:
                self.solJsonObjectsToPublish = self.solJsonObjectsToPublish[object_id:]
                SolUtils.AppStats().update("PUBSERVER_BACKLOG", len(self.solJsonObjectsToPublish))

# ======= periodically do something

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
        ret = self.mgrThread.jsonManager.snapshot_POST(manager=0)

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
            'mac':       self.mgrThread.get_mac_manager(),
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

# ======= main application thread

class SolManager(threading.Thread):

    def __init__(self):
        self.goOn           = True
        self.threads        = {
            "mgrThread"                : None,
            "pubFileThread"            : None,
            "pubServerThread"          : None,
            "snapshotThread"           : None,
            "statsThread"              : None,
            "pollForCommandsThread"    : None,
        }
        self.duplex_client = None

        # init Singletons
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

        # start myself
        threading.Thread.__init__(self)
        self.name                      = 'SolManager'
        self.daemon                    = True
        self.start()

    def run(self):
        try:
            # start manager thread
            self.threads["mgrThread"]            = MgrThread()

            # wait for manager thread to start
            while self.threads["mgrThread"].macManager is None:
                time.sleep(2)
            log.debug("Manager MAC is {0}".format(self.threads["mgrThread"].get_mac_manager()))

            # start the duplexClient
            self.duplex_client = DuplexClient.from_url(
                server_url        = 'http://{0}/api/v1/o.json'.format(SolUtils.AppConfig().get("solserver_host")),
                id                = self.threads["mgrThread"].get_mac_manager(),
                token             = SolUtils.AppConfig().get("solserver_token"),
                polling_period    = SolUtils.AppConfig().get("period_pollcmds_min")*60,
                from_server_cb    = self.from_server_cb,
                buffer_tx         = False,
            )
            while self.duplex_client is None:
                log.debug("Waiting for duplex client to be started")
                time.sleep(1)
            log.debug("duplex client started")

            # start the all other threads
            self.threads["pubFileThread"]            = PubFileThread()
            self.threads["pubServerThread"]          = PubServerThread()
            self.threads["pubServerThread"].setDuplexClient(self.duplex_client)
            self.threads["snapshotThread"]           = SnapshotThread(
                mgrThread=self.threads["mgrThread"],
            )
            self.threads["statsThread"]              = StatsThread(
                mgrThread=self.threads["mgrThread"],
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
        self.duplex_client.to_server([{'msg': msg}])

    def _returnStatsGroup(self, stats, prefix):
        keys = []
        for (k, v) in stats.items():
            if k.startswith(prefix):
                keys += [k]
        returnVal = []
        for k in sorted(keys):
            returnVal += ['   {0:<30}: {1}'.format(k, stats[k])]
        return returnVal

    def from_server_cb(self, o):
        print "from_server_cb: {0}".format(o)
        print 'TODO: handle messages received from server'

# =========================== main ============================================

def main():
    SolManager()

if __name__ == '__main__':
    main()
