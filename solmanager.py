#!/usr/bin/python

__version__ = (2, 0, 0, 0)

# =========================== adjust path =====================================

import sys
import os

if __name__ == "__main__":
    here = sys.path[0]
    sys.path.insert(0, os.path.join(here, 'libs', 'sol-REL-1.4.0.0'))
    sys.path.insert(0, os.path.join(here, 'libs', 'smartmeshsdk-REL-1.1.2.4', 'libs'))
    sys.path.insert(0, os.path.join(here, 'libs', 'duplex-REL-1.0.0.0'))

# =========================== imports =========================================

# from default Python
import time
import json
import threading
import logging.config
import base64
import traceback
import argparse

# project-specific
from   SmartMeshSDK          import sdk_version, \
                                    ApiException
from   SmartMeshSDK.utils    import JsonManager, \
                                    FormatUtils
from   dustCli               import DustCli
from   solobjectlib          import Sol, \
                                    SolVersion, \
                                    SolDefines, \
                                    SolUtils
from   DuplexClient          import DuplexClient

# =========================== logging =========================================

logging.config.fileConfig('logging.conf', disable_existing_loggers=False)
log = logging.getLogger("solmanager")

# =========================== defines =========================================

DFLT_CONFIGFILE    = 'solmanager.config'
STATSFILE          = 'solmanager.stats'
BACKUPFILE         = 'solmanager.backup'

ALLSTATS           = [
    #== admin
    'ADM_NUM_CRASHES',
    #== notifications from manager
    # note: we count the number of notifications form the manager, for each time, e.g. NUMRX_NOTIFDATA
    # all stats start with "NUMRX_"
    #== publication
    'PUB_TOTAL_SENTTOPUBLISH',
    # to file
    'PUBFILE_PUBBINARY',
    'PUBFILE_BACKLOG',
    'PUBFILE_WRITES',
    # to server
    'PUBSERVER_PUBBINARY',
    'PUBSERVER_PUBJSON',
    'PUBSERVER_FROMSERVER',
]

# =========================== helpers =========================================

def getVersions():
    return {
        'SolManager'    : list(__version__),
        'Sol'           : list(SolVersion.VERSION),
        'SmartMesh SDK' : list(sdk_version.VERSION),
    }

# =========================== classes =========================================

class Tracer(object):
    """
    Singleton that writes trace to CLI
    """
    _instance = None
    _init     = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Tracer, cls).__new__(cls, *args, **kwargs)
        return cls._instance
    
    def __init__(self):
        if self._init:
            return
        self._init           = True
        self.dataLock        = threading.RLock()
        self.traceOn         = False
    
    #======================== public ==========================================
    
    def setTraceOn(self,newTraceOn):
        assert newTraceOn in [True,False]
        with self.dataLock:
            self.traceOn     = newTraceOn
    
    def trace(self,msg):
        with self.dataLock:
            go = self.traceOn
        if go:
            print msg

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
        self.sol        = Sol.Sol()
        self.macManager = None
        self.dataLock   = threading.RLock()

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

        # record the manager's MAC address
        while self.macManager is None:
            try:
                self.macManager = self.get_mac_manager()
            except ApiException.ConnectionError as err:
                log.warn(err)
                time.sleep(1)
        log.debug("Connected to manager {0}".format(self.macManager))


    # ======================= public ==========================================

    def get_mac_manager(self):
        if self.macManager is None:
            resp = self.jsonManager.raw_POST(
                manager          = 0,
                commandArray     = ["getMoteConfig"],
                fields           = {
                    "macAddress": [0, 0, 0, 0, 0, 0, 0, 0],
                    "next": True
                },
            )
            assert resp['isAP'] is True
            self.macManager = FormatUtils.formatBuffer(resp['macAddress'])
        return self.macManager

    def from_server_cb_MgrThread(self,o):
        try:
            if   o['command']=='JsonManager':
                '''
                o = {
                    'type':          'manager',
                    'id':            '00-17-0d-00-00-30-3c-03',
                    'format':        'json',
                    'command':       'JsonManager',
                    'timestamp':     '2018-01-30 15:55:12.056165+00:00',
                    'data':          {
                        'function':  'status_GET',
                        'args':      {},
                        'token':     'myToken',
                    }
                }
                '''
                assert o['type']=='manager'
                assert o['format']=='json'
                try:
                    assert o['data']['function'].split('_')[-1] in ['GET','PUT','POST','DELETE']
                    # find the function to call
                    func = getattr(self.jsonManager,o['data']['function'])
                    # call the function
                    res = func(**o['data']['args'])
                except Exception as err:
                    value = {
                        'success':   False,
                        'return':    str(err),
                    }
                else:
                    value = {
                        'success':   True,
                        'return':    res,
                    }
                finally:
                    if 'token' in o['data']:
                        value['token'] = o['data']['token']
                    json_res = {
                        'type':          'JsonManagerResponse',
                        'mac':           o['id'],
                        'manager':       self.macManager,
                        'value':         value,
                    }
                    PubServer().publishJson(json_res)
            elif o['command']=='oap':
                '''
                o = {
                    'type':          'mote',
                    'id':            '00-17-0d-00-00-38-03-69',
                    'format':        'json',
                    'command':       'oap',
                    'timestamp':     '2018-01-30 15:55:12.056165+00:00',
                    'data':          {
                        'function':  'digital_out_PUT',
                        'args':      {
                            "pin" :       2,
                            "body":       {
                                "value":  1
                            }
                        },
                        'token':     'myToken',
                    }
                }
                '''
                assert o['type']=='mote'
                assert o['format']=='json'
                try:
                    assert o['data']['function'].split('_')[-1] in ['GET','PUT','POST','DELETE']
                    # find the function to call
                    func = getattr(self.jsonManager,'oap_{0}'.format(o['data']['function']))
                    # format the args
                    args = o['data']['args']
                    args['mac'] = o['id']
                    # call the function
                    res = func(**args)
                except NameError:
                    value = {
                        'success':     False,
                        'error':       'timeout',
                    }
                except Exception as err:
                    value = {
                        'success':     False,
                        'error':       str(err),
                    }
                else:
                    value = {
                        'success':     True,
                        'return':      res,
                    }
                finally:
                    if 'token' in o['data']:
                        value['token'] = o['data']['token']
                    json_res = {
                        'type':          'oapResponse',
                        'mac':           o['id'],
                        'manager':       self.macManager,
                        'value':         value,
                    }
                    PubServer().publishJson(json_res)
        except Exception as err:
            log.error("could not execute {0}: {1}".format(o,traceback.format_exc()))

    def close(self):
        pass

    # ======================= private =========================================

    def _notif_cb(self, notifName, notifJson):
        self._handler_dust_notifs(
            notifJson,
            notifName
        )

    def _handler_dust_notifs(self, dust_notif, notif_name=""):
        if   (notif_name!="") and ('name' not in dust_notif):
            dust_notif['name'] = notif_name
        elif (notif_name=="") and ('name' not in dust_notif):
            logging.warning("Cannot find notification name")
            return

        try:
            # trace
            Tracer().trace('from manager: {0}'.format(dust_notif['name']))
            
            # filter raw HealthReport notifications
            if dust_notif['name'] == "notifHealthReport":
                return

            # change "manager" field of snaphots (for stars to display correctly)
            if dust_notif['name'] == "snapshot":
                dust_notif['manager'] = self.get_mac_manager()

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
                # publish
                PubFile().publishBinary(sol_json)     # to the backup file
                PubServer().publishBinary(sol_json)   # to the solserver over the Internet

        except Exception as err:
            SolUtils.logCrash(err, SolUtils.AppStats())

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

class Pub(object):
    """
    Abstract publish thread.
    """
    def __init__(self):
        self.sol             = Sol.Sol()
        self.dataLock        = threading.RLock()
    
    def publishBinary(self, o):
        raise SystemError("abstract method")

    def publishJson(self, o):
        raise SystemError("abstract method")

class PubFile(Pub,DoSomethingPeriodic):
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
            cls._instance = super(PubFile, cls).__new__(cls, *args, **kwargs)
        return cls._instance
    
    def __init__(self):
        if self._init:
            return
        self._init           = True
        self.toPublishBinary = []
        # initialize parent classes
        Pub.__init__(self)
        DoSomethingPeriodic.__init__(self, SolUtils.AppConfig().get("period_pubfile_min"))
        self.name            = 'PubFile'
        self.start()
    
    #======================== public ==========================================
    
    def publishBinary(self, o):
        
        # update stats
        SolUtils.AppStats().increment('PUBFILE_PUBBINARY')
        
        with self.dataLock:
            self.toPublishBinary += [o]
            
            # update stats
            SolUtils.AppStats().update("PUBFILE_BACKLOG", len(self.toPublishBinary))
    
    def publishJson(self, o):
        raise SystemError('publishJson not supported in PubFile')
    
    def getBacklogLength(self):
        with self.dataLock:
            return len(self.toPublishBinary)
    
    #======================== private =========================================
    
    def _doSomething(self):
        self._publishNow()
    
    def _publishNow(self):
        # update stats
        SolUtils.AppStats().increment('PUBFILE_WRITES')
        
        # trace
        Tracer().trace('write to backup file')
        
        with self.dataLock:
            # order toPublishBinary chronologically
            self.toPublishBinary.sort(key=lambda i: i['timestamp'])

            # extract the JSON SOL objects heard more than BUFFER_PERIOD ago
            now = time.time()
            solJsonObjectsToWrite = []
            while True:
                if not self.toPublishBinary:
                    break
                if now-self.toPublishBinary[0]['timestamp'] < self.BUFFER_PERIOD:
                    break
                solJsonObjectsToWrite += [self.toPublishBinary.pop(0)]

            # update stats
            SolUtils.AppStats().update("PUBFILE_BACKLOG", len(self.toPublishBinary))

        # write those to file
        if solJsonObjectsToWrite:
            self.sol.dumpToFile(
                solJsonObjectsToWrite,
                BACKUPFILE,
            )

class PubServer(Pub):
    """
    Singleton that sends objects to the solserver.
    """
    _instance = None
    _init     = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(PubServer, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if self._init:
            return
        self._init              = True
        Pub.__init__(self)
        self.name               = 'PubServer'
        self.duplex_client      = None
    
    #======================== public ==========================================
    
    def setDuplexClient(self, duplex_client):
        with self.dataLock:
            self.duplex_client  = duplex_client

    def publishBinary(self, o):
        # stop if duplex_client not configured yet
        with self.dataLock:
            if not self.duplex_client:
                return
        
        # update stats
        SolUtils.AppStats().increment('PUBSERVER_PUBBINARY')
        
        # convert objects and push to duplex_client
        o = self.sol.json_to_bin(o)
        o = base64.b64encode(''.join(chr(b) for b in o))
        o = json.dumps(['b',o])
        log.debug("sending binary object, size: {0} B".format(len(o)))
        self.duplex_client.to_server(o)

    def publishJson(self, o):
        # stop if duplex_client not configured yet
        with self.dataLock:
            if not self.duplex_client:
                return
        
        # update stats
        SolUtils.AppStats().increment('PUBSERVER_PUBJSON')

        # convert objects and push to duplex_client
        o = json.dumps(['j',o])
        log.debug("sending json object, size: {0} B".format(len(o)))
        self.duplex_client.to_server(o)

# ======= periodically do something

class SolSnapshotThread(DoSomethingPeriodic):

    def __init__(self, mgrThread=None):
        assert mgrThread

        # store params
        self.mgrThread       = mgrThread

        # initialize parent class
        super(SolSnapshotThread, self).__init__(SolUtils.AppConfig().get("period_snapshot_min"))
        self.name            = 'SolSnapshotThread'
        self.start()

        # initialize local attributes
        self.last_snapshot = None

    def _doSomething(self):
        self._doSnapshot()

    def _doSnapshot(self):
        # trace
        Tracer().trace('trigger snapshot')
        
        ret = self.mgrThread.jsonManager.snapshot_POST(manager=0)

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
        
        # trace
        Tracer().trace('collect statistics')
        
        # create sensor object
        sobject = {
            'mac':       self.mgrThread.get_mac_manager(),
            'timestamp': int(time.time()),
            'type':      SolDefines.SOL_TYPE_SOLMANAGER_STATS,
            'value':     getVersions(),
        }
        
        # publish
        PubFile().publishBinary(sobject)
        PubServer().publishBinary(sobject)

# ======= main application thread

class SolManager(threading.Thread):

    def __init__(self,configfile):
        # store params
        self.configfile     = configfile

        # local variables
        self.goOn           = True
        self.threads        = {
            "mgrThread"                : None,
            "pubFile"                  : None,
            "pubServer"                : None,
            "solSnapshotThread"        : None,
            "statsThread"              : None,
            "pollForCommandsThread"    : None,
        }
        self.duplex_client = None

        # init Singletons
        SolUtils.AppConfig(config_file=self.configfile)
        SolUtils.AppStats(stats_file=STATSFILE, stats_list=ALLSTATS)

        # CLI interface
        self.cli                       = DustCli.DustCli(
            appName     = "SolManager",
            quit_cb     = self._clihandle_quit,
            versions    = getVersions(),
        )
        self.cli.registerCommand(
            name                       = 'trace',
            alias                      = 't',
            description                = 'switch trace on/off',
            params                     = ["state",],
            callback                   = self._clihandle_trace,
        )
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
            self.threads["mgrThread"]  = MgrThread()

            # start the duplexClient
            self.duplex_client = DuplexClient.from_url(
                server_url             = 'http://{0}/api/v1/o.json'.format(SolUtils.AppConfig().get("solserver_host")),
                id                     = self.threads["mgrThread"].get_mac_manager(),
                token                  = SolUtils.AppConfig().get("solserver_token"),
                polling_period         = SolUtils.AppConfig().get("period_pollserver_min")*60,
                from_server_cb         = self.from_server_cb_JsonManager,
                buffer_tx              = False,
            )
            while self.duplex_client is None:
                log.warning("Waiting for duplex client to be started")
                time.sleep(1)
            log.debug("duplex client started")

            # start the all other threads
            self.threads["pubFile"]                  = PubFile()
            self.threads["pubServer"]                = PubServer()
            self.threads["pubServer"].setDuplexClient(self.duplex_client)
            self.threads["solSnapshotThread"]        = SolSnapshotThread(
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
                            log.info("Waiting for %s to start", t.name)
                    except AttributeError:
                        pass  # happens when not a real thread
                time.sleep(5)
            log.info("All threads started")

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

    def _clihandle_trace(self, params):
        if params[0]=='on':
            Tracer().setTraceOn(True)
            print 'trace on'
        else:
            Tracer().setTraceOn(False)
            print 'trace off'
       
    def _clihandle_stats(self, params):
        stats = SolUtils.AppStats().get()
        output  = []
        output += ['#== admin']
        output += self._returnStatsGroup(stats, 'ADM_')
        output += ['#== notifications from manager']
        output += self._returnStatsGroup(stats, 'NUMRX_')
        output += ['#== publication']
        output += self._returnStatsGroup(stats, 'PUB_')
        output += ['# to file']
        output += self._returnStatsGroup(stats, 'PUBFILE_')
        output += ['# to server']
        output += self._returnStatsGroup(stats, 'PUBSERVER_')
        output = '\n'.join(output)
        print output

    def _clihandle_versions(self, params):
        output  = []
        for (k,v) in getVersions().items():
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

    def from_server_cb_JsonManager(self, os):
        
        # update stats
        SolUtils.AppStats().increment('PUBSERVER_FROMSERVER')
        
        log.debug("from_server_cb_JsonManager: {0}".format(os))
        for o in os:
            try:
                name    = '{0}.{1}.{2}'.format(
                    o['id'],
                    o['command'],
                    o['data']['function'],
                )
            except:
                name    = 'from_server'
            threading.Thread(
                target  = self.threads["mgrThread"].from_server_cb_MgrThread,
                args    = (o,),
                name    = name,
            ).start()

# =========================== main ============================================

def main(args):
    SolManager(**args)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--configfile',     default=DFLT_CONFIGFILE)
    args = vars(parser.parse_args())
    main(args)
