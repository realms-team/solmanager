import sys
import Queue
import time
import threading
import collections

import requests

# =========================== logging =========================================

import logging
logger = logging.getLogger(__name__)

# =========================== classes =========================================

def convertToString(data):
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(map(convertToString, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convertToString, data))
    else:
        return data

class DuplexClientPeriodicTimer(threading.Thread):
    def __init__(self, period, func):
        # store params
        self.period                     = period
        self.func                       = func
        # local variables
        self.dataLock                   = threading.RLock()
        self.goOn                       = True
        self.currentDelay               = 0
        # start the thread
        threading.Thread.__init__(self)
        self.name                       = 'DuplexClientPeriodicTimer'
        self.daemon                     = True
        self.start()
    def run(self):
        try:
            self.currentDelay = 1
            while self.goOn:
                funcToCall = None
                with self.dataLock:
                    self.currentDelay -= 1
                    if self.currentDelay == 0:
                        funcToCall = self.func
                        self.currentDelay = self.period
                if funcToCall:
                    try:
                        funcToCall()
                    except Exception as err:
                        logger.critical("DuplexClientPeriodicTimer could not call {0}: {1}".format(funcToCall,err))
                time.sleep(1)
        except Exception as err:
            logger.critical("DuplexClientPeriodicTimer crashed: {0}".format(err))
    def fireNow(self):
        with self.dataLock:
            self.currentDelay = 1
    def close(self):
        self.goOn = False

class DuplexClient(object):
    
    def __init__(self, kwargs):
        self.from_server_cb = kwargs['from_server_cb']
        self.id             = kwargs['id']
        self.token          = kwargs['token']

    @classmethod
    def from_url(cls, **kwargs):
        server_url = kwargs['server_url']
        if   server_url.startswith('http'):
            return DuplexClientHttp(kwargs)
        elif server_url.startswith('ws'):
            return DuplexClientWs(kwargs)
        else:
            raise SystemError()

    def to_server(self, o):
        raise NotImplementedError()
    def getStatus(self):
        raise NotImplementedError()

class DuplexClientHttp(DuplexClient):
    
    MAXQUEUEZISE = 100
    
    def __init__(self, kwargs):
        '''
        The following kwargs MUST be present:
        - the required kwargs for the DuplexClient class
        - 'server_url' URL of the server, e.g. "http://127.0.0.1:8080/api/v1/o.json"
        - 'polling_period' the period (in seconds) with which the DuplexClientHttp instance polls the server
        - 'buffer_tx' a boolean. It False, objects passed through the to_server() method are buffered until the next polling_period.
        '''

        # store params
        self.server_url      = kwargs['server_url']
        self.polling_period  = kwargs['polling_period']
        self.buffer_tx       = kwargs['buffer_tx']
        
        # local variables
        self.dataLock        = threading.RLock()
        self.toserverqueue   = Queue.Queue(maxsize=self.MAXQUEUEZISE)
        self.is_connected    = False
        self.lastheard_ts    = None
        self._set_is_connected(False)
        
        # initialize parent
        DuplexClient.__init__(self, kwargs)

        # start periodic timer, and fire now
        self.periodicTimer   = DuplexClientPeriodicTimer(
            period = self.polling_period,
            func   = self._poll_server,
        )
        self.periodicTimer.fireNow()

    # ======================= public ==========================================
    
    def to_server(self, o):
        '''
        'o' contains a single object ['b','yttywetywe']
        '''
        assert type(o)==str
        
        # add to queue
        self.toserverqueue.put(o)
        
        # send now, if appropriate
        if self.buffer_tx==False:
           self.periodicTimer.fireNow()
    
    def getStatus(self):
        returnVal = {}
        with self.dataLock:
            returnVal['connectionmode']          = 'http_polling'
            returnVal['is_connected']            = self.is_connected
            returnVal['lastheard_ts']            = self.lastheard_ts
            if self.lastheard_ts:
                returnVal['lastheard_since']     = time.time()-self.lastheard_ts
            returnVal['toserverqueue_fill']      = self.toserverqueue.qsize()
        return returnVal
    
    # ======================= private =========================================
    
    def _poll_server(self, o=None):
        '''
        Send one HTTP POST request to server to
        (1) send the elements from toserverqueue to the server
        (2) receive the objects from the server and rearm.
        '''
        # send objects
        try:
            # create HTTP body
            body = {
                'id':      self.id,
                'token':   self.token,
                'ttl':     self.polling_period+3,
            }
            # objects
            o = []
            while True:
                try:
                    e = self.toserverqueue.get(block=False)
                except Queue.Empty:
                    break
                else:
                    o += [e]
            if o:
                body['o'] = o
            
            # send to server
            r = requests.post(
                self.server_url,
                json = body,
            ).json()
            r = convertToString(r)
        except requests.exceptions.ConnectionError as err:
            self._set_is_connected(False)
            logger.error(err)
        except Exception as err:
            self._set_is_connected(False)
            logger.error(err)
        else:
            self._set_is_connected(True)
            if r['o']:
                self.from_server_cb(r['o'])
    
    def _set_is_connected(self,newstate):
        with self.dataLock:
            self.is_connected      = newstate
            if self.is_connected:
                self.lastheard_ts  = time.time()

class DuplexClientWs(DuplexClient):
    def __init__(self, kwargs):
        raise NotImplementedError()

# =========================== main ============================================

class CliDuplexClient(object):

    def __init__(self):

        # create server
        self.duplexClient = DuplexClient.from_url(
            server_url       = 'http://api-dev.solsystem.io/api/v1/o.json',
            id               = 'testmanager',
            token            = '{"org":"lmayz4","token":"255L*XFQX?8ETDyBVs"}',
            polling_period   = 5,
            buffer_tx        = True,
            from_server_cb   = self.from_server_cb,
        )
        '''
        self.duplexClient = DuplexClient.from_url(
            server_url       = 'ws://127.0.0.1:8080/api/v1/ws',
            id               = id,
            token            = 'mytoken',
            from_server_cb   = self.from_server_cb,
        )
        '''
        
        # cli
        self.cli                  = DustCli.DustCli(
            'CliDuplexClient',
            self._clihandle_quit,
        )
        self.cli.registerCommand(
            name                  = 'tx',
            alias                 = 'tx',
            description           = 'transmit to server',
            params                = ['msg'],
            callback              = self._clihandle_tx,
        )
        self.cli.registerCommand(
            name                  = 'status',
            alias                 = 'u',
            description           = 'check status',
            params                = [],
            callback              = self._clihandle_status,
        )

    def _clihandle_tx(self, params):
        msg = params[0]
        self.duplexClient.to_server([{'msg': msg}])
    
    def _clihandle_status(self, params):
        pp.pprint(self.duplexClient.getStatus())
    
    def from_server_cb(self, o):
        print 'from server: {0}'.format(o)

    def _clihandle_quit(self):
        time.sleep(.3)
        print "bye bye."
        sys.exit(0)

def main():
    client = CliDuplexClient()

if __name__ == "__main__":
    import random
    import string
    import DustCli
    import pprint
    pp = pprint.PrettyPrinter(indent=4)
    main()
