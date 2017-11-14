from connector import Connector
import requests
import threading
import logging

logger = logging.getLogger(__name__)

HTTP_CHUNK_SIZE = 10  # send batches of 10 Sol objects


class ConnectorHttps(Connector):

    def _start(self):
        if self.pubrate_min != 0:
            # start pubthread
            self.publish_thread = threading.Thread(target=self._publish_task, name="ConnectorHttps")
            self.publish_thread.daemon = True
            self.publish_thread.start()

    def subscribe(self, cb, topic=None):
        """
        Subscribe to messages on a given topic

        :param basestring topic: the topic to subscribe to (a keyword)
        :param function cb: callback function to call when receiving message with that topic
        """
        # start pubthread
        self.subscribe_thread = threading.Thread(target=self._subscribe_task, args=[cb])
        self.subscribe_thread.daemon = True
        self.subscribe_thread.start()

    def publish(self, msg, topic=None):
        """
        Publish a message
        :param dict msg: the message to send
        :param string topic: the topic to send to
        """
        sol_bin = self.sol.json_to_bin(msg)

        # if pubrate_min == 0, send now
        if self.pubrate_min == 0:
            sol_http = self.sol.bin_to_http([sol_bin])
            self._publish_now(sol_http)

        # else, add message to queue
        else:
            self.publish_queue.append(sol_bin)

    def _publish_now(self, msg, topic=None):
        return_val = False
        try:
            # send message to server
            url = '{0}://{1}:{2}/api/v2/o.json'.format(self.proto, self.host, self.port)
            logger.debug("Publishing now to {0}".format(url))
            requests.packages.urllib3.disable_warnings()
            r = requests.put(
                url     = url,
                headers = {'X-SOLSYSTEM-Token': self.auth["token"],
                           'X-SOLSYSTEM-Id': self.auth["id"],
                           'X-SOLSYSTEM-OrgId': self.auth["org_id"],
                           },
                json    = msg,
                verify  = self.auth["cert"],
            )
        except requests.exceptions.RequestException as err:
            # happens when could not contact server
            logger.warning("Error when sending http payload: %s", err)
        else:
            # server answered
            if r.status_code != requests.codes.ok:
                logger.warning("Error HTTP response status: " + str(r.text))
            else:
                return_val = True
        return return_val

    def _publish_task(self):
        with self.queue_lock:
            # split publish list into chunks
            http_payload = []
            for i in xrange(0, len(self.publish_queue), HTTP_CHUNK_SIZE):
                chunk = self.publish_queue[i: i + HTTP_CHUNK_SIZE]
                http_payload.append(self.sol.bin_to_http(chunk))

            # publish chunks
            for chunk in http_payload:
                if self._publish_now(chunk) is True:
                    self.publish_queue = self.publish_queue[HTTP_CHUNK_SIZE:]

        # restart after pubrate_min
        threading.Timer(self.pubrate_min * 60, self._publish_task).start()

    def _subscribe_task(self, cb, topic="command.json"):
        # poll host for commands
        try:
            url = '{0}://{1}:{2}/api/v2/{3}'.format(self.proto, self.host, self.port, topic)
            logger.debug("Subscribing to {0}".format(url))
            r = requests.get(
                url=url,
                headers={'X-SOLSYSTEM-Token': self.auth["token"],
                         'X-SOLSYSTEM-Id': self.auth["id"],
                         'X-SOLSYSTEM-OrgId': self.auth["org_id"],
                         },
                verify=self.auth["cert"],
            )
        except requests.exceptions.RequestException as err:
            # happens when could not contact server
            logger.warning("Error when sending http payload: %s", err)
        else:  # server answered
            # clear objects
            if r.status_code == 200:
                # update stats
                for item in r.json():
                    cb(item['command'])
            else:
                # update stats
                logger.warning("Error HTTP response status: " + str(r.text))

        # restart after subrate_min
        threading.Timer(self.subrate_min * 60, self._subscribe_task, [cb, topic]).start()