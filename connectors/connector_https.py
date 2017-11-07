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
            self._publish_task()

    def subscribe(self, topic, cb):
        """
        Subscribe to messages on a given topic

        :type topic: basestring
        :param topic: the topic to subscribe to (a keyword)
        :type cb: function
        :param cb: callback function to call when receiving message with that topic
        """
        self._subscribe_task(topic)

    def publish(self, msg, topic=None):
        """
        Publish a message
        :type msg: dict
        :param msg: the message to send
        :type topic: sting
        :param topic: the topic to send to
        """

        # if pubrate_min == 0, send now
        if self.pubrate_min == 0:
            self._publish_now(msg, topic)

        # else, add message to queue
        else:
            self.publish_queue.append((msg, topic))

    def _publish_now(self, msg, topic=None):
        sol_bin = self.sol.json_to_bin(msg)
        sol_http = self.sol.bin_to_http([sol_bin])
        try:
            # send message to server
            url = '{0}://{1}:{2}/api/v1/{3}'.format(self.proto, self.host, self.port, topic)
            logger.debug("Publishing now to {0}".format(url))
            requests.packages.urllib3.disable_warnings()
            r = requests.put(
                url     = url,
                headers = {'X-REALMS-Token': self.auth["token"]},
                json    = sol_http,
                verify  = self.auth["cert"],
            )
        except requests.exceptions.RequestException as err:
            # happens when could not contact server
            logger.warning("Error when sending http payload: %s", err)
        else:
            # server answered
            if r.status_code != requests.codes.ok:
                logger.warning("Error HTTP response status: " + str(r.text))

    def _publish_task(self):
        # split publish list into chunks
        http_payload = []
        for i in xrange(0, len(self.publish_queue), HTTP_CHUNK_SIZE):
            chunk = self.publish_queue[i: i + HTTP_CHUNK_SIZE]
            http_payload.append(self.sol.bin_to_http(chunk))

        # publish chunks
        for payload in http_payload:
            self._publish_now(*payload)

        # restart after pubrate_min
        threading.Timer(self.pubrate_min * 60, self._publish_task).start()

    def _subscribe_task(self, topic):
        # poll host for commands
        try:
            url = '{0}://{1}:{2}/api/v1/{3}/'.format(self.proto, self.host, self.port, topic)
            logger.debug("Subscribing to {0}".format(url))
            r = requests.get(
                url=url,
                headers={'X-REALMS-Token': self.auth["token"]},
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
                    self._handle_command(item['command'])
            else:
                # update stats
                logger.warning("Error HTTP response status: " + str(r.text))

        # restart after subrate_min
        threading.Timer(self.subrate_min * 60, self._subscribe_task, [topic]).start()