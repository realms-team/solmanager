from connector import Connector
import requests
import warnings
import threading

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
        raise NotImplementedError

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
        try:
            # send message to server
            r = requests.put(
                '{0}://{1}:{2}/api/v2/o.json'.format(self.proto, self.host, self.port),
                headers = {'X-REALMS-Token': self.auth["token"]},
                json    = msg,
                verify  = self.auth["cert"],
            )
        except (requests.exceptions.RequestException) as err:
            # happens when could not contact server
            warnings.warn("Error when sending http payload: %s", err)
        else:
            # server answered
            if r.status_code != requests.codes.ok:
                warnings.warn("Error HTTP response status: " + str(r.text))

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

    def _subscribe_task(self):
        # poll host for commands
        try:
            r = requests.get(
                '{0}://{1}:{2}/api/v2/getcommands/'.format(self.proto, self.host, self.port),
                headers={'X-REALMS-Token': self.auth["token"]},
                verify=self.auth["cert"],
            )
        except (requests.exceptions.RequestException) as err:
            # happens when could not contact server
            warnings.warn("Error when sending http payload: %s", err)
        else:  # server answered
            # clear objects
            if r.status_code == 200:
                # update stats
                for item in r.json():
                    self._handle_command(item['command'])
            else:
                # update stats
                warnings.warn("Error HTTP response status: " + str(r.text))

        # restart after subrate_min
        threading.Timer(self.subrate_min * 60, self._subscribe_task).start()