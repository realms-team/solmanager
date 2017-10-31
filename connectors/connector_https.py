from connector import Connector
import requests
import warnings


class ConnectorHttps(Connector):

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
        # send http_payload to server
        try:
            # update stats
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