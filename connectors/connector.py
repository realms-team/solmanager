from furl import furl
import threading


class Connector(object):

    def __init__(self, url, auth=None, pubrate_min=0, subrate_min=0):
        """
        Initialize the connector instance and set the config

        :param url: a URL formatted endpoint
        :param auth: a dictionary of auth fields
        :param pubrate_min: the publication rate
        :param subrate_min: the subscription rate
        """
        self.connected = False

        furl_obj = furl(url)
        self.host = furl_obj.host
        self.port = furl_obj.port
        self.port = furl_obj.port
        self.proto = furl_obj.scheme

        self.pubrate_min = pubrate_min
        self.subrate_min = subrate_min

        self.auth = auth

        self.publish_queue = []  # tuple list to store message to send

        if self.pubrate_min != 0:
            self._publish_task()  # start the publishing task

    def subscribe(self, topic, cb):
        """
        Subscribe to messages on a given topic

        :type topic: basestring
        :param topic: the topic to subscribe to (a keyword)
        :type cb: function
        :param cb: callback function to call when receiving message with that topic
        """
        pass

    def publish(self, msg, topic=None):
        """
        Publish a message
        :type msg: dict
        :param msg: the message to send
        :type topic: sting
        :param topic: the topic to send to
        """
        pass

    def _publish_task(self):
        threading.Timer(self.pubrate_min*60, self._publish_task).start()

