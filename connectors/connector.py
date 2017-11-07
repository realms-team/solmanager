from furl import furl
from solobjectlib import Sol
import connectors
import threading


def create(config_dict):
    auth = connectors.connector.get_auth_dict(config_dict)
    furl_obj = furl(config_dict["url"])
    proto = furl_obj.scheme
    if proto == "https":
        return connectors.connector_https.ConnectorHttps(config_dict["url"], auth)
    elif proto == "file":
        return connectors.connector_file.ConnectorFile(config_dict["url"], auth)
    else:
        raise NotImplementedError


def get_auth_dict(config_dict):
    auth_dict = {}
    for key, value in config_dict.iteritems():
        if "auth_" in key:
            auth_dict[key[len("auth_"):]] = value
    return auth_dict


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
        self.url = url
        self.host = furl_obj.host
        self.port = furl_obj.port
        self.proto = furl_obj.scheme

        self.pubrate_min = pubrate_min
        self.subrate_min = subrate_min

        self.auth = auth

        self.publish_queue = []  # tuple list to store message to send

        self.sol = Sol.Sol()

        self.dataLock = threading.RLock()

        self._start()

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

    @staticmethod
    def _handle_command(command):
        if command.data["command"] == "snapshot":
            # TODO send POST to solmanager API
            pass
