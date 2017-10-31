import paho.mqtt.client as mqtt
from connector import Connector
import json

SUBSCRIBE_TIMEOUT = 10

class ConnectorMqtt(Connector):

    def subscribe(self, topic, cb):
        """
        Subscribe to messages on a given topic

        :type topic: basestring
        :param topic: the topic to subscribe to (a keyword)
        :type cb: function
        :param cb: callback function to call when receiving message with that topic
        """
        if not self.connected:
            self._connect()

        self.client.subscribe(topic=topic)
        self.client.message_callback_add(sub=topic, callback=cb)

    def publish(self, msg, topic=None):
        """
        Publish a message
        :type msg: dict
        :param msg: the message to send
        :type topic: sting
        :param topic: the topic to send to
        """
        self.client.publish(topic=topic, payload=json.dumps(msg))

    def _connect(self):
        self.client = mqtt.Client()
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

        self.client.connect(self.host, self.port, SUBSCRIBE_TIMEOUT)
        self.connected = True

    def _on_connect(client, userdata, flags, rc):
        """
        The callback for when the client receives a CONNACK response from the server.
        :param userdata:
        :param flags:
        :param rc:
        :return:
        """
        print("Connected with result code " + str(rc))

        # Subscribing in on_connect() means that if we lose the connection and
        # reconnect then subscriptions will be renewed.
        # client.subscribe("$SYS/#")

    # The callback for when a PUBLISH message is received from the server.
    def _on_message(client, userdata, msg):
        print(msg.topic + " " + str(msg.payload))

