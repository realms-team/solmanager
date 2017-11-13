from connector import Connector
import threading
import logging
import json
import time

import websocket

logger = logging.getLogger(__name__)


class ConnectorWebsocket(Connector):

    def _start(self):
        # start websocket connection
        self.is_running = False
        self.websocket_thread = threading.Thread(target=self._connect)
        self.websocket_thread.daemon = True
        self.websocket_thread.start()

        # start pubthread
        if self.pubrate_min != 0:
            # start pubthread
            self.publish_thread = threading.Thread(target=self._publish_task, name="ConnectorWebsocket_pubtask")
            self.publish_thread.daemon = True
            self.publish_thread.start()

        # todo check if token is present

    def subscribe(self, cb, topic="None"):
        """
        Subscribe to messages on a given topic

        :type topic: basestring
        :param topic: the topic to subscribe to (a keyword)
        :type cb: function
        :param cb: callback function to call when receiving message with that topic
        """
        self.cb = cb

    def publish(self, msg, topic=None):
        """
        Publish a message
        :type msg: dict
        :param msg: the message to send
        :type topic: sting
        :param topic: the topic to send to
        """
        self.publish_queue.append((msg, topic))

    def _publish_now(self, msg, topic=None):
        logger.debug("Sending message: {0}".format(msg))
        try:
            self.ws.send(json.dumps(msg))
        except Exception as err:
            logger.warning("Cannot send: {0}".format(err))
        else:
            return True

    def _publish_task(self):

        # publish and remove from queue on success
        with self.queue_lock:
            self.publish_queue = [x for x in self.publish_queue if not self._publish_now(*x)]

        # restart after pubrate_min
        threading.Timer(self.pubrate_min * 60, self._publish_task).start()

    def _connect(self):
        while 1:
            if self.is_running is False:
                websocket_endpoint = "{0}/api/v2/command.json".format(self.url, self.auth["id"])
                try:
                    self.ws = websocket.WebSocketApp(websocket_endpoint,
                                                     on_message=self._on_message,
                                                     on_error=self._on_error,
                                                     on_close=self._on_close,
                                                     on_open=self._on_open,
                                                     header={
                                                         'X-SOLSYSTEM-Token': self.auth["token"],
                                                         'X-SOLSYSTEM-Id': self.auth["id"]}
                                                     )
                except Exception as err:
                    logger.error("Cannot create Websocket connection with {0}: {1}".format(websocket_endpoint, err))
                else:
                    logger.info("Connection established with {0}".format(websocket_endpoint))
                    wst = threading.Thread(target=self.ws.run_forever)
                    wst.daemon = True
                    wst.start()
                    self.is_running = True
            else:
                time.sleep(10)


    def _on_open(self, ws):
        logger.info("Websocket opened")

    def _on_close(self, ws):
        logger.info("Websocket closed")
        self.is_running = False

    def _on_error(self, ws, error):
        logger.error("{0}".format(error))

    def _on_message(self, ws, message):
        if self.cb is not None:
            self.cb(json.loads(message))
        else:
            logger.warn("No callback function defined")
