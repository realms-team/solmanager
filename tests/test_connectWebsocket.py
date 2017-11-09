import pytest
from connectors import connector_websocket
import mock

SOL_OBJ =   {
    "timestamp"  : 11111111,
    "mac"        : '01-02-03-04-05-06-07-08',
    "type"       : 0x40,
    "value"      : {
        "temp_raw"       : 0x6387,
        "rh_raw"         : 0x9d27,
        "id"             : 3,
    },
 }

TOPIC = "solserver-topic-test"

# =========================== fixtures ========================================


@pytest.fixture
def config():
    return {
        "url": "ws://localhost",
        "auth": { "id": '01-02-03-04-05-06-07-08' }
    }

# =========================== test ============================================


def test_connector_mqtt(config):
    cb_subscribe = mock.Mock()

    ws_connector = connector_websocket.ConnectorWebsocket(config["url"], config["auth"])

    # subscribe
    ws_connector.subscribe(TOPIC, cb_subscribe)

    # publish
    ws_connector.publish(SOL_OBJ, TOPIC)

    # test that the cb was called with the correct arguments
    #cb_subscribe.assert_called_with(message=SOL_OBJ)

