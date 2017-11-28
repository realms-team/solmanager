import pytest
from connectors import connector_https
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

TOPIC = "o.json"

# =========================== fixtures ========================================


@pytest.fixture
def config():
    return {
        "url": "https://localhost:8082",
        "auth": {
            "token": 'SOLSERVER_TOKEN_LOCAL',
            "cert": "../solserver.cert"
        }
    }

# =========================== test ============================================


def test_connector_https(config):
    cb_subscribe = mock.Mock()

    https_connector = connector_https.ConnectorHttps(config["url"], config["auth"])

    # subscribe
    https_connector.subscribe(cb_subscribe, TOPIC)

    # publish
    https_connector.publish(SOL_OBJ, TOPIC)

    # test that the cb was called with the correct arguments
    #cb_subscribe.assert_called_with(message=SOL_OBJ)

