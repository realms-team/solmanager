| Master branch  | Develop branch |
| -------------- | -------------- |
| [![Code Health](https://landscape.io/github/realms-team/solmanager/master/landscape.svg?style=flat)](https://landscape.io/github/realms-team/solmanager/master) | [![Code Health](https://landscape.io/github/realms-team/solmanager/develop/landscape.svg?style=flat)](https://landscape.io/github/realms-team/solmanager/develop) |

This repo contains the software to run on the manager. It:
* connects to the SmartMesh IP manager
* formats received data/notifications as sensors objects
* stores objects locally
* syncs locally-stored objects with the SolApi

# Installing and Running

* download the latest release: https://github.com/realms-team/solmanager/releases
* add your MQTT credentials into the `solmanager.config` file
* double-click/run on `solmanager.py` to start the manager

```

                         +-----+SolManager-----+                +-------------+
+-------------+          |                     +--------------> |   SolApi    |
| SmartMeshIP |          |   +-------------+   |     HTTP:443   +-------------+
|   Manager   +<------------>+ JsonManager |   |
|             | API port |   +-------------+   |
+-------------+          |                     |
                         +---------------------+

```

## Configuration

* Create a copy of `solmanager.config.sample`, name it `solmanager.config`
* Modify the configuration fields as you see fit for your deployment

## Supervisor

For the solmanager to restart automatically in Linux:
* Install supervisor: ```sudo apt-get install supervisor```
* Place the supervisor configuration: ```sudo cp supervisord.conf.sample /etc/supervisor/conf.d/solmanager.conf```
* In that configuration file, replace #SOL_MANAGER_PATH by the path where the `solmanager/` directory is
* Restart supervisor service: `sudo service supervisor restart`
