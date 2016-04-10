#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
. ${DIR}/autossh.conf.sh

ssh -NTR ${TUNNEL} -p ${REMOTEPORT} ${REMOTEUSER}@${REMOTEHOST}
