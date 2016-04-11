#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
. ${DIR}/autossh.conf.sh

NLINES=`ps aux | grep "$TUNNEL" | wc -l`

if [ $NLINES -eq 1 ]
then
       ssh -NTR ${TUNNEL} -p ${REMOTEPORT} ${REMOTEUSER}@${REMOTEHOST}
fi
exit 0

