#!/bin/bash
./fcbuilder.sh
if [ $? -ne 0 ]; then
	echo "BUILD FAILED"
	exit 1
fi
./fcrunner.sh

echo "Fixing permissions"
echo "HOST UID = ${HOST_UID}"
echo "HOST GID = ${HOST_GID}"
chown -R $HOST_UID:$HOST_GID /Results/
chmod -R 777 /Results/