#!/usr/bin/env bash

rm -rf /Results/ISLA
mkdir /Results/ISLA


echo "starting at $(date)"  >> /Results/isla.log.txt

for i in $(seq 1 $1);
do
	echo "Creating Set: $i"
	mkdir -p "/Results/ISLA/set$i"
	isla -O fuzz -n 1000 -f 1000 -s 1000 -d /Results/ISLA/set$i 'python3 fuzz_goat.py {}' pkcs.bnf pkcs-cons.isla
	echo "Finished Set: $i"
done
echo "finished at $(date)"  >> /Results/isla.log.txt
echo "Fixing permissions"
echo "HOST UID = ${HOST_UID}"
echo "HOST GID = ${HOST_GID}"
chown -R $HOST_UID:$HOST_GID /Results/
chmod -R 777 /Results/

# cat results/*_stdout.txt
