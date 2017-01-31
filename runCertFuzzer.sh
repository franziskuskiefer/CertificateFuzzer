#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR
# export LD_LIBRARY_PATH=$DIR/Libraries/Botan-1.11.19/


MAX_CERTS=0
SIGN_CERTS=true
CREATE_TEST_CERT=false
SET_COMMONNAME="localhost"
SEED=12345

for i in $@; do
	IFS='=' read -ra arr <<< $i

	if [[ ${arr[0]} == "max_certs" ]] ; then
		MAX_CERTS=${arr[1]}
	fi

	if [[ ${arr[0]} == "sign" ]] ; then
		SIGN_CERTS=${arr[1]}

	fi

	if [[ ${arr[0]} == "create_test" ]] ; then
		CREATE_TEST_CERT=${arr[1]}

	fi

	if [[ ${arr[0]} == "base_cert" ]] ; then
		BASE_CERT=${arr[1]}

	fi

	if [[ ${arr[0]} == "set_common_name" ]] ; then
		SET_COMMONNAME=${arr[1]}

	fi

	if [[ ${arr[0]} == "seed" ]] ; then
		SEED=${arr[1]}

	fi
	
	#for j in "${arr[@]}"; do
		
	#done

done


cd build/
ulimit -s 81920
./CertFuzzer $BASE_CERT $MAX_CERTS $SIGN_CERTS $CREATE_TEST_CERT $SET_COMMONNAME $SEED
