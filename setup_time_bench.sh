#!/bin/bash 

size=2048
mode=1

for i in `seq 0 100`
do 
    rm -rf ./test-client 
    ./leath_rpc_client -b $size -i $mode
done