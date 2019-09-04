#!/bin/bash 

for c in `seq 2 6`
do
    for size in `seq 2 3`
    do
        for mode in `seq 1 2`
        do
            for i in `seq 0 99`
            do
                rm -rf ./test-client 
                ./leath_rpc_client -b `expr $size \* 1024` -n $c -i $mode
            done
        done 
    done 
done