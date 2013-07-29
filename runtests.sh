#!/bin/bash

checkok ()
{
    if [ $? -ne 0 ]; then
        echo "Compile ERROR!"
        exit -1
    fi
}

g++ -m32 -g *.cpp -o v
checkok
./v

g++ -m64 -g *.cpp -o v
checkok
./v

g++ -m32 -O3 *.cpp -o v
checkok
./v

g++ -m64 -O3 *.cpp -o v
checkok
./v

icc -O3 -axPT -ipo *.cpp -o v
checkok
./v
