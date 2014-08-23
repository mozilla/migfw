#!/bin/sh
# System command to build the code

echo " -- MIGFW OS X Code builder -- "
echo " -- Enter \"run\" to build and run, anything else to just build "
read opt
g++ main.cpp -o migfwObj -DDEBUG
echo "Source code main.cpp built to \"migfwObj\""

if [ "$opt" == "run" ]; then
	echo "Running obj in terminal"
	./migfwObj
fi