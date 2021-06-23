#!/bin/bash

if [ -e process.txt ]
then
	rm process.txt
fi

ps ax | grep httpclass.py | awk '{print $1}' >> process.txt
if [ -e process.txt ]
then
	python3 stop.py process.txt
fi
