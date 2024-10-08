#!/bin/bash

mkdir ./traces

for cell in {1..100}
do
	mkdir ./traces/cell$cell
done


for i in {1..100}
do
	for cell in {1..100}
	do
		tcpdump port 9050 --interface lo -w ./traces/cell$cell/iteration$i &
		python3 client.py grid $cell -T restaurant -t
		kill $!
	done
done
