#!/bin/bash

HOST=$1
PORT=$2
DATABASE=$3
USERNAME=$4

psql -h $HOST -p $PORT -U $USERNAME -d $DATABASE -c 'create schema if not exists admin'

while read filename; do
	echo "Running $filename"
	psql -h $HOST -p $PORT -U $USERNAME -d $DATABASE -f $filename
done <views.list
