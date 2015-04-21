#!/bin/bash

TYPE=$1
NAME=$2
STATE=$3

SERVICES="dnsmasq"

case $STATE in
	"MASTER") 
		for SVC in ${SERVICES}; do
			/usr/sbin/service ${SVC} start
        done
		exit 0
        ;;
	"BACKUP") 
		for SVC in ${SERVICES}; do
			/usr/sbin/service ${SVC} stop
        done
		exit 0
        ;;
	"FAULT")  
		for SVC in ${SERVICES}; do
			/usr/sbin/service ${SVC} stop
        done
        exit 0
        ;;
	*)
		echo "unknown state -- ${STATE}"
        exit 1
        ;;
esac
