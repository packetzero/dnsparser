#!/bin/sh
TOP=$PWD
PLATFORM=`uname -s`-`uname -m`			# e.g. Darwin-x86_64 , Linux-x86_64

# jenkins should be settings this appropriately
if [ "$CONFIG" == "" ] ; then
  CONFIG=Release
fi

cd platform/$PLATFORM

BINDIR=./bin

if [ `uname -s` == "Darwin" ] ; then
  BINDIR+=/${CONFIG}
fi

$BINDIR/libdnsparser-tests

