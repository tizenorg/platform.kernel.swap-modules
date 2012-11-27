#!/bin/sh

module=$1

DEBUG_OFF=1

debug(){
    if [ $DEBUG_OFF -eq 0 ];then
       echo $1
    fi
}

debug ">insmod with patch"

par1=`echo $@ | awk '{print $1}'`
add_params=${@#*$par1}

if [ -f ${module} ];then
    tmp_ver=`mktemp`
    tmp_mod=`mktemp`

    version=`uname -r`

    echo "$version" > $tmp_ver
    debug "<`cat $tmp_ver`>"
    debug "./bin/patchko.sh -p <$module> <$tmp_mod> <$tmp_ver>"
    ./bin/patchko.sh -p $module $tmp_mod $tmp_ver
    chmod 644 $tmp_mod
    debug "insmod $tmp_mod $add_params"
    insmod $tmp_mod $add_params
    rm $tmp_mod
    rm $tmp_ver
fi
