#!/bin/sh
echo ">insmod with patch"
module=$1

par1=`echo $@ | awk '{print $1}'`
add_params=${@#*$par1}

if [ -f ${module} ];then
    tmp_ver=`mktemp`
    tmp_mod=`mktemp`

    version=`uname -r`

    echo "$version" > $tmp_ver
    echo "<`cat $tmp_ver`>"
    echo "./bin/patchko.sh -p <$module> <$tmp_mod> <$tmp_ver>"
    ./bin/patchko.sh -p $module $tmp_mod $tmp_ver
    chmod 644 $tmp_mod
    echo "insmod $tmp_mod $add_params"
    insmod $tmp_mod $add_params
    rm $tmp_mod
    rm $tmp_ver
fi
