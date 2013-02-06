#!/bin/sh
opt=$1
patch_file=$2
output_file=$3
data_file=$4

objdump=$3
readelf=$4

howto()
{
    echo " $0 -r <patchingfile.ko> <readelf> <objdump>"
    echo " $0 -g <patchingfile.ko> <readelf> <objdump>"
    echo " $0 -p <patchingfile.ko> <outputfile.ko> <patchdata>"
}

DEBUG_OFF=1

debug(){
    if [ $DEBUG_OFF -eq 0 ];then
       echo "patchko.sh) $1"
    fi
}

debugmk(){
    echo "patchko.sh) $1"
}

error(){
    debugmk "[Err]$1"
}

#toolchain=~/Work/tools/u1_slp/toolchai
#cross=${toolchain}/bin/arm-none-linux-gnueabi-
#cross=arm-none-linux-gnueabi-

sect_name="modinfo"
varname="vermagic"
debug "patchfile <$patch_file>"

if [ -f "$patch_file" ]; then

    if [ "$opt" = "-p" ];then
    #set version (use only on target)
        debug "Set version (patching) to <$patch_file>"
        if [ -f "$data_file" ];then
            cp -f "${patch_file}" "${output_file}"

            #get patching adderes
            pos=$((`cat $patch_file.addr | awk '{print \$1}'`))
            abs_len=$((`cat $patch_file.addr | awk '{print \$2}'`))

            key_before=`dd if="$patch_file" bs=1 skip=${pos}c count=${abs_len}c 2>/dev/null`
            debug "key_before<$key_before>"
            key_before_tail=${key_before#*\ }
            debug "key_before_tail<$key_before_tail>"
            echo -ne "`cat $data_file` $key_before_tail\000">$data_file

            key_len="`cat $data_file`"
            key_len=$((${#key_len}+1))

            debug "POS>$pos<"
            debug "OLDLEN>$abs_len<"
            debug "NEWLEN>$key_len<"
            debug "PATCH_TO>`cat $data_file`<"

            debug "key_len=$key_len"
            if [ $key_len -le ${abs_len} ];then
                debug "before=<$key_before>"
                res=`dd if="${data_file}" of="${output_file}" bs=1 seek=${pos} skip=0c count=${key_len}c conv=notrunc 2>/dev/null`

                res=`dd if="$output_file" bs=1 skip=${pos}c count=${abs_len}c 2>/dev/null`
                debug "patched=<$res>"
            else
                error "Error on patching <${patch_file}>:data file <$data_file> NEW KEY TOO LONG"
                error "CHECK YOUR KERNEL USED ON COMPILE SWAP IF YOU READ IT"
                exit 254
            fi
        else
            error "Error on patching <${patch_file}>:data file <$data_file> not found"
            exit 255
        fi
    else
    #if[ "$opt" != "-p" ];then
        debug "+not p"

        $readelf -v
        if [ $? -ne 0 ];then
            error "readelf not found on path <$readelf>"
            exit 2
        fi
        $objdump -v
        if [ $? -ne 0 ];then
            error "objdump not found on path <$objdump>"
            exit 1
        fi

        file_size=$((`ls -la "$patch_file" | awk '{print \$5}'`))
        debugmk "file_size=$file_size"

        section=`$readelf -e $patch_file | grep ${sect_name}`
        section=${section##*${sect_name}}
        debugmk "section=$section"

        addr=$((0x`echo $section | awk '{print $2}'`))
        offs=$((0x`echo $section | awk '{print $3}'`))
        size=$((0x`echo $section | awk '{print $4}'`))
        debugmk $addr:$offs:$size

        abs_len=$((0x`$objdump -t -j .${sect_name} "$patch_file" | grep _${varname} | awk '{print $5}'`))
        abs_len=$(($abs_len-${#varname}-1))
        sect_off=$((0x`$objdump -t -j .${sect_name} "$patch_file" | grep _${varname} | awk '{print $1}'`))
        add_off=$((${#varname}+1))

        abs_addr=$((${addr}+${offs}+${sect_off}+${add_off}))
        debugmk "abs_addr=$abs_addr;"
        debugmk "abs_len=$abs_len"
        if [ "$opt" = "-r" ];then
        #read version (for patch testing)
            debugmk "Read version in <$patch_file>"
            res=`dd if="$patch_file" bs=1 skip=${abs_addr}c count=${abs_len}c 2>/dev/null`
            debugmk "ver<$res>"
        elif [ "$opt" = "-g" ];then
        #gen file version (use only on host)
            debugmk "Generate version data for <$patch_file>"
            #res=`dd if="$patch_file" of="$patch_file.addr" bs=1 skip=${abs_addr}c count=${abs_len}c`
            if [ "$abs_addr" = "" ];then
                debugmk "ERROR cannot get absolute addres of module info line for patching"
                exit 253
            elif [ "$abs_len" = "" ];then
                debugmk "ERROR cannot get length of module info line for patching"
                exit 252
            else
                echo "$abs_addr $abs_len">"$patch_file.addr"
            fi
            debugmk "patch_addr=`cat $patch_file.addr`"
        else
            error "Wrong param <$opt>"
        fi
    fi
else
    error "file for patchig not found <$patch_file>"
    fi
