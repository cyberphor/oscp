#!/bin/bash

# exit script if not running as root or sudo
if [ $(id -u) != 0 ]; then
    echo "This script requires administrative privileges."
    exit 1
fi

# make the 'bootstraps' directory if it does not exist
BOOTSTRAP_DIR="/usr/local/bin/bootstraps"
if [ ! -d $BOOTSTRAP_DIR ] ; then
    mkdir $BOOTSTRAP_DIR
fi

# copy all 'bootstraps' to the 'bootstraps' directory
# and allow root/sudo to execute them
BOOTSTRAPS=(
    "bootstraps/bytearray.py"
    "bootstraps/katz2crack.py"
    "bootstraps/new-ctf.sh"
    "bootstraps/save-screenshots-here.py"
    "bootstraps/print-open-ports-from-nmap-scan.py"
) 
for BOOTSTRAP in ${BOOTSTRAPS[@]}; do
    if [ -f $BOOTSTRAP ]; then
        chmod ug+x $BOOTSTRAP
        cp -p $BOOTSTRAP $BOOTSTRAP_DIR
    fi
done

# update the PATH environment variable
# if it does not already include the 'bootstraps' directory
if ! grep -q "/usr/local/bin/bootstraps" /etc/environment; then
    sed -i 's/$/\:\/usr\/local\/bin\/bootstraps/g' /etc/environment
    source /etc/environment
fi