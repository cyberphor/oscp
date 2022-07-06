#!/bin/bash

# exit script if not running as root or sudo
if [ $(id -u) != 0 ]; then
    echo "This script requires administrative privileges."
    exit 1
fi

# delete the 'bootstraps' directory if it exists
if [ -d "/usr/local/bin/bootstraps" ]; then
    rm -rf "/usr/local/bin/bootstraps"
fi

# update path if 'bootstraps' directory is in it
if $(grep -q "/usr/local/bin/bootstraps" /etc/environment); then
    sed -i "s/\:\/usr\/local\/bin\/bootstraps//g" /etc/environment
    source /etc/environment
fi