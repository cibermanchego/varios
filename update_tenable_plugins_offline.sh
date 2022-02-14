#!/usr/bin/sh

# Download plugins from Tenable site

curl https://plugins.nessus.org/v2/nessus.php?f=all-2.0.tar.gz&u=3f09asdf0934… -o /data_diode/plugins/all-2.0.tar.gz

sleep 3

curl https://plugins.nessus.org/v2/nessus.php?f=SecurityCenterFeed48.tar.gz&u=3f09assdf90rg… -o /data_diode/plugins/SecurityCenterFeed48.tar.gz

sleep 3

curl https://plugins.nessus.org/v2/nessus.php?f=sc-plugins-diff.tar.gz&u=3f09assdf90rg… -o /data_diode/plugins/sc-plugins-diff.tar.gz
# Download plugins from your web repository to Tenable.sc server
curl http://www.repoplace.local/plugins/all-2.0.tar.gz -o /plugins/all-2.0.tar.gz

sleep 3

curl http://www.repoplace.local/plugins/SecurityCenterFeed48.tar.gz -o /plugins/SecurityCenterFeed48.tar.gz

sleep 3

curl http://www.repoplace.local/plugins/sc-plugins-diff.tar.gz -o /plugins/sc-plugins-diff.tar.gz


#Load plugins to Tenable.sc system

#Run as root

/bin/su -c "/opt/sc/support/bin/php /opt/sc/src/tools/pluginUpdate.php /tmp/sc-plugins-diff.tar.gz " - tns

/bin/su -c "/opt/sc/support/bin/php /opt/sc/src/tools/pluginUpdate.php /tmp/SecurityCenterFeed48.tar.gz " - tns


# This is a script to copy plugins Nessus scanners and then load them

# There are 2 variables accepted via commandline

# $1 = first parameter (/source_path/source_filename)

# $2 = second parameter (file that contains list of hosts)

SOURCEFILE=$1

HOSTFILE=$2

if [ -f $SOURCEFILE ]
then
    printf "File found, preparing to transfer\n"
    while read server
    do
        scp -p $SOURCEFILE ${server}:
        ssh -t ${server} "sudo /home/admin/update_scanner.sh"
    done < $HOSTFILE
else
    printf "File \"$SOURCEFILE\" not found\n"
    exit 0
fi
exit 0

# Contents of update_scanner.sh
# /opt/nessus/sbin/nessuscli update /home/admin/all-2.0.tar.gz
