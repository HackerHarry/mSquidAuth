#!/usr/bin/env bash

# multiple Squid basic auth checks
# Harry Basalamah 12/2021
#
# credits
# https://stackoverflow.com/questions/24147067/verify-user-and-password-against-a-file-created-by-htpasswd/40131483
# https://stackoverflow.com/questions/38710483/how-to-stop-ldapsearch1-from-base64-encoding-userpassword-and-other-attributes
# https://stackoverflow.com/questions/6250698/how-to-decode-url-encoded-string-in-shell
#
# requires ldap-utils, openssl and perl
# tested with Squid 4 using a "auth_param basic program /usr/lib/squid/mSquidAuth.sh" line

# authenticate first against squid password file
# if this fails, try LDAP (Active Directory) and also check group membership

# variables
# sLOGFILE=/var/log/squid/mSquidAuth.log
sPWDFILE="/etc/squid/passwd"
sLDAPHOST="ldaps://dc.domain.local:636"
sBASE="DC=domain,DC=local"
sLDS_OPTIONS="-o ldif-wrap=no -o nettimeout=7 -LLL -P3 -x "
sBINDDN="CN=LDAP-read-user,OU=Users,DC=domain,DC=local"
sBINDPW="read-user-password"
sGROUP="Proxy-Users"

# functions
function _grantAccess {
#	echo "access granted - $sUSER" >>$sLOGFILE
	echo "OK"
}

function _denyAccess {
#	echo "access denied - $sUSER" >>$sLOGFILE
	echo "ERR"
}

function _setUserAndPass {
	local sAuth="$1"
	local sOldIFS=$IFS
	IFS=' '
	set -- $sAuth
	IFS=$sOldIFS
	# set it globally
	sUSER="$1"
	sPASS=$(urldecode "$2")
}

function urldecode { : "${*//+/ }"; echo -e "${_//%/\\x}"; } # simply beautiful

# loop
while (true); do

read -r sAUTH
sUSER=""
sPASS=""
sSALT=""
sUSERENTRY=""
sHASHEDPW=""
sUSERDN=""
iDNCOUNT=0

if [ -z "$sAUTH" ]; then
#	echo "exiting" >>$sLOGFILE
	exit 0
fi

_setUserAndPass "$sAUTH"

sUSERENTRY=$(grep -E "^${sUSER}:" "$sPWDFILE")
if [ -n "$sUSERENTRY" ]; then
	sSALT=$(echo "$sUSERENTRY" | cut -d$ -f3)
	if [ -n "$sSALT" ]; then
		sHASHEDPW=$(openssl passwd -apr1 -salt "$sSALT" "$sPASS")
		if [ "$sUSERENTRY" = "${sUSER}:${sHASHEDPW}" ]; then
			_grantAccess
			continue
		fi
	fi
fi

# LDAP is next
iDNCOUNT=$(ldapsearch $sLDS_OPTIONS -H "$sLDAPHOST" -D "$sBINDDN" -w "$sBINDPW" -b "$sBASE" "(|(sAMAccountName=${sUSER})(userPrincipalName=${sUSER}))" dn 2>/dev/null | grep -cE 'dn::? ')
if [ $iDNCOUNT != 1 ]; then
	# user needs a unique account
	_denyAccess
	continue
fi
# get user's DN
# we need the extra grep in case we get lines back starting with "# refldap" :/
sUSERDN=$(ldapsearch $sLDS_OPTIONS -H "$sLDAPHOST" -D "$sBINDDN" -w "$sBINDPW" -b "$sBASE" "(|(sAMAccountName=${sUSER})(userPrincipalName=${sUSER}))" dn 2>/dev/null | perl -MMIME::Base64 -n -00 -e 's/\n +//g;s/(?<=:: )(\S+)/decode_base64($1)/eg;print' | grep -E 'dn::? ' | sed -r 's/dn::? //')
# try and bind using that DN to check password validity
# also test if that user is member of a particular group
# backslash in DN needs special treatment
if ldapsearch $sLDS_OPTIONS -H "$sLDAPHOST" -D "$sUSERDN" -w "$sPASS" -b "$sBASE" "name=${sGROUP}" member 2>/dev/null | perl -MMIME::Base64 -n -00 -e 's/\n +//g;s/(?<=:: )(\S+)/decode_base64($1)/eg;print' | grep -q "${sUSERDN/\\/\\\\}"; then
	_grantAccess
	continue
fi
_denyAccess

done
