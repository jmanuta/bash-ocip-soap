#!/usr/bin/env bash
# jmanuta@bluip.com | bwoci-p soap interface



function authenticateOci() {

	:<<-Comment
	
	Run first to authenticate

	Comment


	checkOs
	loadConfig
	ociHttpConstants
	AuthenticationRequest
	LoginRequest14sp4

}


function checkOs() {

	:<<-Comment
	
	Fix md5 if macOs
		
	Comment

	md5="md5sum"
	[ "$(uname -s)" = "Darwin" ] && md5="md5"

}


function loadConfig() {

	:<<-Comment

	Loads config file with the following variables:

	sysAdminUser="user@bluip.com"
	sysAdminPass="password"
	protocol="http"
	xspAddress="xsp-address.com"
	xsiContextVersion="com.broadsoft.xsi-actions/v2.0"
	ociPath="webservice/services/ProvisioningService?wsdl"

	Comment

    source config


}


function ociHttpConstants() {

	:<<-Comment

	[1] Generate unique sessionId
	[2] Set reusable soap and xml for OCI requests

	Comment


	sessionId="$(echo "$RANDOM" | "${md5}" | awk '{print $1}')"

	unset xmlHeader
	unset xmlFooter
	unset soapHeader
	unset soapFooter

	xmlHeader+='<?xml version="1.0" encoding="UTF-8"?>'
	xmlHeader+='<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:com:broadsoft:webservice">'
	xmlHeader+='<SOAP-ENV:Body>'
	xmlHeader+='<ns1:processOCIMessage>'
	xmlHeader+='<ns1:in0>'

	xmlFooter+='</ns1:in0>'
	xmlFooter+='</ns1:processOCIMessage>'
	xmlFooter+='</SOAP-ENV:Body>'
	xmlFooter+='</SOAP-ENV:Envelope>'

	soapHeader+='<?xml version="1.0" encoding="ISO-8859-1"?>'
	soapHeader+='<BroadsoftDocument protocol="OCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
	soapHeader+='<sessionId xmlns="">'"${sessionId}"'</sessionId>'

	soapFooter+='</BroadsoftDocument>'

}



function escape() {

	:<<-Comment

	Escape xml

	[1] < to &ltr; 
	[2] > to &gtr;
	[3] " to &quot;

	Comment

	echo "${1}" | sed -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'

}


function send() {
	
	:<<-Comment

	Send HTTP POST

	[1] Add JSESSIONID on all but AuthenticationRequest

	Comment

	if [[ "${1}" == *"AuthenticationRequest"* ]]; then
		unset jheader
	else
		declare -a jheader=(--header "Cookie: JSESSIONID=\"${jsessionId}\";")
	fi


	curl \
		--silent \
		--request POST \
		--header 'Content-Type: text/xml; charset=utf-8' \
		--header 'Connection: Keep-Alive' \
		--header 'SOAPAction: ""' \
		"${jheader[@]}" \
		--include \
		--data "${xmlHeader}$(escape "${soapHeader}")$(escape "${1}")$(escape "${soapFooter}")${xmlFooter}" \
		--url "${protocol}"://"${xspAddress}"/"${ociPath}" 2>&1

}



function AuthenticationRequest() {
 
	:<<-Comment
	
	[1] POST AuthenticationRequest to XSP
		a. curl is verbose to capture jsessionId
		b. stderr is redirected to stdout to hide verbose output to user
	[2] Parse response, store nonce and jsessionId

	Comment

	unset data

	data+='<command xmlns="" xsi:type="AuthenticationRequest">'
	data+='<userId>'"${sysAdminUser}"'</userId>'
	data+='</command>'


	unset response
	response=$(send "${data}")

	nonce="$(echo "${response}" | grep -oE "nonce&gt;[0-9].*&lt;/nonce&gt" | grep -oE "[0-9]+")"
	jsessionId="$(echo "${response}" | grep -oE "JSESSIONID=[A-Z0-9]{32}" | tail -1 | cut -d"=" -f2)"

	if [[ "${response}" = *"nonce"* ]]; then
		#echo "[${FUNCNAME[0]}] Successful"
		:

	elif [[ "${response}" = *"User is not found"* ]]; then
		(>&2 echo "[${FUNCNAME[0]}] ERROR -- Unknown sysAdminUser.  Check config!")
		exit 1

	elif [[ -z "${response}" ]]; then
		(>&2 echo "[${FUNCNAME[0]}] ERROR -- Empty response from server.  Check if server is reachable.")
		exit 1
	else
		(>&2 echo "[${FUNCNAME[0]}] ERROR -- Cause unknown.\n\nDumping output --\n\n")
		echo "${response}"
		exit 1

	fi

}


function LoginRequest14sp4() {

	:<<-Comment

	[1] Calculates signedPassword
	[2] POST LoginRequest14sp4 to XSP
	[3] Check response for errors

	Comment


	signedPassword=$(
		digestSha=$(echo -n "${sysAdminPass}" | openssl sha1 | egrep -oE '[0-9a-z]{40}')
		digestMd5=$(echo -n "${nonce}":"${digestSha}" | "${md5}" | awk '{print $1}')
		echo "${digestMd5}"
	)

	unset data
	data+='<command xmlns="" xsi:type="LoginRequest14sp4">'
	data+='<userId>'"${sysAdminUser}"'</userId>'
	data+='<signedPassword>'"${signedPassword}"'</signedPassword>'
	data+='</command>'

	unset response
	response=$(send "${data}")


	if [[ "${response}" = *"passwordExpiresDays"* ]]; then
		# echo "[${FUNCNAME[0]}] Successful"
		:

	elif [[ "${response}" = *"Invalid password"* ]]; then
		(>&2 echo "[${FUNCNAME[0]}] ERROR -- Invalid sysAdminPass.  Check config!")
		exit 1

	elif [[ "${response}" = *"Lost connection to OCS"* ]]; then
		(>&2 echo "[${FUNCNAME[0]}] ERROR -- Connection issue to server")
		exit 1

	else
		(>&2 echo "[${FUNCNAME[0]}] ERROR -- Unknown cause")
		exit 1

	fi

}


function UserModifyRequest17sp4() {

	:<<-Comment

	Change first and last name on specified userId

	Comment


	userId="${1}"
	firstName="${2}"
	lastName="${3}"

	unset data

	data+='<command xsi:type="UserModifyRequest17sp4" xmlns="">'
	data+='<userId>'"${userId}"'</userId>'
	data+='<lastName>'"${lastName}"'</lastName>'
	data+='<firstName>'"${firstName}"'</firstName>'
	data+='<callingLineIdLastName>'"${lastName}"'</callingLineIdLastName>'
	data+='<callingLineIdFirstName>'"${firstName}"'</callingLineIdFirstName>'
	#data+='<nameDialingName xsi:nil="true"/>'
	#data+='<callingLineIdPhoneNumber xsi:nil="true"/>'
	#data+='<department xsi:type="GroupDepartmentKey" xsi:nil="true"/>'
	#data+='<language>English</language>'
	#data+='<timeZone>'"${timezone}"'</timeZone>'
	#data+='<title>Mr</title>'
	#data+='<pagerPhoneNumber xsi:nil="true"/>'
	#data+='<mobilePhoneNumber>7025551234</mobilePhoneNumber>'
	#data+='<emailAddress>name@domain.com</emailAddress>'
	#data+='<yahooId xsi:nil="true"/>'
	#data+='<addressLocation xsi:nil="true"/>'
	#data+='<networkClassOfService>'"${NCOS}"'</networkClassOfService>'
	#data+='<impPassword>password</impPassword>'
	data+='</command>'


	unset response
	response=$(send "${data}")


	if [[ "${response}" = *"SuccessResponse"* ]]; then
		# echo "[${FUNCNAME[0]}] Successful"
		:

	else
		(>&2 echo "[${FUNCNAME[0]}] ERROR -- Unknown cause")
		exit 1

	fi

}
