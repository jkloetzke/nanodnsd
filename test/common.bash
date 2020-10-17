setup()
{
	NANODNSD_DNS_TCP=
	NANODNSD_DNS_UDP=
	NANODNSD_HTTP=

	coproc ./nanodnsd -c "$BATS_TEST_DIRNAME/test.conf" 2>&1 >/dev/null
	local typ port
	while [[ -z $NANODNSD_DNS_TCP || -z $NANODNSD_DNS_UDP || -z $NANODNSD_HTTP ]] && read -r typ port <&${COPROC[0]} ; do
		case $typ in
			tcp)
				NANODNSD_DNS_TCP=$port
				;;
			udp)
				NANODNSD_DNS_UDP=$port
				;;
			http)
				NANODNSD_HTTP=$port
				;;
		esac
	done

	if [[ -z $NANODNSD_DNS_TCP || -z $NANODNSD_DNS_UDP || -z $NANODNSD_HTTP ]] ; then
		echo "# Failed to start nanodnsd!" >&3
		exit 1
	fi
	NANODNSD_PID=$COPROC_PID
}

teardown()
{
	if [[ ${NANODNSD_PID:+true} ]] ; then
		kill $NANODNSD_PID
		wait $NANODNSD_PID
		unset NANODNSD_PID
	fi
}

do_query()
{
	NANODNSD_A=
	NANODNSD_AAAA=
	NANODNSD_SOA=
	NANODNSD_NS=
	NANODNSD_STATUS=

	local port opt
	case $1 in
		tcp)
			port=$NANODNSD_DNS_TCP
			opt=+tcp
			;;
		udp)
			port=$NANODNSD_DNS_UDP
			opt=+notcp
			;;
		*)
			echo "# Invalid query transport!" >&3
			exit 1
	esac
	shift

	while read -r line ; do
		case "$line" in
			 \;*HEADER*status:*)
				NANODNSD_STATUS="$(sed -e 's/.*status: \([A-Z]\+\).*/\1/' <<<"$line")"
				;;
			\;*) ;;
			"") ;;
			*)
				read -r domain ttl cls typ rr <<<"$line"
				case "$typ" in
					A)
						NANODNSD_A="$rr"
						;;
					AAAA)
						NANODNSD_AAAA="$rr"
						;;
					SOA)
						NANODNSD_SOA="$rr"
						;;
					NS)
						NANODNSD_NS="$rr"
						;;
				esac
				;;
		esac
	done < <(dig @127.0.0.1 -p $port "$@" $opt)
}

do_update()
{
	T="$(mktemp -d)"
	curl --max-time 3 -s -w '%{http_code}' \
		"http://localhost:$NANODNSD_HTTP/api/update?$1" \
		-o "$T/reply" >"$T/code"
	read -r NANODNSD_STATUS <"$T/code" || true
	read -r NANODNSD_REPLY <"$T/reply" || true
	rm -rf "$T"
}
