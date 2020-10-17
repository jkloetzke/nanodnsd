load bats-support/load
load bats-assert/load
load common

@test "Update entry" {
	do_update "hostname=dynamic.dyn.mydomain.test&token=asdf&ipv4=1.2.3.4&ipv6=::2"
	assert_equal "$NANODNSD_STATUS" 200

	do_query udp "dynamic.dyn.mydomain.test" ANY
	assert_equal "$NANODNSD_A" "1.2.3.4"
	assert_equal "$NANODNSD_AAAA" "::2"
}

@test "Overwrite entry" {
	do_update "hostname=dynamic.dyn.mydomain.test&token=asdf&ipv4=1.2.3.4&ipv6=::2"
	assert_equal "$NANODNSD_STATUS" 200
	do_update "hostname=dynamic.dyn.mydomain.test&token=asdf&ipv4=8.8.8.8&ipv6=1::2"
	assert_equal "$NANODNSD_STATUS" 200

	do_query udp "dynamic.dyn.mydomain.test" ANY
	assert_equal "$NANODNSD_A" "8.8.8.8"
	assert_equal "$NANODNSD_AAAA" "1::2"
}

@test "Clear entry" {
	do_update "hostname=dynamic.dyn.mydomain.test&token=asdf&ipv4=1.2.3.4&ipv6=::2"
	assert_equal "$NANODNSD_STATUS" 200
	do_update "hostname=dynamic.dyn.mydomain.test&token=asdf"
	assert_equal "$NANODNSD_STATUS" 200

	do_query udp "dynamic.dyn.mydomain.test" ANY
	assert_equal "$NANODNSD_A" ""
	assert_equal "$NANODNSD_AAAA" ""
	assert test -n "$NANODNSD_SOA"
}

@test "Expiration of entry" {
	do_update "hostname=ephemeral.dyn.mydomain.test&token=asdf&ipv4=1.2.3.4"
	assert_equal "$NANODNSD_STATUS" 200

	do_query udp "ephemeral.dyn.mydomain.test" ANY
	assert_equal "$NANODNSD_A" "1.2.3.4"

	sleep 2

	do_query udp "ephemeral.dyn.mydomain.test" ANY
	assert_equal "$NANODNSD_A" ""
	assert_equal "$NANODNSD_AAAA" ""
	assert test -n "$NANODNSD_SOA"
}

@test "Wrong token is rejected" {
	do_update "hostname=dynamic.dyn.mydomain.test&token=wrong&ipv4=1.2.3.4&ipv6=::2"
	assert_equal "$NANODNSD_STATUS" 403
	do_update "hostname=dynamic.dyn.mydomain.test&token=&ipv4=1.2.3.4&ipv6=::2"
	assert_equal "$NANODNSD_STATUS" 403
	do_update "hostname=dynamic.dyn.mydomain.test&ipv4=1.2.3.4&ipv6=::2"
	assert_equal "$NANODNSD_STATUS" 403
}

@test "Cannot update static entry" {
	do_update "hostname=static.dyn.mydomain.test&token=&ipv4=1.2.3.4"
	assert_equal "$NANODNSD_STATUS" 403
	do_update "hostname=static.dyn.mydomain.test&ipv4=1.2.3.4"
	assert_equal "$NANODNSD_STATUS" 403
}

@test "Cannot update wrong managed domain" {
	do_update "hostname=dynamic.foo.mydomain.test&token=asdf&ipv4=1.2.3.4&ipv6=::2"
	assert_equal "$NANODNSD_STATUS" 403
	do_update "hostname=dynamic.some.thing.else&token=asdf&ipv4=1.2.3.4&ipv6=::2"
	assert_equal "$NANODNSD_STATUS" 403
}

@test "Slow http clients are kicked" {
	JOBS=()
	PENDING=0

	for i in $(seq 10) ; do
		nc 127.0.0.1 $NANODNSD_HTTP </dev/null >/dev/null &
		JOBS+=($!)
		: $(( PENDING++ ))
	done

	(sleep 3 ; exit 250) 3>&- &
	GUARD=$!

	do_update "hostname=dynamic.dyn.mydomain.test&token=asdf&ipv4=1.2.3.4&ipv6=::2"
	assert_equal "$NANODNSD_STATUS" 200

	while [[ $PENDING -gt 0 ]] && wait -n ; do
		: $(( PENDING-- ))
	done

	if [[ $PENDING -eq 0 ]] ; then
		kill $GUARD || true
	else
		kill "${JOBS[@]}" $GUARD || true
		fail "Some command have failed or timeout happended!"
	fi
}

@test "Too many clients are kicked FIFO like" {
	T="$(mktemp -d)"
	Q="$(printf 'GET /api/update?hostname=dynamic.dyn.mydomain.test&ipv4=1.2.3.4&ipv6=::1&token=asdf HTTP/1.1\r\n\r\n')"

	JOBS=()
	for i in $(seq 10) ; do
		(sleep 0.5 ; echo "$Q") | nc localhost $NANODNSD_HTTP | wc -c > "$T/query-$i.txt" &
		JOBS+=($!)
	done
	wait "${JOBS[@]}"

	answered=0
	for i in $(seq 10) ; do
		read -r received < "$T/query-$i.txt"
		if [[ $received -gt 0 ]] ; then
			: $(( answered++ ))
		fi
	done
	rm -rf "$T"

	assert_equal $answered 1
}
