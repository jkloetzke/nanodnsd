load bats-support/load
load bats-assert/load
load common

@test "Query existing entry via UDP" {
	do_query udp "static.dyn.mydomain.test" ANY
	assert_equal "$NANODNSD_STATUS" NOERROR
	assert_equal "$NANODNSD_A" "127.0.0.1"
	assert_equal "$NANODNSD_AAAA" "::1"
	assert_equal "$NANODNSD_SOA" ""
}

@test "Query existing entry via TCP" {
	do_query tcp "static.dyn.mydomain.test" ANY
	assert_equal "$NANODNSD_STATUS" NOERROR
	assert_equal "$NANODNSD_A" "127.0.0.1"
	assert_equal "$NANODNSD_AAAA" "::1"
	assert_equal "$NANODNSD_SOA" ""
}

@test "Query unknown entry via UDP" {
	do_query udp "nx.dyn.mydomain.test" ANY
	assert_equal "$NANODNSD_STATUS" NXDOMAIN
	assert_equal"$NANODNSD_A" ""
	assert_equal "$NANODNSD_AAAA" ""
	assert test -n "$NANODNSD_SOA"
}

@test "Query unknown entry via TCP" {
	do_query tcp "nx.dyn.mydomain.test" ANY
	assert_equal "$NANODNSD_STATUS" NXDOMAIN
	assert_equal"$NANODNSD_A" ""
	assert_equal "$NANODNSD_AAAA" ""
	assert test -n "$NANODNSD_SOA"
}

@test "Check that server knowns NS of his zone" {
	do_query tcp "dyn.mydomain.test" NS
	assert_equal "$NANODNSD_STATUS" NOERROR
	assert_equal "$NANODNSD_NS" "ns.mydomain.test."
}

@test "Empty domain exists but returns SOA record" {
	do_query udp "dynamic.dyn.mydomain.test" ANY
	assert_equal "$NANODNSD_STATUS" NOERROR
	assert_equal "$NANODNSD_A" ""
	assert_equal "$NANODNSD_AAAA" ""
	assert test -n "$NANODNSD_SOA"
}

# Tests the timeout= parameter that kicks slow clients
@test "DNS TCP SYN attack" {
	JOBS=()
	PENDING=0

	for i in $(seq 10) ; do
		nc 127.0.0.1 $NANODNSD_DNS_TCP </dev/null >/dev/null &
		JOBS+=($!)
		: $(( PENDING++ ))
	done

	(sleep 3 ; exit 250) 3>&- &
	GUARD=$!

	do_query tcp "static.dyn.mydomain.test" ANY
	test "$NANODNSD_A" = "127.0.0.1"
	test "$NANODNSD_AAAA" = "::1"
	test -z "$NANODNSD_SOA"

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

# Only one query must be answered. The others should be dropped.
# Tests the connections= parameter so that excessive clients are dropped.
@test "Send many parallel TCP queries" {
	T="$(mktemp -d)"

	JOBS=()
	for i in $(seq 10) ; do
		(sleep 0.5 ; cat "$BATS_TEST_DIRNAME/static-query.bin") | nc localhost $NANODNSD_DNS_TCP | wc -c > "$T/query-$i.txt" &
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
