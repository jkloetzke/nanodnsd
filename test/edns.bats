load bats-support/load
load bats-assert/load
load common

@test "Query existing entry without cookie" {
	do_query udp "static.dyn.mydomain.test" ANY +edns=0 +nocookie
	assert_equal "$NANODNSD_STATUS" NOERROR
	assert_equal "$NANODNSD_A" "127.0.0.1"
	assert_equal "$NANODNSD_AAAA" "::1"
	assert_equal "$NANODNSD_SOA" ""
}

@test "Invalid EDNS option must be ignored" {
	do_query udp "static.dyn.mydomain.test" ANY +edns=0 +nocookie +ednsopt=100
	assert_equal "$NANODNSD_STATUS" NOERROR
	assert_equal "$NANODNSD_A" "127.0.0.1"
	assert_equal "$NANODNSD_AAAA" "::1"
	assert_equal "$NANODNSD_SOA" ""
}

@test "Invalid ENDS version must be rejected" {
	do_query udp "static.dyn.mydomain.test" ANY +edns=1 +noednsneg +nocookie
	assert_equal "$NANODNSD_STATUS" BADVERS
}

@test "Missing server cookie must return BADCOOKIE" {
	do_query udp "static.dyn.mydomain.test" ANY +cookie +nobadcookie +tries=1 +retry=0
	assert_equal "$NANODNSD_STATUS" BADCOOKIE
}

@test "Rate limit applies to UDP without cookies" {
	# "rate_limit" is "3" so the 4th request should time out.
	refute dig @127.0.0.1 -p $NANODNSD_DNS_UDP +notcp +noedns +nocookie -f "$BATS_TEST_DIRNAME/batch.query"
}

@test "Rate limit does not apply to UDP with cookies" {
	dig @127.0.0.1 -p $NANODNSD_DNS_UDP +notcp +cookie -f "$BATS_TEST_DIRNAME/batch.query"
}

@test "Rate limit does not apply to TCP" {
	dig @127.0.0.1 -p $NANODNSD_DNS_TCP +tcp +nocookie -f "$BATS_TEST_DIRNAME/batch.query"
}
