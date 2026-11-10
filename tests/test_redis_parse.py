from nope.decoys.redis import classify, parse_command


def test_resp_auth_is_auth():
    data = b"*2\r\n$4\r\nAUTH\r\n$6\r\nhunter\r\n"
    assert parse_command(data) == ["AUTH", "hunter"]
    assert classify(parse_command(data)) == "auth"


def test_inline_ping_is_probe():
    assert classify(parse_command(b"PING\r\n")) == "probe"


def test_config_set_is_exploit():
    data = b"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$5\r\n/tmp/\r\n"
    assert classify(parse_command(data)) == "exploit"


def test_exploit_wins_over_auth_in_a_pipeline():
    data = b"*2\r\n$4\r\nAUTH\r\n$1\r\nx\r\n*3\r\n$7\r\nSLAVEOF\r\n$1\r\n1\r\n$1\r\n2\r\n"
    assert classify(parse_command(data)) == "exploit"
