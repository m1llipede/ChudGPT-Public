from chudlm.request_gate import RequestGate


def test_optional_token_authentication() -> None:
    public = RequestGate(30)
    private = RequestGate(30, "a-private-token")
    assert public.authorize("")
    assert private.authorize("Bearer a-private-token")
    assert not private.authorize("Bearer wrong")
    assert not private.authorize("Basic a-private-token")


def test_rate_limit_resets_after_one_minute() -> None:
    gate = RequestGate(2)
    assert gate.allow("client", now=100.0) == (True, 0)
    assert gate.allow("client", now=101.0) == (True, 0)
    allowed, retry_after = gate.allow("client", now=102.0)
    assert not allowed
    assert retry_after == 58
    assert gate.allow("client", now=160.0) == (True, 0)
