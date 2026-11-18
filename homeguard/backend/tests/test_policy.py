from app.domain.policy import ScopeRejected, propose_default_target, validate_cidr


def test_accepts_common_home_lan() -> None:
    scope = validate_cidr("192.168.1.0/24")
    assert scope.cidr == "192.168.1.0/24"
    assert scope.prefix_length == 24
    assert scope.num_addresses == 256
    assert scope.host_bits_normalized is False


def test_accepts_largest_allowed_scope() -> None:
    scope = validate_cidr("10.10.0.0/16")
    assert scope.prefix_length == 16


def test_rejects_public_cidr() -> None:
    try:
        validate_cidr("8.8.8.8/32")
    except ScopeRejected as exc:
        assert exc.code == "public_range"
    else:
        raise AssertionError("public range was accepted")


def test_rejects_whole_internet_and_oversized_private_blocks() -> None:
    for cidr in ("0.0.0.0/0", "10.0.0.0/8", "172.16.0.0/12"):
        try:
            validate_cidr(cidr)
        except ScopeRejected as exc:
            assert exc.code == "scope_too_large"
        else:
            raise AssertionError(f"{cidr} was accepted")


def test_rejects_shared_and_loopback_space() -> None:
    for cidr in ("100.64.0.0/16", "127.0.0.0/24", "172.32.0.0/16", "169.254.1.0/24"):
        try:
            validate_cidr(cidr)
        except ScopeRejected as exc:
            assert exc.code == "public_range"
        else:
            raise AssertionError(f"{cidr} was accepted")


def test_rejects_ipv6() -> None:
    try:
        validate_cidr("fd00::/64")
    except ScopeRejected as exc:
        assert exc.code == "ipv6_not_supported"
    else:
        raise AssertionError("ipv6 was accepted")


def test_normalizes_host_bits() -> None:
    scope = validate_cidr("192.168.1.50/24")
    assert scope.cidr == "192.168.1.0/24"
    assert scope.host_bits_normalized is True


def test_default_target_is_a_24() -> None:
    scope = propose_default_target("10.1.2.9")
    assert scope.cidr == "10.1.2.0/24"


def test_default_target_rejects_public_host() -> None:
    try:
        propose_default_target("1.1.1.1")
    except ScopeRejected as exc:
        assert exc.code == "public_range"
    else:
        raise AssertionError("public host was accepted")
