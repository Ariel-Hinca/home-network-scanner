from app.domain.port_notes import explain_port


def test_router_web_page_is_expected() -> None:
    label, summary = explain_port(80, "router")
    assert label == "expected"
    assert "web page" in summary
    assert "normal" in summary


def test_old_login_on_a_camera_should_be_closed() -> None:
    label, summary = explain_port(23, "camera")
    assert label == "close"
    assert "old remote login" in summary


def test_video_stream_is_expected_on_a_camera_and_only_noted_elsewhere() -> None:
    assert explain_port(554, "camera")[0] == "expected"
    assert explain_port(554, "")[0] == "review"


def test_printer_port_follows_the_device_kind() -> None:
    assert explain_port(9100, "printer")[0] == "expected"
    assert explain_port(9100, "computer")[0] == "review"


def test_remote_screen_is_never_treated_as_normal() -> None:
    assert explain_port(3389, "computer")[0] == "close"
    assert explain_port(5900, "")[0] == "close"


def test_an_unknown_open_port_is_only_worth_a_look() -> None:
    label, summary = explain_port(9999, "")
    assert label == "review"
    assert "no usual meaning" in summary
