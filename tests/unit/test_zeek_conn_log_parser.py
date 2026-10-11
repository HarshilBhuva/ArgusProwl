"""Unit tests for ZeekConnLogParser."""

from datetime import datetime

import pytest

from argusprowl.collectors.zeek.parser import ZeekConnLogParser
from argusprowl.exceptions.exceptions import ParserError
from argusprowl.models.normalized_event import NormalizedEvent


def test_parser_can_parse() -> None:
    """Test can_parse validation logic."""
    parser = ZeekConnLogParser()

    valid_tsv = "1590000000.000\tC12345\t192.168.1.10\t44321\t10.0.0.1\t80\ttcp"
    comment = "#fields ts uid id.orig_h"
    empty = "   "

    assert parser.can_parse(valid_tsv) is True
    assert parser.can_parse(comment) is False
    assert parser.can_parse(empty) is False


def test_parser_valid_record() -> None:
    """Test parsing a valid Zeek conn.log line into NormalizedEvent."""
    parser = ZeekConnLogParser()

    raw_line = (
        "1590000000.123456\tC123456789\t192.168.1.50\t54321\t93.184.216.34\t80\ttcp\t"
        "http\t2.50\t512\t2048\tSF\t-\t-\t0\tShADda\t10\t1024\t8\t2400\t-"
    )

    event = parser.parse(raw_line)

    assert isinstance(event, NormalizedEvent)
    assert event.source_type == "zeek"
    assert event.event_type == "network_connection"
    assert event.source_record_id == "C123456789"
    assert event.src_ip == "192.168.1.50"
    assert event.src_port == 54321
    assert event.dst_ip == "93.184.216.34"
    assert event.dst_port == 80
    assert event.protocol == "tcp"
    assert event.attributes["uid"] == "C123456789"
    assert event.attributes["service"] == "http"
    assert event.attributes["duration"] == 2.50
    assert event.attributes["orig_bytes"] == 512
    assert event.attributes["resp_bytes"] == 2048
    assert event.attributes["conn_state"] == "SF"
    assert event.attributes["history"] == "ShADda"
    assert event.attributes["orig_pkts"] == 10
    assert event.attributes["resp_pkts"] == 8
    assert isinstance(event.timestamp, datetime)


def test_parser_null_fields_with_hyphen() -> None:
    """Test parsing record with '-' for missing values."""
    parser = ZeekConnLogParser()

    raw_line = (
        "1590000000.000\tC999\t10.0.0.2\t1234\t10.0.0.1\t53\tudp\t"
        "dns\t-\t-\t-\tS0\t-\t-\t0\tD\t1\t50\t0\t0\t-"
    )

    event = parser.parse(raw_line)

    assert event.attributes["duration"] == 0.0
    assert event.attributes["orig_bytes"] == 0
    assert event.attributes["resp_bytes"] == 0


def test_parser_header_comments_and_malformed() -> None:
    """Test raising ParserError on comments and malformed input."""
    parser = ZeekConnLogParser()

    with pytest.raises(ParserError):
        parser.parse("#close 2026-08-03")

    with pytest.raises(ParserError):
        parser.parse("invalid_single_token")

    with pytest.raises(ParserError):
        parser.parse("")


def test_parser_dynamic_schema_update() -> None:
    """Test updating field schema when #fields header is encountered."""
    parser = ZeekConnLogParser()

    header_line = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"
    with pytest.raises(ParserError, match="Updated parser schema"):
        parser.parse(header_line)

    raw_line = "1590000000.000\tC888\t1.1.1.1\t100\t2.2.2.2\t200\tudp"
    event = parser.parse(raw_line)

    assert event.attributes["uid"] == "C888"
    assert event.src_ip == "1.1.1.1"
    assert event.dst_ip == "2.2.2.2"
