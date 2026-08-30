"""Tests for Scapy packet normalisation.

Packets are crafted in memory: no interface, no privileges, no traffic.
"""

from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from ids.capture.packet_parser import PacketParser
from ids.core.enums import Protocol


def test_tcp_packet_is_parsed() -> None:
    packet = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=1234, dport=22, flags="S")
    event = PacketParser("eth0").parse(packet)

    assert event is not None
    assert (event.source_ip, event.destination_ip) == ("10.0.0.5", "10.0.0.1")
    assert event.protocol is Protocol.TCP
    assert (event.source_port, event.destination_port) == (1234, 22)
    assert event.tcp_flags == "S"
    assert event.interface == "eth0"
    assert event.packet_size == len(bytes(packet))


def test_bare_syn_is_recognised_as_a_connection_attempt() -> None:
    parser = PacketParser()
    syn = parser.parse(IP(src="10.0.0.5", dst="10.0.0.1") / TCP(flags="S"))
    syn_ack = parser.parse(IP(src="10.0.0.5", dst="10.0.0.1") / TCP(flags="SA"))
    assert syn.is_tcp_syn is True
    assert syn_ack.is_tcp_syn is False


def test_udp_and_icmp_are_parsed() -> None:
    parser = PacketParser()
    udp = parser.parse(IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=1, dport=53))
    icmp = parser.parse(IP(src="10.0.0.5", dst="10.0.0.1") / ICMP())
    assert udp.protocol is Protocol.UDP and udp.destination_port == 53
    assert icmp.protocol is Protocol.ICMP and icmp.destination_port is None


def test_ipv6_is_parsed() -> None:
    packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(dport=443, flags="S")
    event = PacketParser().parse(packet)
    assert event is not None
    assert event.source_ip == "2001:db8::1"


def test_non_ip_traffic_is_dropped() -> None:
    """ARP has no addresses this system reasons about, so it is not an event."""
    assert PacketParser().parse(Ether() / ARP()) is None


def test_ip_without_transport_layer_is_other() -> None:
    event = PacketParser().parse(IP(src="10.0.0.5", dst="10.0.0.1"))
    assert event is not None
    assert event.protocol is Protocol.OTHER


def test_capture_timestamp_is_used_when_present() -> None:
    packet = IP(src="10.0.0.5", dst="10.0.0.1") / TCP()
    packet.time = 1_800_000_000.0
    event = PacketParser().parse(packet)
    assert event.timestamp.timestamp() == 1_800_000_000.0


def test_absurd_timestamp_falls_back_to_now() -> None:
    packet = IP(src="10.0.0.5", dst="10.0.0.1") / TCP()
    packet.time = 10**30
    event = PacketParser().parse(packet)
    assert event.timestamp.year < 9999


def test_payload_is_not_retained() -> None:
    """Metadata only: a payload must never reach the event model."""
    from scapy.packet import Raw

    packet = IP(src="10.0.0.5", dst="10.0.0.1") / TCP() / Raw(b"SECRET-PAYLOAD")
    event = PacketParser().parse(packet)
    assert "SECRET-PAYLOAD" not in str(event)
