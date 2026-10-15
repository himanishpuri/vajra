"""Tests for the iptables VAJRA-BLOCK chain (issue #3)."""

import ipaddress
import subprocess

import pytest


class FakeIptables:
    """Stands in for subprocess.run: records calls and fails those containing any text in fail"""

    def __init__(self, fail=()):
        self.calls = []
        self.fail = fail

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        failed = any(text in " ".join(cmd) for text in self.fail)
        return subprocess.CompletedProcess(cmd, 1 if failed else 0, stdout="", stderr="iptables: failed" if failed else "")


def raises(exc):
    def run(cmd, **kwargs):
        raise exc
    return run


SETUP = [
    [tool, *args]
    for tool in ("iptables", "ip6tables")
    for args in (
        ["-N", "VAJRA-BLOCK"], ["-D", "INPUT", "-j", "VAJRA-BLOCK"], ["-D", "OUTPUT", "-j", "VAJRA-BLOCK"],
        ["-F", "VAJRA-BLOCK"], ["-I", "INPUT", "1", "-j", "VAJRA-BLOCK"], ["-I", "OUTPUT", "1", "-j", "VAJRA-BLOCK"],
    )
]


def drops(tool, action, ip):
    return [[tool, action, "VAJRA-BLOCK", "-s", ip, "-j", "DROP"], [tool, action, "VAJRA-BLOCK", "-d", ip, "-j", "DROP"]]


@pytest.fixture
def engine_module(tmp_path, monkeypatch):
    """Import the engine from a scratch directory with iptables as the backend and a loopback-only allowlist."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    from vajra.soar import engine

    monkeypatch.setattr(engine.FirewallManager, "_detect_backend", lambda self: "iptables")
    monkeypatch.setattr(engine, "build_allowlist", lambda extra=None, log=None: [ipaddress.ip_network("127.0.0.0/8")])
    return engine


def test_setup_puts_chain_above_nfqueue_and_restores_saved_blocks(engine_module, tmp_path, monkeypatch):
    (tmp_path / "logs" / "blocked_ips.txt").write_text("203.0.113.7\n2001:db8::7")
    run = FakeIptables()
    monkeypatch.setattr(engine_module.subprocess, "run", run)
    fw = engine_module.FirewallManager()
    assert run.calls[:len(SETUP)] == SETUP
    assert sorted(run.calls[len(SETUP):]) == sorted(drops("iptables", "-A", "203.0.113.7") + drops("ip6tables", "-A", "2001:db8::7"))
    assert fw.enforcing
    assert fw.blocked_ips == {"203.0.113.7", "2001:db8::7"}


@pytest.mark.parametrize("run", [
    FakeIptables(fail=["iptables -I INPUT"]),
    raises(OSError("iptables: not found")),
], ids=["iptables-error", "oserror"])
def test_ipv4_setup_failure_stops_enforcing(engine_module, tmp_path, monkeypatch, run):
    path = tmp_path / "logs" / "blocked_ips.txt"
    path.write_text("203.0.113.7")
    monkeypatch.setattr(engine_module.subprocess, "run", run)
    fw = engine_module.FirewallManager()
    assert not fw.enforcing
    assert fw.blocked_ips == set()
    assert fw.block_ip("198.51.100.9", "test") is False
    assert path.read_text() == "203.0.113.7"


def test_ipv6_setup_failure_keeps_ipv4_enforcing(engine_module, tmp_path, monkeypatch):
    (tmp_path / "logs" / "blocked_ips.txt").write_text("203.0.113.7")
    monkeypatch.setattr(engine_module.subprocess, "run", FakeIptables(fail=["ip6tables -F"]))
    fw = engine_module.FirewallManager()
    assert fw.enforcing
    assert fw.blocked_ips == {"203.0.113.7"}


def test_block_and_unblock_use_the_chain(engine_module, monkeypatch):
    run = FakeIptables()
    monkeypatch.setattr(engine_module.subprocess, "run", run)
    fw = engine_module.FirewallManager()
    assert fw.block_ip("198.51.100.9", "test") is True
    assert run.calls[-2:] == drops("iptables", "-A", "198.51.100.9")
    assert fw.unblock_ip("198.51.100.9") is True
    assert run.calls[-2:] == drops("iptables", "-D", "198.51.100.9")
