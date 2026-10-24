import socket
import ssl

import pytest
import psycopg
from sqlalchemy.exc import OperationalError
from sqlalchemy.engine import make_url

from scripts.check_neon import (
    CONNECT_TIMEOUT_SECONDS,
    check_connection,
    check_host_connectivity,
    classify_connection_error,
    normalize_database_url,
)


def test_normalize_neon_postgresql_url_for_psycopg_and_tls():
    url = normalize_database_url(
        'postgresql://demo_user:demo%40pass@example.neon.tech/trustvault'
        '?channel_binding=require'
    )

    assert url.drivername == 'postgresql+psycopg'
    assert url.password == 'demo@pass'
    assert url.query['sslmode'] == 'require'
    assert url.query['channel_binding'] == 'require'
    assert url.render_as_string(hide_password=True).find('***') >= 0


def test_normalize_postgres_legacy_scheme():
    url = normalize_database_url(
        'postgres://demo_user:demo_pass@example.neon.tech/trustvault?sslmode=require'
    )

    assert url.drivername == 'postgresql+psycopg'
    assert url.query['sslmode'] == 'require'
    assert url.query['channel_binding'] == 'require'


@pytest.mark.parametrize(
    'value',
    [
        '',
        ' postgresql://user:pass@example.neon.tech/db',
        'sqlite:///local.db',
        'postgresql://user:pass@/db',
        'postgresql://user:pass@example.neon.tech/',
        'postgresql://user@example.neon.tech/db',
        'postgresql://user:pass@example.neon.tech/db?sslmode=disable',
        'postgresql://user:pass@example.neon.tech/db?channel_binding=disable',
    ],
)
def test_reject_invalid_or_insecure_connection_strings(value):
    with pytest.raises(ValueError):
        normalize_database_url(value)


def test_normalize_url_does_not_change_password_or_query_values():
    raw = (
        'postgresql://demo_user:p%40ss%3Aword@example.neon.tech/trustvault'
        '?sslmode=verify-full&channel_binding=require'
    )

    url = normalize_database_url(raw)

    assert url.password == 'p@ss:word'
    assert url.query == make_url(raw).query


@pytest.mark.parametrize(
    ('error', 'expected'),
    [
        (socket.gaierror('host lookup failed'), 'DNS failure'),
        (TimeoutError('connection timeout'), 'network timeout'),
        (OperationalError('connect', {}, RuntimeError('password authentication failed')), 'authentication failure'),
        (ssl.SSLError('certificate verification failed'), 'TLS/certificate problem'),
        (OperationalError('connect', {}, RuntimeError('database does not exist')), 'database unavailable'),
        (OperationalError('connect', {}, RuntimeError('permission denied')), 'another PostgreSQL error'),
    ],
)
def test_classify_connection_errors(error, expected):
    category, guidance = classify_connection_error(error)

    assert category == expected
    assert guidance
    assert 'password authentication failed' not in guidance


def test_host_check_uses_port_5432_and_ten_second_timeout(monkeypatch):
    connected = {}

    class FakeSocket:
        def __init__(self, family, socktype, proto):
            pass

        def settimeout(self, timeout):
            connected['timeout'] = timeout

        def connect(self, address):
            connected['address'] = address

        def close(self):
            connected['closed'] = True

    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda host, port, type: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', port))],
    )
    monkeypatch.setattr(socket, 'socket', FakeSocket)

    check_host_connectivity('example.neon.tech')

    assert connected['address'][1] == 5432
    assert connected['timeout'] == CONNECT_TIMEOUT_SECONDS == 10
    assert connected['closed']


def test_host_check_reports_dns_failure_without_host_or_exception_details(monkeypatch):
    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda *args, **kwargs: (_ for _ in ()).throw(socket.gaierror('private-host lookup detail')),
    )

    with pytest.raises(Exception) as raised:
        check_host_connectivity('private-host.example')

    assert raised.value.category == 'DNS failure'
    assert 'private-host' not in str(raised.value)
    assert 'lookup detail' not in str(raised.value)


def test_host_check_classifies_socket_timeout(monkeypatch):
    class TimeoutSocket:
        def __init__(self, family, socktype, proto):
            pass

        def settimeout(self, timeout):
            assert timeout <= 10

        def connect(self, address):
            raise socket.timeout('secret host detail')

        def close(self):
            pass

    monkeypatch.setattr(
        socket,
        'getaddrinfo',
        lambda host, port, type: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', port))],
    )
    monkeypatch.setattr(socket, 'socket', TimeoutSocket)

    with pytest.raises(Exception) as raised:
        check_host_connectivity('private-host.example')

    assert raised.value.category == 'network timeout'
    assert 'private-host' not in str(raised.value)
    assert 'secret host detail' not in str(raised.value)


def test_check_connection_sets_ten_second_psycopg_timeout(monkeypatch):
    received = {}

    class FakeConnection:
        def begin(self):
            return FakeTransaction()

        def execute(self, statement):
            received.setdefault('statements', []).append(str(statement))
            return FakeResult()

    class FakeTransaction:
        def rollback(self):
            received['rolled_back'] = True

    class FakeResult:
        def scalar_one(self):
            return 1

    class FakeEngine:
        def connect(self):
            return FakeConnectionContext()

        def dispose(self):
            received['disposed'] = True

    class FakeConnectionContext:
        def __enter__(self):
            return FakeConnection()

        def __exit__(self, *args):
            return False

    def fake_create_engine(url, **kwargs):
        received['url'] = url
        received['options'] = kwargs
        return FakeEngine()

    monkeypatch.setattr('scripts.check_neon.create_engine', fake_create_engine)
    url = normalize_database_url(
        'postgresql://demo_user:demo_pass@example.neon.tech/trustvault'
        '?sslmode=require&channel_binding=require'
    )

    assert check_connection(url)
    assert received['url'].query['connect_timeout'] == '10'
    assert received['url'].query['sslmode'] == 'require'
    assert received['url'].query['channel_binding'] == 'require'
    assert received['options']['hide_parameters'] is True
    assert received['rolled_back']
    assert received['disposed']
    assert received['statements'] == ['SET TRANSACTION READ ONLY', 'SELECT 1']


def test_sqlalchemy_psycopg_dialect_accepts_neon_connection_parameters():
    url = normalize_database_url(
        'postgresql://demo_user:demo_pass@example.neon.tech/trustvault'
        '?sslmode=require&channel_binding=require'
    ).set(query={
        'sslmode': 'require',
        'channel_binding': 'require',
        'connect_timeout': '10',
    })

    positional, keyword = url.get_dialect()().create_connect_args(url)

    assert positional == []
    assert keyword['sslmode'] == 'require'
    assert keyword['channel_binding'] == 'require'
    assert keyword['connect_timeout'] == '10'
    driver_parameters = psycopg.conninfo.conninfo_to_dict(
        'host=example.neon.tech port=5432 sslmode=require '
        'channel_binding=require connect_timeout=10'
    )
    assert driver_parameters['sslmode'] == 'require'
    assert driver_parameters['channel_binding'] == 'require'
    assert driver_parameters['connect_timeout'] == '10'
