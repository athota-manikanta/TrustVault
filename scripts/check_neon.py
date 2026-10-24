"""Read-only Neon connectivity check; prompts for DATABASE_URL without echoing it."""
from getpass import getpass
from queue import Empty, Queue
import socket
import ssl
from threading import Thread
import time

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError, SQLAlchemyError

CONNECT_TIMEOUT_SECONDS = 10


class ConnectionDiagnosticError(Exception):
    def __init__(self, category: str, guidance: str):
        super().__init__(category)
        self.category = category
        self.guidance = guidance


def _exception_chain(error: BaseException):
    pending = [error]
    visited = set()
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        yield current
        cause = current.__cause__ or current.__context__
        if cause is not None:
            pending.append(cause)
        original = getattr(current, 'orig', None)
        if isinstance(original, BaseException):
            pending.append(original)


def classify_connection_error(error: BaseException) -> tuple[str, str]:
    chain = tuple(_exception_chain(error))
    sqlstates = {
        getattr(item, 'sqlstate', None)
        or getattr(item, 'pgcode', None)
        for item in chain
    }
    sqlstates.discard(None)
    error_types = {type(item).__name__.lower() for item in chain}
    safe_to_inspect = ' '.join(str(item).lower() for item in chain)

    if any(isinstance(item, socket.gaierror) for item in chain) or any(
        marker in safe_to_inspect
        for marker in ('could not translate host name', 'getaddrinfo failed', 'name or service not known')
    ):
        return 'DNS failure', 'Check that the Neon hostname was copied correctly and DNS/network access is available.'
    if any(isinstance(item, (TimeoutError, socket.timeout)) for item in chain) or any(
        marker in safe_to_inspect for marker in ('timed out', 'timeout expired', 'timeout')
    ):
        return 'network timeout', 'Check your network, firewall, VPN, and Neon project availability, then retry.'
    if '28P01' in sqlstates or '28000' in sqlstates or any(
        marker in safe_to_inspect
        for marker in ('password authentication failed', 'authentication failed', 'invalid password')
    ):
        return 'authentication failure', 'Use a newly rotated Neon role password and URL-encode special password characters.'
    if any(isinstance(item, ssl.SSLError) for item in chain) or any(
        'ssl' in name or 'tls' in name or 'certificate' in name
        for name in error_types
    ) or any(
        marker in safe_to_inspect
        for marker in ('certificate verify failed', 'ssl error', 'tls error', 'certificate required')
    ):
        return 'TLS/certificate problem', 'Use the Neon-provided TLS parameters, including sslmode=require; do not disable TLS.'
    if any(state.startswith('08') for state in sqlstates) or sqlstates.intersection(
        {'3D000', '53300', '57P03'}
    ) or any(
        marker in safe_to_inspect
        for marker in ('connection refused', 'no route to host', 'network is unreachable', 'database does not exist')
    ):
        return 'database unavailable', 'Verify the Neon endpoint, database name, project status, and network access.'
    return 'another PostgreSQL error', 'Check the Neon connection parameters and role permissions; details are intentionally withheld.'


def normalize_database_url(value: str) -> URL:
    if not value or value != value.strip() or '\n' in value or '\r' in value:
        raise ValueError('Connection string is empty or contains surrounding whitespace.')

    try:
        url = make_url(value)
    except ArgumentError:
        raise ValueError('Connection string could not be parsed.') from None

    if url.drivername in {'postgres', 'postgresql'}:
        url = url.set(drivername='postgresql+psycopg')
    elif url.drivername != 'postgresql+psycopg':
        raise ValueError('Expected a PostgreSQL connection string.')

    if not url.host or not url.database or not url.username or not url.password:
        raise ValueError('Connection string must include a host, database, username, and password.')

    sslmode = url.query.get('sslmode')
    if sslmode is not None and sslmode not in {'require', 'verify-ca', 'verify-full'}:
        raise ValueError('TLS must be enabled with sslmode=require or stronger.')
    channel_binding = url.query.get('channel_binding')
    if channel_binding is not None and channel_binding != 'require':
        raise ValueError('Neon connections must use channel_binding=require.')
    if sslmode is None or channel_binding is None:
        query = dict(url.query)
        query['sslmode'] = sslmode or 'require'
        query['channel_binding'] = channel_binding or 'require'
        url = url.set(query=query)

    return url


def check_host_connectivity(host: str, port: int = 5432, timeout: int = CONNECT_TIMEOUT_SECONDS) -> None:
    result_queue = Queue(maxsize=1)

    def resolve():
        try:
            result_queue.put((socket.getaddrinfo(host, port, type=socket.SOCK_STREAM), None))
        except OSError as error:
            result_queue.put((None, error))

    Thread(target=resolve, daemon=True).start()
    try:
        addresses, error = result_queue.get(timeout=timeout)
    except Empty:
        raise ConnectionDiagnosticError(
            'network timeout',
            'DNS resolution timed out. Check your DNS, VPN, or network settings, then retry.',
        ) from None
    if error is not None:
        raise ConnectionDiagnosticError(*classify_connection_error(error)) from None

    last_error = None
    deadline = time.monotonic() + timeout
    for family, socktype, proto, _, address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ConnectionDiagnosticError(
                'network timeout',
                'The connection check exceeded 10 seconds. Check your network or firewall, then retry.',
            ) from None
        connection = socket.socket(family, socktype, proto)
        connection.settimeout(remaining)
        try:
            connection.connect(address)
            return
        except OSError as error:
            last_error = error
        finally:
            connection.close()

    error = last_error or OSError('No usable address found.')
    raise ConnectionDiagnosticError(*classify_connection_error(error)) from None


def check_connection(url: URL) -> bool:
    url = url.set(query={**url.query, 'connect_timeout': str(CONNECT_TIMEOUT_SECONDS)})
    engine = create_engine(url, echo=False, hide_parameters=True, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(text('SET TRANSACTION READ ONLY'))
                result = connection.execute(text('SELECT 1')).scalar_one()
                if result != 1:
                    raise RuntimeError('Unexpected read-only connectivity check result.')
            finally:
                transaction.rollback()
        return True
    finally:
        engine.dispose()


def main() -> int:
    try:
        value = getpass('Paste Neon DATABASE_URL (input hidden): ')
        url = normalize_database_url(value)
    except EOFError:
        print('No connection string was entered.')
        return 2
    except ValueError as error:
        print(f'Invalid connection string: {error}')
        return 2

    print('Connection string format is valid. Checking hostname and port 5432...')
    try:
        check_host_connectivity(url.host, timeout=CONNECT_TIMEOUT_SECONDS)
    except ConnectionDiagnosticError as error:
        print(f'{error.category}: {error.guidance}')
        return 1

    print('Hostname resolved and port 5432 is reachable. Testing read-only PostgreSQL connectivity...')
    try:
        check_connection(url)
    except SQLAlchemyError as error:
        category, guidance = classify_connection_error(error)
        print(f'{category}: {guidance}')
        return 1
    except ConnectionDiagnosticError as error:
        print(f'{error.category}: {error.guidance}')
        return 1

    print('Connected successfully. Read-only SELECT 1 passed; no database contents were changed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
