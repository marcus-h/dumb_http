import os
import select
import socket
import sys
import time
import errno


class Server(object):
    def __init__(self, address, sock_family=socket.AF_INET,
                 sock_type=socket.SOCK_STREAM, fork_on_accept=True):
        super(Server, self).__init__()
        self._address = address
        self._family = sock_family
        self._type = sock_type
        self._fork_on_accept = fork_on_accept

    def _collect_children(self):
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
            while pid != 0 or status != 0:
                print('master', pid, 'exited with status:', status)
                pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError as e:
            if e.errno != errno.ECHILD:
                raise

    def _has_pending_connection(self, sock):
        # just pretend to have a pending connection (the accept will
        # block until there really is a pending connection) - subclasses can
        # do more clever things here
        return True

    def run(self):
        # hmm too lazy to do a proper daemonize...
        self._daemonize()
        with self._create_server_socket() as sock:
            self._configure_server_socket(sock)
            while True:
                if self._has_pending_connection(sock):
                    self._accept(sock)
                if self._fork_on_accept:
                    self._collect_children()

    def _daemonize(self):
        # new-style daemon (see man 7 daemon) - though, we will probably
        # do privileges dropping here (better safe than sorry...) (take
        # also docker/container stuff into account)
        pass

    def _create_server_socket(self):
        return socket.socket(family=self._family, type=self._type)

    def _configure_server_socket(self, sock):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(self._address)
        sock.listen()

    def _accept(self, sock):
        client_sock = None
        pid = -1
        try:
            client_sock, _ = sock.accept()
            if self._fork_on_accept:
                pid = os.fork()
            if not pid or not self._fork_on_accept:
                ret = self.handle_request(client_sock)
        finally:
            if client_sock is not None:
                client_sock.close()
        if not pid:
            # only called in the child in case of a fork
            sys.exit(ret)

    def handle_request(self, sock):
        print('CHILD')
        return 0


class SelectServer(Server):
    def __init__(self, address, *args, timeout=None, **kwargs):
        super(SelectServer, self).__init__(address, *args, **kwargs)
        self._timeout = timeout

    def _calc_timeout(self):
        return self._timeout

    def _select_lists(self, sock):
        return (sock, ), (), ()

    def _has_pending_connection(self, sock):
        timeout = self._calc_timeout()
        select_lists = self._select_lists(sock)
        read, write, exc = select.select(*select_lists, timeout)
        self._post_select(read, write, exc)
        return sock in read

    def _post_select(self, read, write, exc):
        pass


class Periodic(object):
    """Execute a certain handler periodically.

    The time between two consecutive executions is at least <interval>
    many seconds. The return value of the handler can be used to update
    the execution interval. If None is returned, the current interval is
    kept. If a value >= 0 is returned, the interval is set to this
    value. If Periodic.REMOVE is returned, the handler is never executed
    again. All other return values are ignored.
    """

    REMOVE = object()

    def __init__(self, interval, handler):
        super(Periodic, self).__init__()
        if interval is None or interval < 0:
            raise ValueError('non-negative interval required')
        if handler is None:
            raise ValueError('handler cannot be None')
        self._interval = interval
        self._handler = handler
        self._last = 0

    def is_due(self):
        return self.remaining() <= 0

    def remaining(self):
        interval = self._interval
        remaining = self._last + interval - time.time()
        if remaining < 0:
            remaining = 0
        return remaining

    def __call__(self, *args, **kwargs):
        self._last = time.time()
        new_interval = self._handler(*args, **kwargs)
        remove = False
        if new_interval is not None:
            if new_interval is self.REMOVE:
                remove = True
            elif new_interval >= 0:
                self._interval = new_interval
        return remove


class PeriodicServer(SelectServer):
    """A server that executes certain handlers periodically.

    Note: by default all handlers are executed in the main server process.
    That is, use them with care: in particular, they should/must not take
    too long and must not throw an exception. If one of these conditions
    is not fulfilled, the handler should fork a new process and execute
    the actual code in the child. The server will reap the child later
    (see Server._collect_children), if its fork_on_accept parameter is set
    to True. If fork_on_accept is False, just add an additional periodic
    that does a (non-blocking) os.waitpid.
    """

    def __init__(self, address, *args, periodics=None, **kwargs):
        super(PeriodicServer, self).__init__(address, *args, **kwargs)
        if periodics is None:
            periodics = []
        else:
            periodics = list(periodics)
        self._periodics = periodics

    def _calc_timeout(self):
        timeout = super(PeriodicServer, self)._calc_timeout()
        for periodic in self._periodics:
            remaining = periodic.remaining()
            if timeout is None:
                timeout = remaining
            elif timeout > remaining:
                timeout = remaining
        return timeout

    def _post_select(self, read, write, exc):
        super(PeriodicServer, self)._post_select(read, write, exc)
        periodics = self._periodics
        new_periodics = []
        while periodics:
            periodic = periodics.pop(0)
            if not periodic.is_due():
                new_periodics.append(periodic)
                continue
            remove = periodic()
            if not remove:
                new_periodics.append(periodic)
        self._periodics = new_periodics
