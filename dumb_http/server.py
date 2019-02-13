import os
import socket
import sys


class Server(object):
    def __init__(self, port, host=''):
        self._host = host
        self._port = port

    def _collect_children(self):
        pid, status = os.waitpid(-1, os.WNOHANG)
        while pid != 0 or status != 0:
            print('master', pid, 'exited with status:', status)
            pid, status = os.waitpid(-1, os.WNOHANG)

    def run(self):
        # hmm too lazy to do a proper daemonize...
        self._daemonize()
        kwargs = {'family': socket.AF_INET, 'type': socket.SOCK_STREAM}
        with socket.socket(**kwargs) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self._host, self._port))
            sock.listen()
            while True:
                self._accept(sock)
                self._collect_children()

    def _daemonize(self):
        # new-style daemon (see man 7 daemon) - though, we will probably
        # do privileges dropping here (better safe than sorry...) (take
        # also docker/container stuff into account)
        pass

    def _accept(self, sock):
        client_sock = None
        pid = -1
        try:
            client_sock, _ = sock.accept()
            client_sock.set_inheritable(True)
            pid = os.fork()
            if not pid:
                # child
                ret = self.handle_request(client_sock)
        finally:
            if client_sock is not None:
                client_sock.close()
        if not pid:
            # child
            sys.exit(ret)

    def handle_request(self, sock):
        print('CHILD')
        return 0
