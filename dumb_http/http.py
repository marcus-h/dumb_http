import os
import socket  # for class Request

from dumb_http.chunked import ChunkedEncoder
from dumb_http.message import (ReadOnlyHTTPRequest, WriteOnlyHTTPResponse,
                               WriteOnlyHTTPRequest, ReadOnlyHTTPResponse)
from dumb_http.reader import ReadError
from dumb_http.uri import percent_encode
from dumb_http.util import int_to_bytes


def _prepare_data_message(message, data):
    cl = message.get_header('Content-Length')
    te = message.get_header('Transfer-Encoding')
    if data is not None and cl is None and te is None:
        if hasattr(data, 'read'):
            if hasattr(data, 'name'):
                cl = os.stat(data.name).st_size
            else:
                # chunked decoding
                data = ChunkedEncoder(data)
                message.add_header('Transfer-Encoding', b'chunked')
        else:
            cl = len(data)
        if cl is not None:
            message.add_header('Content-Length', int_to_bytes(cl))
    return data


class RequestReaderResponseWriter(object):
    def __init__(self, sio, close=True):
        super(RequestReaderResponseWriter, self).__init__()
        self._sio = sio
        self.request = ReadOnlyHTTPRequest(sio)
        self._response = None
        self._close = close

    # XXX: uuarghs... fix this mess
    def reply(self, status=None, data=None, reason=b'unspec', close=None,
              **headers):
        if close is None:
            close = self._close
        # encoding...
        if self._response is None:
            if status is None:
                status = 500  # hrm usage error...
            response = WriteOnlyHTTPResponse(status, reason)
            for field, value in headers.items():
                response.add_header(field, value)
            data = _prepare_data_message(response, data)
            self._response = response
        self._response.write_body(self.request._sio, data)  # XXX: sio
        if status == 100:
            self._response = None
            close = False
        if close:
            self.close()

    def read(self, count):
        # again, for convenience
        return self.request.read(count)

    def close(self):
        # XXX: check Router._route again (internal comment)
        self._sio.close()


class Request(object):
    def __init__(self, headers=None, dup_headers_use_last=False,
                 suppress_connect_error=False):
        super(Request, self).__init__()
        if headers is None:
            self._headers = {}
        else:
            self._headers = headers
        self._dup_headers_use_last = dup_headers_use_last
        self._suppress_connect_error = suppress_connect_error

    def _makefile(self, sock, *args, **kwargs):
        # hmm we could probably drop our own buffered reader code...
        sio = sock.makefile(*args, **kwargs)
        sock.close()
        return sio

    def _connect(self, address, sock_family, sock_type):
        sock = socket.socket(family=sock_family, type=sock_type)
        sock.connect(address)
        sio = self._makefile(sock, mode='rwb', buffering=0)
        return sio

    def _host_from_address(self, address, sock_family):
        # for now, just a quick workaround
        if sock_family == socket.AF_INET:
            return address[0]
        return address

    def _perform(self, method, address, path, data, query=None,
                 sock_family=socket.AF_INET, sock_type=socket.SOCK_STREAM):
        request_target = path
        if query:
            # hmm move to uri module
            q = bytearray()
            for key, val in query.items():
                key = percent_encode(key)
                val = percent_encode(val)
                if q:
                    q.extend(b'&')
                q.extend(b'%s=%s' % (key, val))
            request_target += b'?' + q
            print(request_target)
        req = WriteOnlyHTTPRequest(method, request_target)
        for field, value in self._headers.items():
            req.add_header(field, value)
        if req.get_header('Host', None) is None:
            host = self._host_from_address(address, sock_family)
            req.add_header('Host', host)
        if req.get_header('Connection', None) is None:
            req.add_header('Connection', b'close')
        sio = None
        try:
            sio = self._connect(address, sock_family, sock_type)
            data = _prepare_data_message(req, data)
            req.write_body(sio, data)
        except ConnectionError as e:
            if sio is not None:
                sio.close()
            if not self._suppress_connect_error:
                raise
            return ConnectionErrorResponse(e.errno, e.strerror)
        kwargs = {'dup_headers_use_last': self._dup_headers_use_last,
                  'suppress_connect_error': self._suppress_connect_error}
        return ConnectionErrorAwareReadOnlyHTTPResponse(sio, **kwargs)

    def get(self, address, path, data=None, query=None,
            sock_family=socket.AF_INET, sock_type=socket.SOCK_STREAM):
        return self._perform(b'GET', address, path, data, query, sock_family,
                             sock_type)

    def post(self, address, path, data=None, query=None,
             sock_family=socket.AF_INET, sock_type=socket.SOCK_STREAM):
        return self._perform(b'POST', address, path, data, query, sock_family,
                             sock_type)

    @classmethod
    def factory(cls, *args, **kwargs):
        return cls(*args, **kwargs)


# uff... what a name
class ConnectionErrorAwareReadOnlyHTTPResponse(ReadOnlyHTTPResponse):
    def __init__(self, *args, suppress_connect_error=False, **kwargs):
        super(ConnectionErrorAwareReadOnlyHTTPResponse, self).__init__(
            *args, **kwargs
        )
        self._suppress_connect_error = suppress_connect_error
        self.errno = None
        self.strerror = None

    def __exit__(self, exc_type, exc_value, traceback):
        ret = super(ConnectionErrorAwareReadOnlyHTTPResponse, self).__exit__(
            exc_type, exc_value, traceback
        )
        if (exc_type is None or not self._suppress_connect_error
                or not issubclass(exc_type, (ConnectionError, ReadError))):
            return ret
        if issubclass(exc_type, ConnectionError):
            self.errno = exc_value.errno
            self.strerror = exc_value.strerror
        else:
            self.strerror = exc_value.msg
        return True

    def is_connection_error(self):
        return self.strerror is not None

    def read(self, count=None):
        if count is not None:
            return super(self.__class__, self).read(count)
        # read everything into a single bytearray
        buf = bytearray()
        while True:
            data = super(self.__class__, self).read(4096)
            if not data:
                break
            buf.extend(data)
        return bytes(buf)


class ConnectionErrorResponse(object):
    def __init__(self, errno, strerror):
        super(ConnectionErrorResponse, self).__init__()
        self.errno = errno
        self.strerror = strerror

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return None

    def close(self):
        pass

    def is_success(self):
        return False

    def is_client_error(self):
        return False

    def is_server_error(self):
        return False

    def is_connection_error(self):
        return True

    def read(self, count=None):
        raise ReadError('cannot read from unconnected response')


def _perform(method, address, path, data, headers, query, encoding,
             sock_family, sock_type, request_factory):
    def encode(_data):
        if encoding is not None and hasattr(_data, 'encode'):
            return _data.encode(encoding)
        return _data

    # hmm... reconsider this
    if isinstance(address, (tuple, list)):
        address = [encode(part) for part in address]
    else:
        address = encode(address)
    path = encode(path)
    data = encode(data)
    encoded_query = {}
    for key, val in query.items():
        encoded_query[encode(key)] = encode(val)
    if request_factory is None:
        request_factory = Request.factory
    req = request_factory(headers, dup_headers_use_last=True,
                          suppress_connect_error=True)
    meth = getattr(req, method)
    return meth(address, path, data, query=encoded_query,
                sock_family=sock_family, sock_type=sock_type)


def get(address, path, data=None, headers=None, encoding='ascii',
        sock_family=socket.AF_INET, sock_type=socket.SOCK_STREAM,
        request_factory=None, **query):
    return _perform('get', address, path, data, headers, query, encoding,
                    sock_family, sock_type, request_factory)


def post(address, path, data=None, headers=None, encoding='ascii',
         sock_family=socket.AF_INET, sock_type=socket.SOCK_STREAM,
         request_factory=None, **query):
    return _perform('post', address, path, data, headers, query, encoding,
                    sock_family, sock_type, request_factory)
