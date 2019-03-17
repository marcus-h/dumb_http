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

    def _connect(self, host, port):
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        sock.connect((host, port))
        # hmm we could probably drop our own buffered reader code...
        sio = sock.makefile(mode='rwb', buffering=0)
        sock.close()
        return sio

    def _perform(self, method, host, path, data, port=80, query=None):
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
            req.add_header('Host', host)
        if req.get_header('Connection', None) is None:
            req.add_header('Connection', b'close')
        try:
            sio = self._connect(host, port)
        except ConnectionError as e:
            if not self._suppress_connect_error:
                raise
            return ConnectionErrorResponse(e.errno, e.strerror)
        data = _prepare_data_message(req, data)
        req.write_body(sio, data)
        kwargs = {'dup_headers_use_last': self._dup_headers_use_last}
        return ConnectionErrorAwareReadOnlyHTTPResponse(sio, **kwargs)

    def get(self, host, path, data=None, port=80, query=None):
        return self._perform(b'GET', host, path, data, port, query)

    def post(self, host, path, data=None, port=80, query=None):
        return self._perform(b'POST', host, path, data, port, query)


# uff... what a name
class ConnectionErrorAwareReadOnlyHTTPResponse(ReadOnlyHTTPResponse):
    def is_connection_error(self):
        return False

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


def _perform(method, host, path, data, port, headers, query, encoding):
    def encode(_data):
        if encoding is not None and hasattr(_data, 'encode'):
            return _data.encode(encoding)
        return _data

    host = encode(host)
    path = encode(path)
    data = encode(data)
    encoded_query = {}
    for key, val in query.items():
        encoded_query[encode(key)] = encode(val)
    req = Request(headers, dup_headers_use_last=True,
                  suppress_connect_error=True)
    meth = getattr(req, method)
    return meth(host, path, data, port, query=encoded_query)


def get(host, path, data=None, port=80, headers=None, encoding='ascii',
        **query):
    return _perform('get', host, path, data, port, headers, query, encoding)


def post(host, path, data=None, port=80, headers=None, encoding='ascii',
         **query):
    return _perform('post', host, path, data, port, headers, query, encoding)
