from collections import OrderedDict
import io

from dumb_http.reader import DelimitedReader, LimitedReader
from dumb_http.chunked import ChunkedReader
from dumb_http.errors import ProtocolError
from dumb_http.util import int_to_bytes


class HTTPMessage(object):
    def __init__(self, dup_header_use_last=False):
        super(HTTPMessage, self).__init__()
        self._headers = OrderedDict()
        self._dup_header_use_last = dup_header_use_last

    def headers(self):
        return self._headers

    def add_header(self, field, value):
        if field.endswith(' '):
            raise ValueError('header field ends with WS')
        field = field.lower()
        if field in self._headers and not self._dup_header_use_last:
            raise ValueError('duplicate headers not supported')
        self._headers[field] = value

    def get_header(self, field, default=None):
        return self._headers.get(field.lower(), default)


def is_ascii(data):
    for byte in data:
        byte = int(byte)
        if byte < 0 or byte >= 128:
            return False
    return True


class AbstractReadOnlyHTTPMessage(HTTPMessage):
    def __init__(self, sio, max_header_len=104856, *args, **kwargs):
        super(AbstractReadOnlyHTTPMessage, self).__init__(*args, *kwargs)
        if max_header_len < 0:
            raise ValueError('max_header_len must be >= 0')
        self._sio = sio  # XXX
        self._reader = DelimitedReader(sio)
        self._max_header_len = max_header_len
        self._headers_read = False
        self._body_reader = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        # do not suppress a potential exception
        return None

    def close(self):
        reader = self._reader
        body_reader = self._body_reader
        self._reader = None
        self._body_reader = None
        if reader is not None:
            reader.close()
        if body_reader is not None:
            body_reader.close()

    def read_start_line(self):
        raise NotImplementedError()

    def read_headers(self):
        if self._headers_read:
            return
        self.read_start_line()
        max_bytes = self._max_header_len
        while True:
            line = self._reader.read_until(b'\r\n', max_bytes=max_bytes)
            if not line:
                # all headers were processes
                break
            self._process_header(line)
        self._headers_read = True

    def _process_header(self, line):
        # print('process_header', line)
        field, value = self._parse_header(line)
        if not is_ascii(field):
            raise ProtocolError('header field name is not ascii', field)
        self.add_header(field.decode('ascii').lower(), value)

    def _parse_header(self, line):
        split = line.split(b':', 1)
        if len(split) < 2:
            # XXX: not necessary a protocol error because we ignore folded
            # headers (multi line headers)
            raise ProtocolError('illegal header line (maybe)', line)
        return split[0], split[1].strip()

    def get_header(self, field, *args, **kwargs):
        self.read_headers()
        return super(AbstractReadOnlyHTTPMessage, self).get_header(field,
                                                                   *args,
                                                                   **kwargs)

    def body(self):
        if self._body_reader is not None:
            return self._body_reader
        self.read_headers()
        # hmm should we check Expect: "100-continue" here?
        cl = int(self.get_header('Content-Length', -1))
        reader = None
        if cl >= 0:
            reader = LimitedReader(self._reader, max_bytes=cl)
        if self.get_header('Transfer-Encoding', b'') == b'chunked':
            reader = ChunkedReader(self._reader)
        if reader is None:
            raise ValueError('cannot handle body')
        self._body_reader = reader
        return reader

    def read(self, count):
        # for convenience
        return self.body().read(count)


class ReadOnlyHTTPResponse(AbstractReadOnlyHTTPMessage):
    def __init__(self, sio, max_status_len=104856, max_header_len=104856,
                 *args, **kwargs):
        super(ReadOnlyHTTPResponse, self).__init__(sio, *args, **kwargs)
        if max_status_len < 0:
            raise ValueError('max_status_len must be >= 0')
        self._max_status_len = max_status_len
        self._status_line_read = False

    def read_start_line(self):
        return self.read_status_line()

    def read_status_line(self):
        if self._status_line_read:
            return
        line = self._reader.read_until(b'\r\n', max_bytes=self._max_status_len)
        split = line.split(b' ')[:2]
        if len(split) < 2:
            raise ProtocolError('illegal status line', line)
        self._http_version = split[0]
        self._status = int(split[1])
        self._status_line_read = True

    def _status_in_range(self, start, end):
        self.read_status_line()
        return start <= self._status <= end

    def is_success(self):
        return self._status_in_range(200, 205)

    def is_client_error(self):
        return self._status_in_range(400, 417) or self._status_in_range(426,
                                                                        426)

    def is_server_error(self):
        return self._status_in_range(500, 505)


class AbstractWriteOnlyHTTPMessage(HTTPMessage):
    def __init__(self, *args, **kwargs):
        super(AbstractWriteOnlyHTTPMessage, self).__init__(*args, **kwargs)
        self._headers_written = False

    def write_start_line(self, writer):
        raise NotImplementedError()

    def _build_header_line(self, field, value):
        return field.encode('ascii') + b': ' + value + b'\r\n'

    def write_headers(self, writer):
        if self._headers_written:
            return
        self.write_start_line(writer)
        for field, value in self.headers().items():
            writer.write(self._build_header_line(field, value))
        writer.write(b'\r\n')
        self._headers_written = True

    def write_body(self, writer, data, bufsize=4096):
        self.write_headers(writer)
        if data is None:
            return
        # user has to make sure that data does not exceed cl etc.
        if hasattr(data, 'read'):
            f = data
        else:
            f = io.BytesIO(data)
        data = f.read(bufsize)
        while data:
            writer.write(data)
            data = f.read(bufsize)


class WriteOnlyHTTPRequest(AbstractWriteOnlyHTTPMessage):
    def __init__(self, method, request_target, *args, **kwargs):
        super(WriteOnlyHTTPRequest, self).__init__(*args, **kwargs)
        self._method = method
        self._request_target = request_target
        self._request_line_written = False

    def write_start_line(self, writer):
        return self.write_request_line(writer)

    def _build_request_line(self):
        return self._method + b' ' + self._request_target + b' HTTP/1.1\r\n'

    def write_request_line(self, writer):
        if self._request_line_written:
            return
        writer.write(self._build_request_line())
        self._request_line_written = True


class ReadOnlyHTTPRequest(AbstractReadOnlyHTTPMessage):
    def __init__(self, sio, max_request_len=104856,
                 max_header_len=104856, *args, **kwargs):
        super(ReadOnlyHTTPRequest, self).__init__(sio, max_header_len=104856,
                                                  *args, **kwargs)
        if max_request_len < 0:
            raise ValueError('max_request_len must be >= 0')
        self._max_request_len = max_request_len
        self._request_line_read = False

    def read_start_line(self):
        return self.read_request_line()

    def read_request_line(self):
        if self._request_line_read:
            return
        line = self._reader.read_until(b'\r\n',
                                       max_bytes=self._max_request_len)
        split = line.split(b' ')
        if len(split) != 3:
            raise ProtocolError('illegal request line', line)
        self._method = split[0].strip()
        self._request_target = split[1].strip()
        self._http_version = split[2].strip()
        self._request_line_read = True


class WriteOnlyHTTPResponse(AbstractWriteOnlyHTTPMessage):
    def __init__(self, status, reason=None, *args, **kwargs):
        super(WriteOnlyHTTPResponse, self).__init__(*args, **kwargs)
        self._status = int_to_bytes(status)
        self._reason = reason
        self._status_line_written = False

    def write_start_line(self, writer):
        return self.write_status_line(writer)

    def _build_status_line(self):
        return b'HTTP/1.1 ' + self._status + b' ' + self._reason + b'\r\n'

    def write_status_line(self, writer):
        if self._status_line_written:
            return
        writer.write(self._build_status_line())
        self._status_line_written = True

    def write_body(self, writer, *args, **kwargs):
        self.write_status_line(writer)
        return super(WriteOnlyHTTPResponse, self).write_body(writer, *args,
                                                             **kwargs)
