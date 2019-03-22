import re

from dumb_http.reader import DelimitedReader, ReadError
from dumb_http.errors import ProtocolError


class ChunkedReader(DelimitedReader):
    chunk_size_re = re.compile(b'^([0-9a-fA-F]+)')

    def __init__(self, *args, **kwargs):
        super(ChunkedReader, self).__init__(*args, **kwargs)
        self._chunk_size = 0
        self._last_chunk_read = False

    def _read(self, count, *args, **kwargs):
        return super(ChunkedReader, self).read(count, *args, **kwargs)

    def _read_chunk_line(self, max_chunk_line_bytes, *args, **kwargs):
        line = self.read_until(b'\r\n', max_bytes=max_chunk_line_bytes, *args,
                               **kwargs)
        if not line:
            raise ProtocolError('empty chunk line', line)
        mo = self.chunk_size_re.search(line)
        if mo is None:
            raise ProtocolError('no chunk size', line)
        chunk_size = int(mo.group(1), 16)
        if chunk_size < 0:
            raise ProtocolError('negative chunk size', line)
        # print('chunk_line', chunk_size, mo.group(1))
        if chunk_size == 0 and mo.group(1) != b'0':
            # 0 size chunks are useless, if not the last chunk
            raise ProtocolError('maybe protocol error (?)', line)
        return chunk_size, chunk_size == 0

    def _read_trailer(self, max_trailer_line_bytes, *args, **kwargs):
        # we ignore all trailer parts (XXX: protocol violation!)
        max_bytes = max_trailer_line_bytes
        while True:
            data = self.read_until(b'\r\n', max_bytes=max_bytes, *args,
                                   **kwargs)
            if not data:
                break

    def read(self, count, max_chunk_line_bytes=104857, *args, **kwargs):
        if self._last_chunk_read:
            # the caller already saw eof (hmm really an exception or b''?)
            raise ReadError('illegal read after last chunk')
        max_bytes = max_chunk_line_bytes
        if not self._chunk_size:
            self._chunk_size, last_chunk = self._read_chunk_line(max_bytes,
                                                                 *args,
                                                                 **kwargs)
            if last_chunk:
                self._last_chunk_read = True
                self._read_trailer(max_bytes, *args, **kwargs)
                return b''
        if self._chunk_size < count:
            count = self._chunk_size
        data = self._read(count, *args, **kwargs)
        if not data and count:
            raise ReadError('EOF in chunk')
        if data:
            self._chunk_size -= len(data)
            if self._chunk_size < 0:
                raise ReadError('read return more than the requested bytes')
            if not self._chunk_size:
                no_data = self.read_until(b'\r\n', max_bytes=max_bytes, *args,
                                          **kwargs)
                if no_data:
                    raise ProtocolError('got data after end of chunk')
        return data


class ChunkedWriter(object):
    @classmethod
    def write(cls, writer, readable, chunk_size=8192):
        # preferred chunk_size (if you want to ensure it,
        # readable should be a BufferedReader)
        count = chunk_size
        while True:
            data = readable.read(count)
            if not data:
                break
            cls._write_chunk(writer, data)
        # last chunk
        cls._write_chunk(writer, b'')
        writer.write('\r\n')


class ChunkedEncoder(object):
    def __init__(self, readable, preferred_chunk_size=8192):
        super(ChunkedEncoder, self).__init__()
        self._readable = readable
        self._preferred_chunk_size = preferred_chunk_size
        self._chunk_buf = bytearray()
        self._last_chunk = False

    def _fill_chunk_buf(self, data):
        chunk_line = "{:X}\r\n".format(len(data)).encode('ascii')
        self._chunk_buf.extend(chunk_line)
        self._chunk_buf.extend(data)
        self._chunk_buf.extend(b'\r\n')

    def _read_from_chunk_buf(self, count):
        data = self._chunk_buf[:count]
        del self._chunk_buf[:count]
        return data

    def read(self, count, *args, **kwargs):
        if self._chunk_buf:
            return self._read_from_chunk_buf(count)
        if self._last_chunk:
            return b''
        data = self._readable.read(self._preferred_chunk_size, *args, **kwargs)
        if not data:
            self._last_chunk = True
        self._fill_chunk_buf(data)
        return self._read_from_chunk_buf(count)
