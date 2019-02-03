class ReadError(Exception):
    def __init__(self, msg):
        self.msg = msg


class BaseReader(object):
    def __init__(self, readable):
        self._readable = readable

    def close(self):
        if self._readable is None:
            # already closed
            return
        readable = self._readable
        self._readable = None
        readable.close()

    def read(self, count):
        if self._readable is None:
            raise ReadError('readable is None (already closed?)')
        if count < 0:
            raise ValueError('count must be non-negative')
        return self._readable.read(count)


class BufReader(BaseReader):
    def __init__(self, *args, **kwargs):
        super(BufReader, self).__init__(*args, **kwargs)
        self._buf = self.makebuf()

    @staticmethod
    def makebuf():
        return bytearray()

    @staticmethod
    def read_from_buf(buf, count):
        # here, a negative count is ok
        if count > len(buf):
            raise ReadError('buffer has not sufficient bytes')
        data = buf[:count]
        del buf[:count]
        return bytes(data)

    @staticmethod
    def slice_buf(buf, buf_or_bytes, i, j):
        buf[i:j] = buf_or_bytes

    @staticmethod
    def prepend_buf(buf, buf_or_bytes):
        BufReader.slice_buf(buf, buf_or_bytes, 0, 0)

    @staticmethod
    def append_buf(buf, buf_or_bytes):
        buf.extend(buf_or_bytes)

    def read(self, count, ignore_buf=False):
        buf_len = len(self._buf)
        if buf_len and not ignore_buf:
            if count > buf_len:
                count = buf_len
            return self.read_from_buf(self._buf, count)
        return super(BufReader, self).read(count)


class BufferedReader(BufReader):
    def _fill_buf(self, count, bufsize):
        count -= len(self._buf)
        while count > 0:
            if bufsize > count:
                bufsize = count
            data = super(BufferedReader, self).read(bufsize, ignore_buf=True)
            if not data:
                raise ReadError('early EOF')
            self.prepend_buf(self._buf, data)
            count -= len(data)

    def read(self, count, bufsize=4096):
        """Returns exactly count bytes.

        This might block. An early EOF results in a ReadError.
        The data is read from the underlying readable in bufsize
        bytes chunks (the last read might be smaller).

        """
        self._fill_buf(count, bufsize)
        return self.read_from_buf(self._buf, count)


class DelimitedReader(BufReader):
    def _read(self, bufsize):
        return self.read(bufsize)

    def read_until_iter(self, delimiter, bufsize=4096, discard=True,
                        max_bytes=None):
        off = -1
        delim_len = len(delimiter)
        bytes_read = 0
        search_buf = self.makebuf()
        while off == -1:
            if len(search_buf) >= delim_len:
                yield self.read_from_buf(search_buf, -(delim_len - 1))
            data = self._read(bufsize)
            if not data:
                raise ReadError('early EOF (delimiter not read)')
            bytes_read += len(data)
            if bytes_read > max_bytes:
                raise ReadError('max_bytes exceeded')
            search_buf.extend(data)
            off = search_buf.find(delimiter)
        data = self.read_from_buf(search_buf, off)
        if discard:
            self.read_from_buf(search_buf, delim_len)
        self.prepend_buf(self._buf, search_buf)
        yield data

    def read_until(self, delimiter, bufsize=4096, discard=True,
                   max_bytes=None):
        buf = self.makebuf()
        for data in self.read_until_iter(delimiter, bufsize, discard,
                                         max_bytes):
            buf.extend(data)
        return self.read_from_buf(buf, len(buf))


class LimitedReader(BufReader):
    def __init__(self, *args, **kwargs):
        self._remaining_bytes = kwargs.pop('max_bytes')
        super(LimitedReader, self).__init__(*args, **kwargs)

    def read(self, count, *args, **kwargs):
        if count > self._remaining_bytes:
            count = self._remaining_bytes
        data = super(LimitedReader, self).read(count, *args, **kwargs)
        self._remaining_bytes -= len(data)
        return data
