"""Provides URI stuff.

Note: only URIs with an authority part are supported.

"""
import re
import sys

from dumb_http.util import Properties


uri_properties = ('scheme', 'authority', 'userinfo', 'host', 'port', 'path',
                  'query', 'fragment')


class RawURI(**Properties.define(*uri_properties)):
    path_query_fragment_pat = (
        b'(?P<path>/[^?#]*)?'
        b'(?:\\?(?P<query>[^#]*))?'
        b'(?:#(?P<fragment>.*))?')

    path_query_fragment_re = re.compile(
        b'^'
        + path_query_fragment_pat
        + b'$')

    uri_re = re.compile(
        b'^'
        b'(?P<scheme>[^:]+)://'
        b'(?P<authority>'
        b'(?:(?P<userinfo>[^@]+)@)?'
        b'(?P<host>[^/?#:]+)'
        b'(?::(?P<port>[0-9]*))?'
        b')'  # authority group closed
        + path_query_fragment_pat
        + b'$')

    def __init__(self, scheme, authority, userinfo, host, port, path, query,
                 fragment, encoding=None):
        super(RawURI, self).__init__()
        self._scheme = scheme
        self._authority = authority
        self._userinfo = userinfo
        self._host = host
        self._port = port
        self._path = path
        self._query = query
        self._fragment = fragment
        self._encoding = encoding

    @classmethod
    def parse(cls, uri, encoding=None, empty_value=None):
        components = cls._parse_value(cls.uri_re, uri, encoding, empty_value)
        if components is None:
            return None
        return RawURI(*components, encoding)

    @classmethod
    def _parse_value(cls, parse_re, value, encoding, empty_value):
        if encoding is not None:
            value = value.encode(encoding)
        mo = parse_re.search(value)
        if mo is None:
            return None
        return cls.sanitize_components(*mo.groups(), empty_value=empty_value)

    @classmethod
    def sanitize_components(cls, *components, empty_value=None):
        def sanitize(component):
            if not component:
                return empty_value
            return component

        return [sanitize(component) for component in components]


class DecodingAwareURI(**Properties.define(
            'raw_uri', *uri_properties, use_cls_prop_get=True
        )):
    def __init__(self, raw_uri, percent_decode, decode):
        super(DecodingAwareURI, self).__init__()
        self._raw_uri = raw_uri
        self._percent_decode = percent_decode
        self._decode = decode

    def decode_value(self, value, percent_decode=None, decode=None,
                     encoding=None):
        # print(decode, self._decode, self.raw_uri._encoding)
        if value is None:
            return value
        if percent_decode is None:
            percent_decode = self._percent_decode
        if decode is None:
            decode = self._decode
        if encoding is None:
            encoding = self.raw_uri._encoding
        if percent_decode:
            value = self.percent_decode(value, encoding)
        if decode and encoding is not None:
            value = value.decode(encoding)
        return value

    percent_decode_re = re.compile(b'%(?P<hex>[0-9a-fA-F]{2})')

    @classmethod
    def percent_decode(cls, value, encoding=None):
        def hex_to_byte(mo):
            return chr(int(mo.group('hex'), 16)).encode(encoding)

        if encoding is None:
            encoding = 'ascii'
        return cls.percent_decode_re.sub(hex_to_byte, value)

    # just for the properties (cannot be called on an instance!)
    def _prop_get(prop):
        def _get(self):
            value = getattr(self.raw_uri, prop)
            return self.decode_value(value)

        return _get

    def _prop_raw_uri_get(self):
        return self._raw_uri


class PathAndQueryAwareURI(DecodingAwareURI):
    def __init__(self, raw_uri, percent_decode=True, decode=True):
        super(PathAndQueryAwareURI, self).__init__(raw_uri, percent_decode,
                                                   decode)
        self._path = None
        self._query = None

    def _prop_path_get(self):
        if self._path is None:
            self._path = Path(self.raw_uri.path, self.decode_value)
        return self._path

    path = property(_prop_path_get)

    def _prop_query_get(self):
        if self._query is None:
            self._query = Query(self.raw_uri.query, self.decode_value)
        return self._query

    query = property(_prop_query_get)


class Path(**Properties.define(
            'path', 'components', use_cls_prop_get=True
        )):
    def __init__(self, path, decode_value):
        super(Path, self).__init__()
        self._path = path
        self._components = None
        self._decode_value = decode_value

    def _prop_get(prop):
        def _get(self):
            value = getattr(self, '_{}'.format(prop))
            return self._decode_value(value)

        return _get

    def _prop_components_get(self):
        if self._components is None:
            # self._path is bytes
            path = self._path
            if path:
                path = path.strip(b'/')
            if not path:
                self._components = ()
                return self._components
            # ok... we have components
            comps = path.split(b'/')
            self._components = tuple([self._decode_value(c) for c in comps])
        return self._components


class Query(**Properties.define(
            'as_kv'
            )):
    def __init__(self, query, decode_value):
        super(Query, self).__init__()
        self._query = query
        self._kv_dict = None
        self._decode_value = decode_value

    def _prop_get(prop):
        def _get(self):
            value = getattr(self, '_{}'.format(prop))
            return self._decode_value(value)

        return _get

    def _prop_as_kv_get(self):
        # hmm... the dict itself is mutable...
        if self._kv_dict is None:
            query = self._query
            if query:
                query = query.strip(b'&')
            self._kv_dict = {}
            if not query:
                return self._kv_dict
            # XXX: if a key appears multiple times the last one is used
            for kv_pair in query.split(b'&'):
                if b'=' not in kv_pair:
                    # silently skip non pairs
                    continue
                key, value = kv_pair.split(b'=', 1)
                key = self._decode_value(key)
                value = self._decode_value(value)
                self._kv_dict[key] = value
        return self._kv_dict


class URI(PathAndQueryAwareURI):
    def __init__(self, raw_uri):
        super(URI, self).__init__(raw_uri)

    @classmethod
    def parse(cls, *args, **kwargs):
        raw_uri = RawURI.parse(*args, **kwargs)
        if raw_uri is None:
            return None
        return URI(raw_uri)

    @classmethod
    def _parse_path_query_fragment(cls, path_query_fragment, encoding=None,
                                   percent_decode=True, empty_value=None):
        if encoding is not None:
            path_query_fragment = path_query_fragment.encode(encoding)
        uri = b'http://localhost/' + path_query_fragment
        if encoding is not None:
            # uarghs
            uri = uri.decode(encoding)
        uri = cls.parse(uri, encoding=encoding, empty_value=empty_value)
        if uri is None:
            return (None, None, None)
        return uri.path, uri.query, uri.fragment

    @classmethod
    def parse_path(cls, path_query_fragment, encoding=None,
                   percent_decode=True, empty_value=None):
        path, _, _ = cls._parse_path_query_fragment(path_query_fragment,
                                                    encoding,
                                                    percent_decode,
                                                    empty_value)
        return path

    @classmethod
    def parse_query(cls, path_query_fragment, encoding=None,
                    percent_decode=True, empty_value=None):
        _, query, _ = cls._parse_path_query_fragment(path_query_fragment,
                                                     encoding,
                                                     percent_decode,
                                                     empty_value)
        return query


percent_encode_re = re.compile(br'(?P<reserved>[:/?#[\]@!$&\'()*+,;=])')


def percent_encode(value, encoding=None):
    def res_byte_to_hex(mo):
        return "%{:02X}".format(ord(mo.group('reserved'))).encode(encoding)

    if encoding is None:
        encoding = 'ascii'
    return percent_encode_re.sub(res_byte_to_hex, value)


if __name__ == '__main__':
    #    uri = URI.parse(sys.argv[1].encode('utf-8'))
    #    print(uri.serialize(percent_encode=True))
    #    print(URI.parse_path(b'#y'))
    #    raw_uri = RawURI.parse(sys.argv[1].encode('utf-8'))
    #    if raw_uri is None:
    #        sys.exit('parse error')
    #    print(raw_uri.path)
    #    uri = PathAndQueryAwareURI(RawURI.parse(sys.argv[1].encode('utf-8')))
    #    uri = URI.parse(sys.argv[1].encode('utf-8'))
    #    uri = URI.parse(sys.argv[1], encoding='utf-8')
    #    if uri is None:
    #        sys.exit('parse error')
    #    print(uri.z)
    #    print(uri.path.components)
    #    print(uri.query.as_kv)
    path = URI.parse_path(sys.argv[1], encoding='utf-8')
    print(path.components)
