import re

from dumb_http.http import RequestReaderResponseWriter
from dumb_http.server import PeriodicServer
from dumb_http.uri import URI
from dumb_http.util import Properties, to_bytes


# some of these class names (and maybe parts of the implementation?) are
# inspired by rails' actionpack (more precisely, action_dispatch). However,
# some ideas, like the RegexQueryMatcher, are "novel"...


class Route(object):
    def __init__(self, *matchers):
        super(Route, self).__init__()
        self._matchers = matchers

    def matches(self, request, diagnostic=None):
        match_results = []
        for matcher in self._matchers:
            try:
                match_result = matcher.matches(request, diagnostic)
            except UnicodeDecodeError:
                match_result = None
            if match_result is None:
                return None
            match_results.append(match_result)
        return match_results


class MatchDiagnostic(object):
    def __init__(self, request):
        super(MatchDiagnostic, self).__init__()
        self._request = request
        self._messages = []
        self._cur_messages = {}

    def info(self, matcher, msg):
        self._append_cur_msg('info', matcher, msg)

    def error(self, matcher, msg):
        self._append_cur_msg('error', matcher, msg)

    def push(self):
        if not self._cur_messages:
            return
        self._cur_messages.setdefault('info', [])
        self._cur_messages.setdefault('error', [])
        self._messages.append(self._cur_messages)
        self._cur_messages = {}

    def errors(self):
        return self._collect('error')

    def infos(self):
        return self._collect('info')

    def _collect(self, level):
        messages = []
        for msg_dict in self._messages:
            msgs = msg_dict[level]
            if msgs:
                messages.append(msgs)
        return messages

    def _append_cur_msg(self, level, matcher, msg):
        if not self._interested_in(matcher):
            return
        self._cur_messages.setdefault(level, []).append(msg)

    def _interested_in(self, matcher):
        # we are not interested in a RegexPathMatcher (subclasses
        # can override this...) (it would be too noisy...)
        return not isinstance(matcher, RegexPathMatcher)


class AbstractMatcherBase(object):
    def __init__(self, encoding=None, percent_decode=True,
                 no_match_value=None):
        super(AbstractMatcherBase, self).__init__()
        self._encoding = encoding
        self._percent_decode = percent_decode
        self._no_match_value = no_match_value

    def _to_bytes(self, value):
        return to_bytes(value, self._encoding)

    def _decode_or_keep(self, value):
        if self._encoding is not None:
            value = value.decode(self._encoding)
        return value

    def matches(self, request, diagnostic):
        raise NotImplementedError()


class RegexPathMatcher(AbstractMatcherBase):
    def __init__(self, method_description, path_description,
                 encoding=None, percent_decode=True, no_match_value=None):
        super(RegexPathMatcher, self).__init__(encoding, percent_decode,
                                               no_match_value)
        self._method_re = self._build_method_regex(method_description)
        path_descr = path_description
        self._component_regexes = self._build_component_regexes(path_descr)

    def _build_method_regex(self, method_description):
        method_description = self._to_bytes(method_description)
        method_description = b'^' + method_description + b'$'
        method_description = self._decode_or_keep(method_description)
        return re.compile(method_description)

    def _build_component_regexes(self, path_description):
        component_regexes = []
        for component in path_description.components:
            component_re = self._build_component_regex(component)
            component_regexes.append(component_re)
        return component_regexes

    named_component_re = re.compile(b'^(?P<named_part><[^>]+>)')

    def _build_component_regex(self, component):
        component = self._to_bytes(component)
        mo = self.named_component_re.search(component)
        if mo is not None:
            if mo.group('named_part') == component:
                component += b'.+'
            component = b'(?P' + component + b')'
        component = b'^' + component + b'$'
        component = self._decode_or_keep(component)
        return re.compile(component)

    def matches(self, request, diagnostic):
        path = URI.parse_path(request._request_target, encoding=self._encoding,
                              percent_decode=self._percent_decode)
        if path is None:
            raise ValueError('illegal path')
        if len(self._component_regexes) != len(path.components):
            return None
        # request._method is a bytes
        method = self._decode_or_keep(request._method)
        mo = self._method_re.search(method)
        if mo is None:
            return None
        matches = []
        named_matches = {}
        for comp_re, comp in zip(self._component_regexes, path.components):
            mo = comp_re.search(comp)
            if mo is None:
                if diagnostic is not None:
                    comp = self._to_bytes(comp)
                    pattern = self._to_bytes(comp_re.pattern)
                    msg = b"comp '%s' does not match '%s'" % (comp, pattern)
                    diagnostic.error(self, msg)
                return None
            matches.append(comp)
            named_matches.update(mo.groupdict(self._no_match_value))
        return MatchResult(matches, named_matches)


class QueryRegex(**Properties.define(
            'is_optional', 'key_pattern', 'value_pattern'
        )):
    def __init__(self, key_pattern, value_pattern, no_match_value, to_bytes,
                 decode_or_keep):
        super(QueryRegex, self).__init__()
        data = self._build_regexes(key_pattern, value_pattern, to_bytes,
                                   decode_or_keep)
        self._key_re, self._value_re, self._is_optional = data
        self._no_match_value = no_match_value

    def _prop_key_pattern_get(self):
        return self._key_re.pattern

    def _prop_value_pattern_get(self):
        return self._value_re.pattern

    optional_re = re.compile(rb'^\((?P<key_pattern>.+)\)\?$')

    def _build_regexes(self, key_pattern, value_pattern, to_bytes,
                       decode_or_keep):
        key_pattern = to_bytes(key_pattern)
        value_pattern = to_bytes(value_pattern)
        mo = self.optional_re.search(key_pattern)
        if mo is not None:
            key_pattern = mo.group('key_pattern')
        key_pattern = b'^' + key_pattern + b'$'
        value_pattern = b'^' + value_pattern + b'$'
        key_pattern = decode_or_keep(key_pattern)
        value_pattern = decode_or_keep(value_pattern)
        return (re.compile(key_pattern), re.compile(value_pattern),
                mo is not None)

    def match(self, key, value):
        mo_key = self._key_re.search(key)
        if mo_key is None:
            return (False, {}, {})
        mo_value = self._value_re.search(value)
        if mo_value is None:
            return (False, {}, {})
        no_match_value = self._no_match_value
        return (True, mo_key.groupdict(no_match_value),
                mo_value.groupdict(no_match_value))


class RegexQueryMatcher(AbstractMatcherBase):
    def __init__(self, query_description, defs_required=True,
                 only_defined=True, encoding=None, percent_decode=True,
                 no_match_value=None):
        super(RegexQueryMatcher, self).__init__(encoding, percent_decode,
                                                no_match_value)
        self._defs_required = defs_required
        self._only_defined = only_defined
        self._query_regexes = self._build_query_regexes(query_description)

    def _build_query_regexes(self, query_description):
        query_regexes = []
        for key_pattern, value_pattern in query_description.as_kv.items():
            query_regex = QueryRegex(key_pattern, value_pattern,
                                     self._no_match_value, self._to_bytes,
                                     self._decode_or_keep)
            query_regexes.append(query_regex)
        return query_regexes

    def _match_defined(self, query, named_matches, diagnostic):
        if not self._defs_required:
            return True
        for query_regex in self._query_regexes:
            def_found = False
            for key, value in query.as_kv.items():
                is_match, key_nm, value_nm = query_regex.match(key, value)
                if is_match:
                    named_matches[key] = value
                    named_matches.update(key_nm)
                    named_matches.update(value_nm)
                    def_found = True
                    break
            if not def_found and not query_regex.is_optional:
                if diagnostic is not None:
                    key_pattern = self._to_bytes(query_regex.key_pattern)
                    value_pattern = self._to_bytes(query_regex.value_pattern)
                    msg = b"Missing query parameter: key: '%s', val: '%s'" % (
                                key_pattern, value_pattern)
                    diagnostic.error(self, msg)
                return False
        return True

    def _match_actual(self, query, named_matches, diagnostic):
        if not self._only_defined:
            return True
        for key, value in query.as_kv.items():
            if key in named_matches:
                # already matched by _match_defined
                continue
            act_found = False
            for query_regex in self._query_regexes:
                is_match, key_nm, value_nm = query_regex.match(key, value)
                if is_match:
                    named_matches[key] = value
                    named_matches.update(key_nm)
                    named_matches.update(value_nm)
                    act_found = True
                    break
            if not act_found:
                if diagnostic:
                    key = self._to_bytes(key)
                    value = self._to_bytes(value)
                    msg = b"Unexpected query parameter: '%s'='%s'" % (key,
                                                                      value)
                    diagnostic.error(self, msg)
                return False
        return True

    def matches(self, request, diagnostic):
        query = URI.parse_query(request._request_target,
                                encoding=self._encoding,
                                percent_decode=self._percent_decode)
        if query is None:
            raise ValueError('illegal query')
        named_matches = {}
        if not self._match_defined(query, named_matches, diagnostic):
            return None
        if not self._match_actual(query, named_matches, diagnostic):
            return None
        return MatchResult(named_matches=named_matches)


class MatchResult(**Properties.define(
            'matches', 'named_matches'
        )):
    def __init__(self, matches=None, named_matches=None):
        # using a *matches, **named_matches signature does not work in
        # general because a key in named_matches could be a bytes instance
        if matches is None:
            matches = []
        if named_matches is None:
            named_matches = {}
        self._matches = matches
        self._named_matches = named_matches


class NamedMatchesAccessor(object):
    def __init__(self, named_matches):
        self._named_matches = named_matches

    def __getattr__(self, name):
        named_matches = self._named_matches
        if name not in named_matches:
            raise AttributeError()
        val = named_matches[name]
        setattr(self, name, val)
        return val

    def as_dict(self):
        return dict(self._named_matches)


class AbstractResource(object):
    def serve(self, rrrw, matches):
        raise NotImplementedError()


class Router(object):
    def __init__(self, *route_binders):
        super(Router, self).__init__()
        self._route_binders = route_binders

    def _makefile(self, sock, *args, **kwargs):
        return sock.makefile(*args, **kwargs)

    def _create_rrrw(self, sio):
        return RequestReaderResponseWriter(sio)

    def route(self, sock):
        with self._makefile(sock, 'rwb', buffering=0) as sio:
            rrrw = self._create_rrrw(sio)
            return self._route(rrrw)

    def _route(self, rrrw):
        # XXX: hmm should we explicitly close the rrrw? (actually, so
        # far it only operates on the sio (which is closed by one of our
        # callers) - maybe it acquire more resources, which _have_ to
        # be closed in the future? Reconsider this.
        rrrw.request.read_request_line()
        rrrw.request.read_headers()
        diagnostic = MatchDiagnostic(rrrw.request)
        for route_binder in self._route_binders:
            matches = route_binder.matches(rrrw.request, diagnostic)
            if matches is not None:
                return route_binder._resource.serve(rrrw, matches)
            diagnostic.push()
        return self._no_such_route(rrrw, diagnostic)

    def _no_such_route(self, rrrw, diagnostic):
        errors = diagnostic.errors()
        if not errors:
            rrrw.reply(404, b'no such route\n')
            return
        msg = bytearray()
        for error_list in errors:
            if msg:
                msg.extend(b'or\n')
            msg.extend(b', '.join(error_list))
            msg.extend(b'\n')
        msg[:0] = b'Bad request - no route found\n'
        rrrw.reply(400, msg)
        return 0


class RouteBinder(object):
    def __init__(self, route, resource=None):
        super(RouteBinder, self).__init__()
        self._route = route
        self._resource = resource

    def to(self, resource):
        if self._resource is not None:
            # hmm probably an error
            raise ValueError('route already bound')
        self._resource = resource
        return self

    def matches(self, request, diagnostic):
        return self._route.matches(request, diagnostic)


class RouterBasedHTTPServer(PeriodicServer):
    def __init__(self, host, port, router, **server_options):
        super(RouterBasedHTTPServer, self).__init__(port, host,
                                                    **server_options)
        self._router = router

    def handle_request(self, sock):
        print('in handle_request')
        return self._router.route(sock)
