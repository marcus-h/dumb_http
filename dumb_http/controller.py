from inspect import signature, Parameter

from dumb_http.router import (AbstractResource, Route, RouteBinder,
                              RegexPathMatcher, RegexQueryMatcher,
                              NamedMatchesAccessor)
from dumb_http.uri import URI


# opts = {'encoding': 'utf-8', 'percent_decode'}
# route('/foo/bar').to(ControllerA, Controller.foo).with(**opts)
# route('/foo/<bar>').to(ControllerA, Controller.foo).with(**opts)
# route('/foo/<bar>[^x]+').to(ControllerA, Controller.no_x).with(**opts)

class ControllerResource(AbstractResource):
    def __init__(self, controller_factory, controller_meth, *args, **kwargs):
        super(AbstractResource, self).__init__()
        self._controller_factory = controller_factory
        self._controller_meth = controller_meth
        self._args = args
        self._kwargs = kwargs

    def serve(self, rrrw, matches):
        controller = self._create_controller(rrrw, matches)
        return self._call_controller_meth(controller)

    def _create_controller(self, rrrw, matches):
        return self._controller_factory(rrrw, matches, *self._args,
                                        **self._kwargs)

    def _call_controller_meth(self, controller):
        args, kwargs = self._bind_named_matches(controller)
        return self._controller_meth(*args, **kwargs)

    def _bind_named_matches(self, controller):
        sig = signature(self._controller_meth)
        named_matches = controller.nm.as_dict()
        bindings = {}
        kwargs = {}
        use_kwargs = False
        is_first = True
        bindable = [Parameter.POSITIONAL_OR_KEYWORD, Parameter.KEYWORD_ONLY]
        for parameter in sig.parameters.values():
            name = parameter.name
            kind = parameter.kind
            # note: this is always False if named_matches' keys were not
            # decoded
            parameter_exists = name in named_matches
            if kind in bindable:
                if parameter_exists:
                    value = named_matches[name]
                    if not value and parameter.default != Parameter.empty:
                        # XXX: instead of "not value" we should check for
                        # no_match_value (because no_match_value can
                        # potentially evaluate to True)... :/
                        value = parameter.default
                    bindings[name] = value
                elif parameter.default == Parameter.empty:
                    if not is_first:
                        msg = b'cannot bind parameter\n'
                        controller.reply(500, msg)
                        raise ValueError(msg)
                    # assumption: no static method or plain function etc.
                    bindings[name] = controller
            elif kind == Parameter.VAR_KEYWORD:
                use_kwargs = True
            elif kind == Parameter.POSITIONAL_ONLY:
                # we could handle this, but I'm too lazy for now...
                # (very unlikely that this will happen at all - if it happens
                # just wrap your method in some plain python method...)
                msg = b'cannot bind positional only parameter\n'
                controller.reply(500, msg)
                raise ValueError(msg.decode('ascii'))
            is_first = False
        if use_kwargs:
            bindings.update(kwargs)
        try:
            bound = sig.bind(**bindings)
        except TypeError:
            controller.reply(500, b'unable to bind parameters\n')
            raise
        return bound.args, bound.kwargs


class ControllerRouteBinder(RouteBinder):
    def to(self, controller_factory, controller_meth, *args, **kwargs):
        resource = ControllerResource(controller_factory, controller_meth)
        return super(ControllerRouteBinder, self).to(resource)


# using an ascii encoding by default is a bit inconsistent with the rest of
# this module (usually everything is bytes by default) - but using a default
# encoding and str is more convenient for now
def route(method_description, path_query_fragment_description,
          encoding='ascii'):
    matchers = []
    path = URI.parse_path(path_query_fragment_description, encoding=encoding)
    # for now a path must be present
    if path is None:
        raise ValueError('path required')
    matchers.append(RegexPathMatcher(method_description, path,
                                     encoding=encoding))
    query = URI.parse_query(path_query_fragment_description, encoding=encoding)
    if query is not None:
        matchers.append(RegexQueryMatcher(query, encoding=encoding))
    route = Route(*matchers)
    return ControllerRouteBinder(route)


class ControllerBase(object):
    def __init__(self, rrrw, matches):
        super(ControllerBase, self).__init__()
        self.rrrw = rrrw
        self._matches = matches
        self._named_matches = None

    def _get_nm(self):
        if self._named_matches is None:
            named_matches = self._accumulate_named_matches()
            self._named_matches = NamedMatchesAccessor(named_matches)
        return self._named_matches

    nm = property(_get_nm)

    def _accumulate_named_matches(self):
        named_matches = {}
        for match_result in self._matches:
            named_matches.update(match_result.named_matches)
        return named_matches

    def read(self, count):
        return self.rrrw.request.body().read(count)

    def reply(self, status=None, data=None, reason=b'unspec', **headers):
        if status is not None and status != 100:
            headers['Connection'] = b'close'
        self.rrrw.reply(status, data, reason, **headers)
        return 0
#        if data is not None:
#            if hasattr(data, 'name'):
#                cl = os.stat(data.name).st_size
#            else:
#                cl = len(data)
#            resp.add_header('Content-Length', int_to_bytes(cl))
#        resp.write_body(self._request._sio, data)
#        # closes the sio
#        self._request.close()
#        return 0

    def no_such_route(self):
        self.reply(404, b'no such route\n')


class EncodingAwareController(ControllerBase):
    def __init__(self, rrrw, matches, encoding):
        self._encoding = encoding  # do this first
        super(EncodingAwareController, self).__init__(rrrw, matches)

    def _accumulate_named_matches(self, *args, **kwargs):
        named_matches = super(EncodingAwareController,
                              self)._accumulate_named_matches()
        res = {}
        for key, value in named_matches.items():
            key = self._decode(key, True)
            value = self._decode(value, False)
            res[key] = value
        return res

    def _decode(self, key_or_value, is_key):
        # subclasses might do more clever things here...
        if hasattr(key_or_value, 'decode'):
            try:
                key_or_value = key_or_value.decode(self._encoding)
            except ValueError as e:
                kv = str(key_or_value)
                enc = self._encoding
                msg = "Unable to decode {} using {} encoding".format(kv, enc)
                self.reply(400, msg)
                raise e
        return key_or_value

    def reply(self, status=None, data=None, *args, **kwargs):
        if hasattr(data, 'encode'):
            data = data.encode(self._encoding)
        return super(EncodingAwareController, self).reply(status, data, *args,
                                                          **kwargs)

    @classmethod
    def factory(cls, encoding, **create_kwargs):
        def _create(*args, **kwargs):
            kwargs['encoding'] = encoding
            kwargs.update(create_kwargs)
            return cls(*args, **kwargs)

        return _create
