"""Provides various classes in order to work with CMSGs/ancillary data.

Use these classes if one of your routes expects certain CMSGs or if
your client wishes to send certain CMSGs.

For examples, have a look at
examples/rt_srv_cmsg_unix.py
examples/clnt_ex_cmsg_unix.py
examples/rt_srv_cmsg_tcp.py
"""

import socket
import struct

from dumb_http.router import (AbstractMatcherBase, MatchResult,
                              Router as RouterBase)
from dumb_http.controller import route as base_route
from dumb_http.http import (Request as RequestBase, get as base_get,
                            post as base_post)
from dumb_http.util import Properties


# TODO: This whole module needs a bit more love (split it into a package?)

# FIXME: a server can only receive CMSGs and a client can only send CMSGs
#        (just because this is enough for our current use case)


class MsgHdr(**Properties.define('flags', 'address', 'cmsgs')):
    def __init__(self, flags, address, cmsgs):
        super(MsgHdr, self).__init__()
        self._flags = flags
        self._address = address
        self._cmsgs = cmsgs

    def discard(self):
        cmsgs = self._cmsgs
        while cmsgs:
            cmsgs.pop().discard


class AncillaryDataRecorder(object):
    def __init__(self, controllen, record=True, processor=None, one_shot=True):
        super(AncillaryDataRecorder, self).__init__()
        self._controllen = controllen
        self._record = record
        self.records = []
        if processor is None:
            processor = AncillaryDataProcessor()
        self._processor = processor
        self._one_shot = one_shot

    def is_one_shot(self):
        return self._one_shot

    def is_recording(self):
        return self._record

    def start(self, controllen=None, one_shot=None):
        self._record = True
        if controllen is not None:
            self._controllen = controllen
        if one_shot is not None:
            self._one_shot = one_shot

    def stop(self):
        self._record = False

    def record(self, msg_flags, address, *raw_data):
        if not self.is_recording():
            if raw_data:
                # this should never happen because if we are not recording
                # controllen returns 0 (but better safe than sorry)
                raise RuntimeError('not recording but raw_data present')
            return
        cmsgs = []
        for raw_tuple in raw_data:
            cmsg = self._processor.parse(*raw_tuple)
            cmsgs.append(cmsg)
        self.records.append(MsgHdr(msg_flags, address, cmsgs))
        if self.is_one_shot():
            self.stop()

    def controllen(self):
        if not self.is_recording():
            return 0
        return self._controllen

    def discard(self):
        records = self.records
        while records:
            msghdr = records.pop()
            for cmsg in msghdr.cmsgs:
                cmsg.discard()


class CMSG(object):
    def __init__(self, cmsg_level, cmsg_type, data):
        self.level = cmsg_level
        self.type = cmsg_type
        self.data = data

    def discard(self):
        self.data = None


class CMSGRawProcessor(object):
    def serialize(self, cmsg):
        return cmsg.level, cmsg.type, self._serialize_data(cmsg.data)

    def _serialize_data(self, data):
        # data is supposed to be a tuple/list
        data = self._serialize_data_prepare_data(data)
        return struct.pack(self._serialize_data_format(data), *data)

    def _serialize_data_format(self, data):
        return "{}s".format(len(data))

    def _serialize_data_prepare_data(self, data):
        return data

    def parse(self, cmsg_level, cmsg_type, data):
        parsed_data = self._parse_data(data)
        return CMSG(cmsg_level, cmsg_type, parsed_data)

    def _parse_data(self, data):
        # data is supposed to be a bytes
        parse_format = self._parse_data_format(data)
        data = self._parse_data_prepare_data(parse_format, data)
        return struct.unpack(parse_format, data)

    def _parse_data_format(self, data):
        return self._serialize_data_format(data)

    def _parse_data_prepare_data(self, parse_format, data):
        # this is needed in order to deal with a truncated message
        num_bytes = struct.calcsize(parse_format)
        return data[:num_bytes]


class CMSG_SCM_RIGHTS(CMSG):
    def __init__(self, fobjs):
        super(CMSG_SCM_RIGHTS, self).__init__(socket.SOL_SOCKET,
                                              socket.SCM_RIGHTS, fobjs)

    def discard(self):
        for fobj in self.data:
            fobj.close()
        super(CMSG_SCM_RIGHTS, self).discard()


class CMSG_SCM_RIGHTS_Processor(CMSGRawProcessor):
    def _serialize_data_prepare_data(self, fobjs):
        return [fobj.fileno() for fobj in fobjs]

    def _serialize_data_format(self, fds):
        return self.serialize_data_format(len(fds))

    @classmethod
    def serialize_data_format(cls, num_fds):
        return "{}i".format(num_fds)

    @classmethod
    def bufsize(cls, num_fds):
        return struct.calcsize(cls.serialize_data_format(num_fds))

    def parse(self, cmsg_level, cmsg_type, data, mode='rb'):
        fobjs = [open(fd, mode) for fd in self._parse_data(data)]
        return CMSG_SCM_RIGHTS(fobjs)

    def _parse_data_format(self, data):
        sizeof_int = struct.calcsize('i')
        num_fds = int((len(data) - (len(data) % sizeof_int)) / sizeof_int)
        return "{}i".format(num_fds)


_PROCESSOR_MAPPINGS = {
    socket.SOL_SOCKET: {
        socket.SCM_RIGHTS: CMSG_SCM_RIGHTS_Processor()
    }
}


class AncillaryDataProcessor(object):
    def __init__(self, fallback_processor=None, extra_mappings=None):
        super(AncillaryDataProcessor, self).__init__()
        if fallback_processor is None:
            fallback_processor = CMSGRawProcessor()
        self._fallback_processor = fallback_processor
        self._mappings = {}
        self._mappings.update(_PROCESSOR_MAPPINGS)
        if extra_mappings is not None:
            self._mappings.update(extra_mappings)

    def _processor(self, cmsg_level, cmsg_type):
        return self._mappings.get(cmsg_level, {}).get(cmsg_type,
                                                      self._fallback_processor)

    def serialize(self, *cmsgs):
        data = []
        for cmsg in cmsgs:
            processor = self._processor(cmsg.level, cmsg.type)
            data.append(processor.serialize(cmsg))
        return data

    def parse(self, cmsg_level, cmsg_type, cmsg_data):
        processor = self._processor(cmsg_level, cmsg_type)
        return processor.parse(cmsg_level, cmsg_type, cmsg_data)


class CMSGTemplate(**Properties.define(
            'attr_name', 'level', 'type', 'data_len', 'receive_num'
        )):
    def __init__(self, attr_name, cmsg_level, cmsg_type, data_len,
                 receive_num=None):
        super(CMSGTemplate, self).__init__()
        self._attr_name = attr_name
        self._level = cmsg_level
        self._type = cmsg_type
        self._data_len = data_len
        self._receive_num = receive_num

    def space(self):
        return socket.CMSG_SPACE(self._data_len)

    def _level_and_type_matches(self, cmsg):
        return self._level == cmsg.level and self._type == cmsg.type

    def _data_matches(self, cmsg):
        return self._data_len == len(cmsg.data)

    def matches(self, cmsg, receive_num):
        r_num = self._receive_num
        return ((r_num is None or r_num == receive_num)
                and self._level_and_type_matches(cmsg)
                and self._data_matches(cmsg))


class CMSG_SCM_RIGHTS_Template(CMSGTemplate):
    def __init__(self, attr_name, num_fds, receive_num=None):
        bufsize = CMSG_SCM_RIGHTS_Processor.bufsize(num_fds)
        super(CMSG_SCM_RIGHTS_Template, self).__init__(attr_name,
                                                       socket.SOL_SOCKET,
                                                       socket.SCM_RIGHTS,
                                                       bufsize, receive_num)
        self._num_fds = num_fds

    def _data_matches(self, cmsg):
        return self._num_fds == len(cmsg.data)


class CMSGTemplateMatcher(AbstractMatcherBase):
    def __init__(self, *templates, encoding=None, percent_decode=True,
                 no_match_value=None):
        super(CMSGTemplateMatcher, self).__init__(encoding, percent_decode,
                                                  no_match_value)
        self._templates = templates

    def matches(self, request, diagnostic):
        matches = []
        named_matches = {}
        num_cmsgs = 0
        for receive_num, msghdr in enumerate(request.recorder.records):
            cmsgs = msghdr.cmsgs
            num_cmsgs += len(cmsgs)
            for cmsg in cmsgs:
                found = False
                for template in self._templates:
                    if template.matches(cmsg, receive_num):
                        found = True
                        matches.append(cmsg)
                        if template.attr_name is not None:
                            named_matches[template.attr_name] = cmsg
                        break
                if not found:
                    if diagnostic is not None:
                        msg = "Missing ancillary data: {} {} {} {}\n".format(
                            template.level, template.type, template.data_len,
                            template.receive_num
                        ).encode('ascii')
                        diagnostic.error(self, msg)
                    return None
        if num_cmsgs != len(self._templates):
            num_expected = len(self._templates)
            msg = b'Expected %d cmsgs - got %d cmsgs\n' % (num_expected,
                                                           num_cmsgs)
            diagnostic.error(self, msg)
            return None
        return MatchResult(matches, named_matches)

    def ancillary_data_space(self):
        space = 0
        for template in self._templates:
            space += template.space()
        return space


class CMSGAwareSocketIO(socket.SocketIO):
    def __init__(self, sock, ancillary_data_recorder,
                 ancillary_data_transmitter, *args, **kwargs):
        super(CMSGAwareSocketIO, self).__init__(sock, *args, **kwargs)
        self._recorder = ancillary_data_recorder
        self._transmitter = ancillary_data_transmitter
        # hmm keep fingers crossed that the underlying implementation will
        # not change...
        self._sock._io_refs += 1

    def close(self):
        recorder = self._recorder
        if recorder is not None:
            self._recoder = None
            recorder.discard()
        return super(CMSGAwareSocketIO, self).close()

    def readinto(self, b):
        if not len(b):
            # Keep the original readinto/recv_into behavior in case of a
            # 0-length read: _socket.socket.recv_into immediately returns in
            # case of a 0-length read (see sock_recv_guts in
            # Modules/socketmodule.c). Since we are going to implement readinto
            # via _socket.socket.recvmsg_into, we have to do the 0-length read
            # check manually because _socket.socket.recvmsg_into simply calls
            # the recvmsg syscall, which would block in case of a 0-length read
            # (at least in case of a tcp ipv4 socket). For the sake of
            # completeness, a read(sockfd, buf, 0) syscall would _NOT_ block,
            # even though the socket's read (or more precisely read_iter)
            # is implemented via the recvmsg syscall (at least in case of a
            # tcp ipv4 socket), because sock_read_iter (see net/socket.c in
            # the kernel source tree) explicitly does a 0-length read check
            # (and immediately returns 0).
            return 0
        return self.recvmsg_into([b])

    def recvmsg_into(self, buffers, ancillary_data_space=-1, flags=0):
        recorder = self._recorder
        if ancillary_data_space == -1:
            if recorder is not None:
                ancillary_data_space = self._recorder.controllen()
            else:
                ancillary_data_space = 0
        data = self._sock.recvmsg_into(buffers, ancillary_data_space, flags)
        if recorder is not None:
            self._recorder.record(data[2], data[3], *data[1])
        return data[0]

    def write(self, b):
        return self.sendmsg([b])

    def sendmsg(self, buffers, flags=0):
        transmitter = self._transmitter
        raw_cmsgs = []
        if transmitter is not None:
            raw_cmsgs = transmitter.raw_cmsgs()
        return self._sock.sendmsg(buffers, raw_cmsgs, flags)


class Router(RouterBase):
    def __init__(self, *route_binders, recorder_factory=None):
        def _recorder_factory(ancillary_data_space):
            return AncillaryDataRecorder(ancillary_data_space)

        super(Router, self).__init__(*route_binders)
        self._ancillary_data_space = self._calc_ancillary_data_space(
            route_binders
        )
        if recorder_factory is None:
            recorder_factory = _recorder_factory
        self._recorder_factory = recorder_factory

    def _calc_ancillary_data_space(self, route_binders):
        ancillary_data_space = 0
        for route_binder in route_binders:
            space = 0
            for matcher in route_binder._route._matchers:
                if hasattr(matcher, 'ancillary_data_space'):
                    space += matcher.ancillary_data_space()
            if space > ancillary_data_space:
                ancillary_data_space = space
        return ancillary_data_space

    def _makefile(self, sock, mode='rwb', buffering=0, *args, **kwargs):
        recorder = self._recorder_factory(self._ancillary_data_space)
        # use close=False in order to respect the early_close parameter
        # that was passed to Router.route
        return _makefile(sock, recorder, None, mode, buffering, close=False,
                         *args, **kwargs)

    def _create_rrrw(self, sio):
        rrrw = super(Router, self)._create_rrrw(sio)
        # ouch... so hacky
        rrrw.request.recorder = sio._recorder
        return rrrw


def _makefile(sock, recorder, transmitter, mode='rwb', buffering=0, close=True,
              *args, **kwargs):
    if mode != 'rwb':
        raise ValueError("Unsupported mode: {}".format(mode))
    elif buffering != 0:
        raise ValueError("Unsupported buffering: {}".format(buffering))
    sio = CMSGAwareSocketIO(sock, recorder, transmitter, mode, *args,
                            **kwargs)
    if close:
        sock.close()
    return sio


def route(method_description, path_query_fragment_description, *args,
          cmsgs=None, **kwargs):
    matchers = list(kwargs.get('matchers', []))
    if cmsgs is not None:
        # the matcher's encoding args etc. can be ignored
        matchers.append(CMSGTemplateMatcher(*cmsgs))
        kwargs['matchers'] = matchers
    return base_route(method_description, path_query_fragment_description,
                      *args, **kwargs)


def ignore_cmsgs(controller_meth):
    def decorator(self, *args, **kwargs):
        recorder = self.rrrw.request.recorder
        recorder.stop()
        recorder.discard()
        return controller_meth(self, *args, **kwargs)

    return decorator


class AncillaryDataTransmitter(object):
    def __init__(self, processor=None):
        super(AncillaryDataTransmitter, self).__init__()
        if processor is None:
            processor = AncillaryDataProcessor()
        self._processor = processor
        self._cmsgs = []

    def transmit(self, cmsg, one_shot=True):
        self._cmsgs.append((cmsg, one_shot))

    def raw_cmsgs(self):
        new_cmsgs = []
        cmsgs = self._cmsgs
        raw_cmsgs = []
        while cmsgs:
            cmsg, one_shot = cmsgs.pop(0)
            if not one_shot:
                new_cmsgs.append((cmsg, one_shot))
            raw_cmsgs.append(*self._processor.serialize(cmsg))
        self._cmsgs = new_cmsgs
        return raw_cmsgs


class Request(RequestBase):
    def __init__(self, transmitter, *args, **kwargs):
        super(Request, self).__init__(*args, **kwargs)
        self._transmitter = transmitter

    def _makefile(self, sock, *args, **kwargs):
        return _makefile(sock, None, self._transmitter, *args, **kwargs)

    @classmethod
    def factory(cls, transmitter):
        def _factory(*args, **kwargs):
            return super(Request, cls).factory(transmitter, *args, **kwargs)

        return _factory


def _perform(func, *args, **kwargs):
    cmsgs = kwargs.pop('cmsgs', [])
    request_factory = kwargs.pop('request_factory', None)
    if cmsgs and request_factory is not None:
        raise ValueError('cmsgs and request_factory are mutually exclusive')
    if request_factory is None:
        transmitter = AncillaryDataTransmitter()
        for cmsg in cmsgs:
            if isinstance(cmsg, (list, tuple)):
                transmitter.transmit(*cmsg)
            else:
                transmitter.transmit(cmsg)
        request_factory = Request.factory(transmitter)
    return func(*args, request_factory=request_factory, **kwargs)


def get(*args, **kwargs):
    return _perform(base_get, *args, **kwargs)


def post(*args, **kwargs):
    return _perform(base_post, *args, **kwargs)
