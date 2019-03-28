"""A more advanced CMSG/ancillary data example.

Its sole purpose is to demonstrate how to use our framework in order to specify
a CMSG processor etc. for a specific CMSG type. In particular, we will setup a
controller that receives after each recvmsg (syscall) the number of remaining
bytes in the TCP receive queue. For this, we have to setup a CMSG processor that
parses a CMSG of the type TCP_CM_INQ.
"""

import socket
import struct

from dumb_http.router import RouterBasedHTTPServer
from dumb_http.controller import EncodingAwareController
# import Router and route from cmsg instead of the router module
from dumb_http.cmsg import (Router, route, CMSGRawProcessor, CMSGTemplate,
                            AncillaryDataProcessor, AncillaryDataRecorder)


class CMSGTestController(EncodingAwareController):
    def upload(self, count=4096):
        msg = []
        msg.append(
            ('A number represents the remaining bytes in the TCP receive '
             'queue after a recvmsg (the number is just a hint).\n'
             'Reading the status line + headers (+ possibly initial body): ')
        )
        recorder = self.rrrw.request.recorder
        # inspect cmsgs
        msg.append(', '.join([str(msghdr.cmsgs[0].data)
                              for msghdr in recorder.records]))
        recorder.discard()  # discard cmsgs received so far
        count = int(count)
        received = 0
        while True:
            data = self.read(count)
            if not data:
                break
            received += len(data)
        msg.append('Reading the (rest of the) body: ')
        # inspect cmsgs
        msg.append(', '.join([str(msghdr.cmsgs[0].data)
                              for msghdr in recorder.records]))
        msg.append("Received %d bytes (body)\n" % received)
        self.reply(200, '\n'.join(msg))


class CMSG_TCP_CM_INQ_Processor(CMSGRawProcessor):
    def _serialize_data_format(self, data):
        return self.serialize_data_format()

    def _serialize_data_prepare_data(self, inq):
        # see _parse_data for the details (the serialization process
        # expects a tuple/list)
        return (inq, )

    @classmethod
    def serialize_data_format(cls):
        return 'i'

    @classmethod
    def bufsize(cls):
        return struct.calcsize(cls.serialize_data_format())

    def _parse_data(self, *args, **kwargs):
        # just for convenience: we want to access the inq hint via
        # cmsg.data instead of cmsg.data[0]
        data = super(CMSG_TCP_CM_INQ_Processor, self)._parse_data(*args,
                                                                  **kwargs)
        return data[0]


TCP_INQ = 36  # not exported by the socket module...


class CMSG_TCP_CM_INQ_Template(CMSGTemplate):
    TCP_CM_INQ = TCP_INQ  # also not exported by the socket module
    LEVEL = socket.SOL_TCP

    def __init__(self, *args, **kwargs):
        data_len = CMSG_TCP_CM_INQ_Processor.bufsize()
        super(CMSG_TCP_CM_INQ_Template, self).__init__(None, self.LEVEL,
                                                       self.TCP_CM_INQ,
                                                       data_len, *args,
                                                       **kwargs)

    def _data_matches(self, cmsg):
        return isinstance(cmsg.data, int)


def _ancillary_data_recorder_factory(ancillary_data_space):
    extra_mappings = {
        CMSG_TCP_CM_INQ_Template.LEVEL: {
            CMSG_TCP_CM_INQ_Template.TCP_CM_INQ: CMSG_TCP_CM_INQ_Processor()
        }
    }
    processor = AncillaryDataProcessor(extra_mappings=extra_mappings)
    return AncillaryDataRecorder(ancillary_data_space, processor=processor,
                                 one_shot=False)


def _create_router():
    class _Router(Router):
        def route(self, sock, *args, **kwargs):
            # hmm "old" kernels do not support this... (it needs the kernel
            # commit b75eba76d3d72e2374fac999926dafef2997edd2 ("tcp: send
            # in-queue bytes in cmsg upon read"))
            sock.setsockopt(CMSG_TCP_CM_INQ_Template.LEVEL, TCP_INQ, 1)
            return super(_Router, self).route(sock, *args, **kwargs)

    return _Router(
        # curl -X PUT -T <file> http://localhost:3000/upload
        # curl -X PUT -T <file> http://localhost:3000/upload?count=1000
        # curl -X PUT -T <file> http://localhost:3000/upload?count=1
        # curl -H 'Expect:' -X PUT -T <file> http://localhost:3000/upload
        route(
            'PUT|POST', r'/upload?(count)?=\d+',
            cmsgs=[CMSG_TCP_CM_INQ_Template()]
        ).to(
            CMSGTestController.factory('ascii'),
            CMSGTestController.upload
        ),
        recorder_factory=_ancillary_data_recorder_factory
    )


if __name__ == '__main__':
    router = _create_router()
    rt_srv = RouterBasedHTTPServer(('localhost', 3000), router)
    rt_srv.run()
