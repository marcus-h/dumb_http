"""HTTP over a unix domain socket with fd passing.

The idea of doing HTTP via a unix domain socket is taken from the
Open Build Service project (see the backend code).

This example demonstrates how to setup routes that expect control
messages (CMSGs)/ancillary data of the type SCM_RIGHTS. Moreover, it
demonstrates how to use such CMSGs in a controller.

The clnt_ex_cmsg_unix.py script can be used to interact with this
server.
"""

import hashlib
import socket
import time

from dumb_http.router import RouterBasedHTTPServer
from dumb_http.controller import EncodingAwareController
# import Router and route from cmsg instead of the router module
from dumb_http.cmsg import (Router, route, CMSG_SCM_RIGHTS_Template,
                            AncillaryDataRecorder, ignore_cmsgs)


class CMSGUnixTestController(EncodingAwareController):
    def copy(self, cmsg_scm_rights, delay=0, bufsize=4096):
        recorder = self.rrrw.request.recorder
        # stop recording more cmsgs since we are not going to use them
        # (usually one would use a one-shot recorder anyway... (we do not
        # use a one-shot recorder in order to demonstrate a more features)
        recorder.stop()
        with cmsg_scm_rights.data[0] as fobj:
            # once we pop the msghdr, we have to make sure that _WE_ close
            # the received fobj that is contained in cmsg_scm_rights.data
            # (note: cmsg_scm_rights == recorder.records[0].cmsgs[0])
            recorder.records.pop(0)
            data = []
            bufsize = int(bufsize)
            while True:
                d = self.read(bufsize)
                if not d:
                    break
                data.append(d)
            # the reply automatically discards all records in the ancillary
            # data recorder (that's why we pop()ed it before) (discarding the
            # SCM_RIGHTS cmsg implies closing the received fobjs)
            self.reply(200, 'Write in progress\n')
            # now, the connection is closed - start writing
            # wait for the specified delay
            time.sleep(int(delay))
            # fobj is opened as rb => open as wb (fobj and f refer to the
            # same fd (== fobj.fileno()) => use closefd=False so that the
            # fd is only closed once)
            with open(fobj.fileno(), 'wb', closefd=False) as f:
                for d in data:
                    # hmm we should not ignore the retval, but let's keep
                    # this example simple...
                    f.write(d)

    def sha256sum(self, cmsg_fobjs):
        # not necessarily needed because we do not read (from the socket)
        # anymore
        self.rrrw.request.recorder.stop()
        digests = []
        for f in cmsg_fobjs.data:
            with f:
                ctx = hashlib.sha256()
                while True:
                    data = f.read(4096)
                    if not data:
                        break
                    ctx.update(data)
                digests.append(ctx.hexdigest())
        self.reply(200, "sha256 hexdigests:\n{}\n{}\n".format(*digests))

    def count(self):
        # just to demonstrate how to work with a msghdr
        def count_and_discard():
            cnt = 0
            truncated = False
            recorder = self.rrrw.request.recorder
            for msghdr in recorder.records:
                cnt += len(msghdr.cmsgs)
                truncated |= bool(msghdr.flags & socket.MSG_CTRUNC)
            recorder.discard()
            return cnt, truncated

        cnt_request, truncated_request = count_and_discard()
        while True:
            if not self.read(4096):
                break
        cnt_body, truncated_body = count_and_discard()
        msg = ("Request:\n#cmsgs: {}, truncated: {}\n"
               "Body:\n#cmsgs: {}, truncated: {}").format(cnt_request,
                                                          truncated_request,
                                                          cnt_body,
                                                          truncated_body)
        self.reply(200, msg)

    @ignore_cmsgs
    def ignore(self):
        num_bytes = 0
        while True:
            self.rrrw.request.recorder.discard()
            data = self.read(4096)
            if not data:
                break
            num_bytes += len(data)
        num_records = len(self.rrrw.request.recorder.records)
        if num_records:
            # should not happen
            msg = "Internal error: msghdr records found ({})\n".format(
                num_records
            )
            return self.reply(500, msg)
        msg = "Successfully ignored all cmsgs (read {} bytes)\n".format(
            num_bytes
        )
        self.reply(200, msg)


def _ancillary_data_recorder_factory(ancillary_data_len):
    return AncillaryDataRecorder(ancillary_data_len, one_shot=False)


def _create_router():
    factory = CMSGUnixTestController.factory('ascii')
    return Router(
        # read data the PUTed/POSTed data and write it to the passed fobj
        route(
            'PUT|POST', r'/copy?(delay)?=\d+&(bufsize)?=[1-9]\d*',
            cmsgs=[CMSG_SCM_RIGHTS_Template('cmsg_scm_rights', 1, 0)]
        ).to(factory, CMSGUnixTestController.copy),

        # compute the sha256 hexdigests of both passed fobjs
        route(
            'GET', '/sha256sum',
            cmsgs=[CMSG_SCM_RIGHTS_Template('cmsg_fobjs', 2, 0)]
        ).to(factory, CMSGUnixTestController.sha256sum),

        # expects no cmsgs and just counts all cmsgs it receives
        route('POST', '/count').to(factory, CMSGUnixTestController.count),

        # expects no cmsgs and ignores them if present
        route('POST', '/ignore').to(factory, CMSGUnixTestController.ignore),

        recorder_factory=_ancillary_data_recorder_factory
    )


if __name__ == '__main__':
    router = _create_router()
    rt_srv = RouterBasedHTTPServer('\0localhost', router,
                                   sock_family=socket.AF_UNIX,
                                   sock_type=socket.SOCK_STREAM)
    rt_srv.run()
