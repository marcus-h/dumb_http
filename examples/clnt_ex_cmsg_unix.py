"""Demonstrate fd/fobj passing via a unix domain socket.

Usage:
    python3 {script} copy <from file> <to file> [<delay> <bufsize>]:
    The file <from file> is send to the server. Then, the server reads the
    send file into memory, sends a response to the client (this script), waits
    <delay> many seconds, and stores the received file in <to file> (note: the
    fobj that represents <to file> is _passed_ to the server). The server
    reads the received file in chunks of <bufsize> bytes.
    Example:
        python3 {script} copy {script} out.txt 10 4096
        tail -f out.txt

    python3 {script} sha256sum <file 1> <file 2>:
    Pass both files to the server (via fd/fobj passing) and let the server
    compute their sha256 sums.

    python3 {script} count <file> [<num_cmsgs> <flood_cmsgs>]:
    POST the file <file> to the server. The server counts the number of cmsgs
    it received while reading the request and the request's body.
    The optional <num_cmsgs> parameter determines the number of cmsgs that are
    are generated (default value: 1).
    If the optional <flood_cmsgs> parameter is specified (can by any value),
    the generated cmsgs are send with each sendmsg(...) call. If not specified,
    the generated cmsgs are only send with the first sendmsg(...) call.
    Examples:
        python3 {script} count {script} 2
        python3 {script} count {script} 3
        python3 {script} count {script} 2 1
        python3 {script} count {script} 3 1

    python3 {script} ignore <file> [<flood_cmsgs>]
    Similar to the "count" command. The request's target is the /ignore route.
    This is more or less just for testing purposes.
"""

import socket
import sys

# import get and post from the cmsg module instead of the http module
from dumb_http.cmsg import get, post, CMSG_SCM_RIGHTS


def print_usage(script):
    print(__doc__.format(script=script))


def _post_data_and_cmsgs(path, data, cmsgs, flood_cmsgs=False, **query):
    if flood_cmsgs:
        cmsgs = [(cmsg, False) for cmsg in cmsgs]
    with post('\0localhost', path, data=data, sock_family=socket.AF_UNIX,
              sock_type=socket.SOCK_STREAM, cmsgs=cmsgs, **query) as resp:
        if not resp.is_connection_error():
            print(resp.read().decode('utf-8'))
            return 0
    print('Error', resp.is_connection_error(), resp.strerror)
    return 1


def copy(from_fname, to_fname, delay=None, bufsize=None):
    with open(from_fname, 'rb') as f_read, open(to_fname, 'wb') as f_write:
        cmsg = CMSG_SCM_RIGHTS([f_write])
        query = {}
        if delay is not None:
            query['delay'] = delay
        if bufsize is not None:
            query['bufsize'] = bufsize
        return _post_data_and_cmsgs('/copy', f_read, [cmsg], **query)


def sha256sum(from_fname1, from_fname2):
    with open(from_fname1, 'rb') as f1, open(from_fname2, 'rb') as f2:
        # it is more reasonable to put f1 and f2 into a single cmsg - we
        # only do this in order to demonstrate that the receiver receives
        # a _single_ cmsg that contains f1 and f2 (instead of two cmsgs)
        cmsgs = [CMSG_SCM_RIGHTS([f1]), CMSG_SCM_RIGHTS([f2])]
        with get('\0localhost', '/sha256sum', sock_family=socket.AF_UNIX,
                 sock_type=socket.SOCK_STREAM, cmsgs=cmsgs) as resp:
            if not resp.is_connection_error():
                print(resp.read().decode('utf-8'))
                return 0
        print('Error', resp.is_connection_error(), resp.strerror)
        return 1


def count(from_fname, num_cmsgs=1, flood_cmsgs=False):
    with open(from_fname, 'rb') as f:
        cmsgs = []
        for i in range(int(num_cmsgs)):
            cmsgs.append(CMSG_SCM_RIGHTS([f]))
        return _post_data_and_cmsgs('/count', f, cmsgs, flood_cmsgs)


def ignore(from_fname, flood_cmsgs=False):
    with open(from_fname, 'rb') as f, open(from_fname, 'rb') as f_cmsg:
        cmsgs = [CMSG_SCM_RIGHTS([f_cmsg, f_cmsg]), CMSG_SCM_RIGHTS([f_cmsg])]
        return _post_data_and_cmsgs('/ignore', f, cmsgs, flood_cmsgs)


def _run():
    args = sys.argv[1:]
    if not args:
        print_usage(sys.argv[0])
        sys.exit(1)
    cmd = args.pop(0)
    if cmd == 'copy':
        ret = copy(*args)
    elif cmd == 'sha256sum':
        ret = sha256sum(*args)
    elif cmd == 'count':
        ret = count(*args)
    elif cmd == 'ignore':
        ret = ignore(*args)
    else:
        print_usage(sys.argv[0])
        ret = 1
    return ret


if __name__ == '__main__':
    sys.exit(_run())
