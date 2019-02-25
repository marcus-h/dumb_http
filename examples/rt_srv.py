"""Setup a simple http server using the dumb_http framework.

In order to run the example http server just run
marcus@linux:~> export PYTHONPATH=/home/marcus/dumb_http
marcus@linux:~> python3 /home/marcus/dumb_http/examples/rt_srv.py

(of course, the paths have to be adjusted)

Now, the server listens on localhost:3000 for incoming connections.
In order to stop the server, just press <CTRL>-c.

In order to define your own server, execute the following steps:

#
# Step 1: Define the controller(s)
#
For this, you first should/have to think about what kind of data you
expect in a request uri: is the uri data (path, query parameters etc.)
utf-8/latin-1/<your favorite encoding> encoded or do you allow arbitrary
data in the path, query parameters etc.?
If you expect a fixed encoding, your controller(s) should subclass the
controller.EncodingAwareController class. For convenience, it encodes all
uri data behind the scenes and automatically binds uri data to method
parameters etc. (see TestController class).
If you do not/cannot expect a fixed encoding, your controller(s) should
subclass the controller.ControllerBase class. Note: such a controller
cannot bind uri data to method parameters (see BytesOnlyController class).

I would recommend to use one method per route (a route is defined in
Step 2).


#
# Step 2: Define the router, routes and bindings
#
A route consists of a request method, a path and a query description.
The request method, path and query descriptions are specified in a
regex-like DSL. A route is bound to a controller method.

Note: due to the use of regexes some of the route specifications below
might look a bit "complex". However, the advantage (IMHO) is that
most/some of the input validations are done behind the scenes resulting
in a clean and concise controller code (that is, the controller code
only focuses on/implements the logic and does not care about the input
validations).


#
# Step 3: Start the server
#
Just create an instance of the RouterBasedHTTPServer class and execute
the run() method.
"""

import os
import time

from dumb_http.server import Periodic
from dumb_http.router import RouterBasedHTTPServer, Router
from dumb_http.controller import EncodingAwareController, ControllerBase, route


#
# Step 1: Define the controller(s)
#


class TestController(EncodingAwareController):
    def __init__(self, *args, name, greeting, **kwargs):
        super(TestController, self).__init__(*args, **kwargs)
        self._name = name
        self._greeting = greeting

    def hello(self):
        msg = "{}, my name is {}\n".format(self._greeting, self._name)
        self.reply(200, data=msg)

    def read_script(self, resource, mode='rb'):
        if os.path.basename(__file__) != resource:
            msg = "no such resource: {}\n".format(resource)
            self.reply(404, data=msg)
            return
        with open(__file__, mode) as f:
            self.reply(200, data=f)

    def print_params(self, foo, bar, q1, q2, sub, q4_optional='unspecfied'):
        # q3 is omitted on purpose in the parameter list above, it can be
        # obtained as follows
        q3 = self.nm.q3
        msg = ("foo = {}, bar = {}, q1 = {}, q2 = {}, q3 = {}, sub = {}, "
               "q4_optional = {}\n").format(foo, bar, q1, q2, q3, sub,
                                            q4_optional)
        self.reply(200, data=msg)

    def arbitrary_query_keys(self):
        named_matches = self.nm.as_dict()
        key_value_pairs = ['='.join(kv) for kv in named_matches.items()]
        msg = "key value pairs: {}\n".format(', '.join(key_value_pairs))
        self.reply(200, data=msg)

    def repetition(self, value):
        msg = "got: {} (len: {})\n".format(value, len(value))
        self.reply(200, data=msg)


test_controller_factory = TestController.factory('utf-8', name='marcus',
                                                 greeting='Hi')


class BytesOnlyController(ControllerBase):
    def write_resource(self):
        num_bytes = 0
        with open('/dev/null', 'wb') as f:
            while True:
                data = self.read(4096)
                if not data:
                    break
                f.write(data)
                num_bytes += len(data)
        named_matches = self.nm.as_dict()
        resource = named_matches[b'resource']
        raw_data = named_matches.get(b'raw_data', b'not specified')
        msg = b"stored %d bytes in %s (raw_data: %s)\n" % (num_bytes, resource,
                                                           raw_data)
        self.reply(200, data=msg)


#
# Step 2: Define the router, routes and bindings
#


ROUTER = Router(
    # curl http://localhost:3000/hello/world
    route('GET', '/hello/world').to(test_controller_factory,
                                    TestController.hello),

    # curl http://localhost:3000/read?resource=rt_srv.py
    route(
        'GET',
        r'/read?resource=[^/]+\.py&(mode)?=rb|r\+b'
    ).to(test_controller_factory, TestController.read_script),

    # (one line str)
    # curl http://localhost:3000/path/foo%3Abaz/yyy \
    # '?q1=123&q2=some%3Avalue&q3=xbar42y&q4_optional=x_x'
    # or
    # curl http://localhost:3000/path/foo%3Abaz/yyy/ \
    # '?q1=123&q2=some%3Avalue&q3=xbar42y'
    # etc.
    route(
        'GET',
        (r'/path/<foo>/<bar>xxx|yyy?q1=\d+&q2=.*&q3=x(?P<sub>foo|bar\d*)y'
         '&(q4_optional)?=[a-zA-Z_]*')
    ).to(test_controller_factory, TestController.print_params),

    # curl 'http://localhost:3000/a/b/c?x=4711&y=42&z=1337&fixed=foo'
    # etc.
    route(
        'GET',
        r'/a/b/c?.+=\d+|a+&fixed=foo'
    ).to(test_controller_factory, TestController.arbitrary_query_keys),

    # curl http://localhost:3000/xxx/%C3%BF%C3%BF
    # or
    # curl http://localhost:3000/xxx/%C3%BF%C2%80 -o out
    # (examine out, for instance via hexdump -C out)
    # etc.
    # Note: we require an utf-8 encoding
    #       => curl http://localhost:3000/xxx/%FF%FF won't work
    # (If no encoding is specified, utf-8 is used by default)
    route('GET', '/xxx/<value>[\xff\x80]{2}', encoding='utf-8').to(
        test_controller_factory, TestController.repetition
    ),

    # curl -X POST -d 'foo' http://localhost:3000/write?resource=/dev/null
    # or
    # curl -X POST -d 'foo' http://localhost:3000/write \
    # '?resource=/dev/null&raw_data=%FF%FF%BF'
    # (one line)
    # Since we require no encoding (encoding=None), we can specify arbitrary
    # bytes in the raw_data query parameter.
    route(
        b'PUT|POST',
        rb'/write?resource=/dev/null&(raw_data)?=.+',
        encoding=None
    ).to(BytesOnlyController.factory(), BytesOnlyController.write_resource)
)


class PeriodicHandler1(object):
    def __init__(self):
        super(PeriodicHandler1, self).__init__()
        self._last = self._now()

    def _now(self):
        return int(time.time())

    def __call__(self):
        # actual handler code
        now = self._now()
        diff = now - self._last
        self._last = now
        msg = "PeriodicHandler1 called (last call: {} seconds ago)".format(
                diff)
        print(msg)


def periodic_handler2():
    if not hasattr(periodic_handler2, 'count'):
        periodic_handler2.count = 10
    msg = "periodic_handler2 count: {}".format(periodic_handler2.count)
    print(msg)
    periodic_handler2.count -= 1
    if periodic_handler2.count == 5:
        # every 2 seconds
        return 2
    elif not periodic_handler2.count:
        # will be never called again
        return Periodic.REMOVE


if __name__ == '__main__':
    #
    # Step 3: Start the server
    #
    periodics = [Periodic(30, PeriodicHandler1()),
                 Periodic(10, periodic_handler2)]
    rt_srv = RouterBasedHTTPServer('localhost', 3000, ROUTER,
                                   periodics=periodics)
    rt_srv.run()
