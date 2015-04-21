#! /usr/bin/env python2.7

# fakedns.py -- a program to listen to dns queries, lie about a selected
# few of them, and respond with real correct answers to the rest
#
# $Date: 2011-08-03 19:22:31 -0700 (Wed, 03 Aug 2011) $
# $Revision: 216 $
# $Author: rrapoport $
# $HeadURL: http://svn100.dc1.prod.netflix.com/repos/configs/itops/dnsmasq/fakedns/fakedns.py $
# $Id: fakedns.py 216 2011-08-04 02:22:31Z rrapoport $

import logging
import logging.handlers
import optparse
import os
import os.path
import re
import select
import socket
import sys
import time
import traceback

import dns.flags
import dns.message
import dns.rdatatype
import dns.resolver
import dns.rrset

default_syslog_facility = "daemon"
default_syslog_priority = logging.WARN
default_conf_file = "/etc/fakedns.conf"


def setup_logger(logger, stdout=True, syslog=True, facility=default_syslog_facility, debug=False, info=False):
        if debug:
            logging_level = logging.DEBUG
        elif info:
            logging_level = logging.INFO
        else:
            logging_level = default_syslog_priority
        logger.setLevel(logging_level)

        formatter = logging.Formatter("%(asctime)s %(levelname)s %(module)s %(message)s")

        if stdout:
            addHandler = True
            # Let's not add stdout handler more than once
            if logger.handlers:
                for handler in logger.handlers:
                    if "stream" in dir(handler):
                        stream = handler.stream
                        name = stream.name
                        if name == "<stdout>":
                            addHandler = False
                            break
            if addHandler:
                handler = logging.StreamHandler(sys.stdout)
                handler.setLevel(logging_level)
                handler.setFormatter(formatter)
                logger.addHandler(handler)

        if syslog:
            facility_int = logging.handlers.SysLogHandler.facility_names[facility]
            handler = logging.handlers.SysLogHandler(facility=facility_int)
            handler.setLevel(logging_level)
            handler.setFormatter(formatter)
            logger.addHandler(handler)


def parseArgs(logger):
    """
    Utility function to parse command-line arguments and do some
    sanity checking.  Given a logger object so we can start checking for
    valid args that relate to the logger
    """

    parser = optparse.OptionParser()
    add_option(parser, "file", "file containing lies", default=default_conf_file)
    add_option(parser, "port", "port on which to listen", default=53)
    add_option(parser, "address", "Address to which to bind")
    add_option(parser, "facility", "syslog facility to use", default=default_syslog_facility)
    add_option(parser, "debug", "massively increase verbosity", boolean=True, default=False)
    add_option(parser, "info", "Somewhat increase verbosity", boolean=True, default=False)
    add_option(parser, "syslog", "also log to syslog", boolean=True, default=False)
    add_option(parser, "stdout", "also log to stdout", boolean=True, default=False)
    add_option(parser, "notxt", "do not return txt records", boolean=True, default=False)
    add_option(parser, "delay", "require this much delay between responses", boolean=False, default=0)

    (options, args) = parser.parse_args()

    valid_facilities = logging.handlers.SysLogHandler.facility_names.keys()
    valid_facilities.sort()
    if options.facility not in valid_facilities:
        print "Error: '%s' is not a valid facility" % options.facility
        print "Valid facilities: %s" % ", ".join(valid_facilities)
        parser.print_help()
        sys.exit(0)

    if not os.path.exists(options.file):
        print "{} does not exist.  Exiting".format(options.file)
        parser.print_help()
        sys.exit(0)

    return (options, args)


# utility function to make managing the command-line parser slightly easier
def add_option(parser, optionName, help_t, **kwargs_in):
    """
    Helper function to create an option for an OptionParser and deal with
    things like short flag names, etc.
    parser is an optparse.OptionParser object
    optionName is a string option name (e.g. 'flags')
    help_t is the help string for this option
    kwargs_in are various optional kwargs including 'default',
        'multiple', and 'boolean'
    """

    default = kwargs_in.get('default')
    multiple = kwargs_in.get('multiple')
    boolean = kwargs_in.get('boolean')

    kwargs = {}
    args = []

    short = optionName[0]
    if ["-%s" % short] not in [i._short_opts for i in parser.option_list]:
        args.append("-%s" % short)

    args.append("--%s" % optionName)

    if default:
        help_t += " (default: '%s')" % default
        kwargs['default'] = default
    kwargs['help'] = help_t

    if boolean:
        kwargs['action'] = 'store_true'

    if multiple:
        kwargs['action'] = 'append'

    # print "args: %s kwargs: %s" % (args, kwargs)
    i = parser.add_option(*args, **kwargs)
    # print "action: %s" % i.action


def requestHandler(sock, message, address, socketObj, logger, notxt):
    """
    The actual workhorse -- takes a message taken from the socketObj with an
    associated source address, then responds to it by creating a response and
    injecting it into the socketObj, logging appropriately
    """

    message_id = ord(message[0]) * 256 + ord(message[1])
    logger.debug('msg id = ' + str(message_id))
    msg = dns.message.from_wire(message)
    response = dns.message.make_response(msg, recursion_available=True)
    response.flags |= dns.flags.AA
    op = msg.opcode()
    if op != 0:
        response = dns.message.make_response(msg)
        socketObj.send(sock, response.to_wire(), address)
        return
    # We got here? op = 0
    questions = msg.question
    # questions is actually a list of dns.rrset.RRset objects
    question_pairs = []
    for question in questions:
        question_pairs.append([question.name, question.rdtype])
    logger.debug("Starting to look at question_pairs ... ")
    for q in question_pairs:
        rdname = q[0]
        rdtype = q[1]
        logger.debug("looking for %s / %s" % (rdname, rdtype))
        answer = None
        try:
            answer = myCache.get(rdname, rdtype)
            if notxt and rdtype == dns.rdatatype.TXT:
                response.set_rcode(dns.rcode.SERVFAIL)
                logger.debug("Got a TXT request -- will respond with a SERVFAIL")
                continue
            if answer.rdtype == dns.rdatatype.CNAME:
                responses = answer.response.answer
                cur_response = responses[0]
                rdataset = cur_response.to_rdataset()
                rdataset_items = rdataset.items
                cname_item = rdataset_items[0]
                cname_t = cname_item.to_text()
                question_pairs.append([dns.name.Name(cname_t.split(".")), rdtype])
            logger.debug("answer from myCache: ---\n%s\n---\n" % answer)
        except dns.resolver.NXDOMAIN:
            response.set_rcode(dns.rcode.NXDOMAIN)
        except (dns.resolver.Timeout, dns.resolver.NoAnswer):
            response.set_rcode(dns.rcode.SERVFAIL)
        except dns.resolver.NoNameservers:
            response.set_rcode(dns.rcode.NOTIMP)
        except Exception, e:
            msg = "Oops.  Tried to find %s/%s, " % (rdname, rdtype)
            msg += "but got exception %s/%s" % (Exception, e)
            logger.warn(msg)
            tb = traceback.format_exc()
            logger.warn(tb)
            answer = dns.message.make_response(msg)
            logger.debug("answer: %s" % (answer))

        try:
            if answer is not None:
                logger.debug("adding answer to the response ... ")
                response.answer += answer.response.answer
                logger.debug("response.answer is %s" % response.answer)
            else:
                logger.debug("Didn't get an answer, so not doing anything")
        except Exception, e:
            logger.warn("Odd -- in response stuff, got %s/%s" % (Exception, e))
            tb = traceback.format_exc()
            logger.warn(tb)

    logger.debug("response is %s" % response)
    wire_response = response.to_wire()
    socketObj.send(sock, wire_response, address)


def readLies(fname, logger):
    """
    Reads a series of "lies" from the given fname (text string pointing to
    file containing lies).  Each line should be a space-separated quad of
    name origin typeoflie   valueoflie
    where name is a short name (e.g. uiboot),
        origin is the rest of the fqdn for the short name (e.g. netflix.com.)
        typeoflie is a dns record type (e.g. cname)
        valueoflie is the actual return value to return if asked for this record
    """

    # These are record types where, if we're reading in lies for them, we
    # should make sure the value is an FQDN (ends in a '.')
    fqdnRecordTypes = "CNAME PTR".split()

    f = open(fname, "r")
    for line in f:
        line = re.sub("#.*", "", line)
        line = line.rstrip()
        if line == '':
            continue
        logger.debug("Processing line '%s'" % line)
        (fqdn, rdtype_t, fakeAnswer) = line.split()

        # To be helpful, let's save people from themselves and make sure fqdn
        # ends with a '.' (so it really is a proper fqdn0
        if fqdn[-1] != ".":
            fqdn += "."
        logger.debug("A new lie: %s -> %s/%s" % (fqdn, rdtype_t, fakeAnswer))
        if rdtype_t in fqdnRecordTypes and fakeAnswer[-1] != ".":
            fakeAnswer += "."

        rdtype = dns.rdatatype.from_text(rdtype_t)
        currentAnswer = CachedAnswer()
        currentAnswer.permanent = True
        qname = dns.name.from_text(fqdn)
        # A DNS response includes both the query and an answer.  So first, let's create the query:
        query = dns.message.make_query(qname, rdtype)
        # Now, let's create the response.
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text_list(qname, 3600, dns.rdataclass.IN, rdtype, [fakeAnswer])
        arrset = response.find_rrset(response.answer, qname, dns.rdataclass.IN, rdtype, create=True)
        arrset.update(rrset)
        answer = dns.resolver.Answer(qname, rdtype, dns.rdataclass.IN, response)
        currentAnswer.answer = answer
        myCache.set(qname, rdtype, currentAnswer)
    f.close()


class CachedAnswer(object):
    """
    dirt-simple answer object.  Contains properties:
        answer -- the actual dns.resolver.Answer object
        lastCache = timestamp for when we cached this answer
        cacheFor = number of seconds for which to cache this answer
        permanent = boolean flag if we should cache this answer permanently
    """

    def __init__(self):
        self.answer = None
        self.lastCache = None
        self.cacheFor = None
        self.permanent = None


class Cache(object):
    """
    This object allows its users to request resolution of a given rdname/rdtype
    It makes dns queries as necessary, and caches responses an appropriate
    amount of time.
    Internal information is kept in the _cache property, which is a
    dictionary whose keys are DNS names and values are other dicts whose
    keys are DNS record types and whose values are CachedAnswer objects
    e.g.
    self._cache[<dns.name 'uiboot.netflix.com'>] returns a dict that looks something like:
    { <dns.rdtype 'A'> : <CachedAnswer '1.2.3.4'> }
    """

    def __init__(self, logger):
        self._cache = {}
        self._logger = logger

    def set(self, rdname, rdtype, cachedAnswer):
        """
        This is used by anyone who essentially wants to override what
        "real" dns says by pre-caching an answer.
        rdname is a <dns.name>
        rdtype is a <dns.rdtype>
        cachedAnswer is a <CachedAnswer>
        """

        if not rdname in self._cache:
            self._cache[rdname] = {}
        self._cache[rdname][rdtype] = cachedAnswer

    def get(self, rdname, rdtype, nofetch=False):
        """
        given <dns.name rdname> and <dns.rdtype rdtype>, return
        a <dns.resolver.Answer>.  If nofetch is True, we will not
        fetch a response -- so if we did not already cache something for
        rdname/rdtype, we'll return None
        """

        self._logger.debug("cache: %s" % self._cache)

        cached = None
        cached_rdname = self._cache.get(rdname)
        if cached_rdname:
            # If we have a CNAME for this rdname, return it irrespective of what
            # we've been asked
            cached = cached_rdname.get(dns.rdatatype.CNAME)
            if not cached:  # We do not have a CNAME for this rdname
                cached = cached_rdname.get(rdtype, None)

        if nofetch:
            # return whatever answer we have, irrespective of its age or,
            # in fact, existence
            return cached

        if not cached:  # easiest -- we don't know about it
            self._logger.debug("No cached answer.  Must update")
            update = 1
        if cached:
            self._logger.debug("Have a cached answer!")
            if cached.permanent:  # Easiest -- we just return value
                return cached.answer
            else:  # Need to check freshness
                if (cached.lastCache + cached.cacheFor) < time.time():
                    update = 1
                else:
                    update = 0

        if update == 1:  # We need to fetch a new answer to this question
            self._logger.debug("Updating ... ")
            cached = CachedAnswer()  # Create a new CachedObject ...
            cached.answer = dns.resolver.query(rdname, rdtype)
            # How long should we cache for?
            rrset = cached.answer.rrset
            rdataset = rrset.to_rdataset()
            ttl = rdataset.ttl
            cached.lastCache = time.time()
            cached.cacheFor = ttl
            self._logger.debug("Caching %s/%s for %s seconds" % (rdname, rdtype, ttl))
            if not rdname in self._cache:
                self._cache[rdname] = {}
            self._cache[rdname][rdtype] = cached

        self._logger.debug("Returning %s" % cached.answer)
        return cached.answer


class Socket(object):
    """
    Wrapper around the basic system socket object
    """

    def __init__(self, logger, address, port):
        """
        logger is a standard logger; port is an int port number we want
        to use
        """

        if int(port) < 1024 and os.getuid() != 0:
            m = "You cannot listen on a port lower than 1024 if you're not running as root"
            logger.error(m)
            raise RuntimeError(m)
        self.incoming = []
        if address is None:
            address = ''
        self.sockets = []
        # self.sockets.append(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
        self.sockets.append(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        for sock in self.sockets:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((address, int(port)))
            except Exception, e:
                m = "Attempted to bind {} to {}/{}; got {}/{}".format(sock, address, port, Exception, e)
                tb = traceback.format_exc()
                logger.error(tb)
                logger.error(m)
                raise RuntimeError(m)
        logger.debug("Socket opened.  Listening on port {}".format(port))
        self._logger = logger

    def getMessage(self, size=1024):
        """
        wrapper around socket.recvfrom
        """

        if self.incoming:
            return self.incoming.pop(0)

        readable, writable, exceptional = select.select(self.sockets, [], [])
        for sock in readable:
            message, address = sock.recvfrom(size)
            self.incoming.append((sock, message, address))
        return self.incoming.pop(0)

    def send(self, sock, message, address):
        """
        wrapper around socket.sendto
        """
        sock.sendto(message, address)


if __name__ == "__main__":
    # This is actually where we start execution

    logger = logging.getLogger("fakedns")
    (options, args) = parseArgs(logger)
    setup_logger(logger, stdout=options.stdout, syslog=options.syslog, facility=options.facility, debug=options.debug, info=options.info)

    mySocket = Socket(logger, options.address, options.port)
    myCache = Cache(logger)
    readLies(options.file, logger)
    liesRead_ts = time.time()

    if options.delay is None:
        delay = 0
    else:
        try:
            delay = float(options.delay)
        except Exception, e:
            raise RuntimeError("--delay specified, but was not some sort of number")

    logger.debug("Set delay between responses to {} seconds".format(delay))
    last_response = 0
    while True:
        logger.debug('Listening for queries...')
        sock, message, address = mySocket.getMessage()
        t = time.time()
        logger.info("Request from {}".format(address[0]))
        tt = time.time()
        lastMod = os.path.getmtime(options.file)
        if lastMod > liesRead_ts:
            msg = "Last read %s %d seconds ago,\n" % (options.file, (tt - liesRead_ts))
            msg += "but it was modified more recently, %d seconds ago.  Reloading" % (tt - lastMod)
            logger.debug(msg)
            readLies(options.file, logger)
            liesRead_ts = tt
        logger.debug("receiving took %f" % (tt - t))
        t = time.time()
        try:
            if t - last_response < delay:  # We need to wait a bit
                sleep = delay - (t - last_response)
                logger.debug("Too soon after the last request -- sleeping {:.3f} seconds".format(sleep))
                time.sleep(sleep)
            requestHandler(sock, message, address, mySocket, logger, options.notxt)
            last_response = time.time()
        except Exception, e:
            msg = "Oh oh.  In trying to run requestHandler, "
            msg += "we got an exception %s: %s" % (Exception, e)
            logger.warn(msg)
            tb = traceback.format_exc()
            logger.warn(tb)
        tt = time.time()
        logger.debug("handling took %f" % (tt - t))
