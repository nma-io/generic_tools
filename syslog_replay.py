#!/usr/bin/python
"""Syslog Replay Tool.

Author: Nicholas Albright
This is a quick and dirty tool that will replay messages found in a text file to a remote syslog server.
Generic use example:
    MSSP Walks into a customer environment to do monitoring post security event.
    Customer had no central logging prior to the security event.
    On Box logging is still in place.
    Running this tool on existing syslog messages -> forward to SIEM will give us historial logs.
* NOTE:  TimeStamp's need to be 'generated time' not ingested time.
"""
import sys
import time
import socket
import logging
import argparse

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
log = logging.getLogger(__name__)


def sendlog(filename, server, port, rate):
    """Send our Syslog Data to remote server."""
    remote = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    row_count = 0
    rate_count = 0
    try:
        with open(filename, 'r') as fh:
            for line in fh:
                row_count += 1
                rate_count += 1
                if rate_count >= rate:
                    time.sleep(1)
                    rate_count = 0
                remote.sendto(line.rstrip(), (server, int(port)))
    except Exception as err:
        log.exception(err)

    return row_count


def optionparse():
    """Parse Options."""
    opts = argparse.ArgumentParser(description='Nicholas\' Syslog Replay Tool')
    opts.add_argument('filename', help='File continaing syslog formatted messages')
    opts.add_argument('-p', '--port', help='Syslog port (UDP), Default: 514', default=514)
    opts.add_argument('-r', '--rate', help='Rate Per Second (or events per second), Default: 300', default=300)
    opts.add_argument('-s', '--server', help='Server to send messages to.')
    parsed_args = opts.parse_args()
    if not parsed_args.server:
        opts.print_help()
        sys.exit()
    return parsed_args


if __name__ == '__main__':
    args = optionparse()
    start = time.time()
    row_count = sendlog(args.filename, args.server, args.port, int(args.rate))
    end = time.time()
    log.info('Addressed %d messages in %s seconds' % (row_count, str(end - start)))
