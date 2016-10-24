#!/usr/bin/env python
import re
import zlib
import sys


def zlibsearch(data):
    r = []
    zlib_header = '\x78\x9c'
    for offset in [zl.start() for zl in re.finditer(zlib_header, data)]:
        r.append(offset)
    return(r)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Please provide me with a filename.'
        exit()
    data = open(sys.argv[1]).read()
    entry_points = zlibsearch(data)
    if not entry_points:
        print 'Unable to find zLib Data. Exiting'
        exit()
    rawdata = []
    print 'Found {} possible entry point(s): {}'.format(len(entry_points), entry_points)
    for offset in entry_points:
        try:
            rawdata.append(zlib.decompress(data[offset:]))
        except:
            pass

    if not rawdata:
        print 'Potential Zlib area(s) found, but didn\'t decompress to anything useful.'
        exit()

    i = 1
    for row in rawdata:
        outfilename = sys.argv[1].split('.')[0] + '-' + str(i) + '.bin'
        outf = open(outfilename, 'wb')
        outf.write(row)
        outf.close()
        i += 1
        print 'Wrote %s' % outfilename
