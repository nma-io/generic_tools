#!/usr/bin/python
"""AD Lookup Tool.

Runs net user /domain and grabs the listing of domain users.
Then runs a query against each individual user to determine when the password was last changed.

This can be helpful during:

Pentests - Find those old service accounts that may have older passwords
IR - Find accounts that have been reactivated by an adversary
SOC - Which accounts are important to watch?
Audit - Do they do what they say they do?

Yes - there are commercial products that do this. Feel free not to use it if you don't see the need

Nicholas Albright - NMA-IO
"""
import re
import csv
import sys
import time
import queue
import threading
import subprocess

user_queue = queue.Queue()
resp_queue = queue.Queue()


def queryuser(uq, rq):
    """Run query for given username, return results."""
    while not uq.empty():
        username = uq.get()
        if not username:
            continue
        try:
            r = {}
            q = subprocess.Popen(
                ['net', 'user', '/domain', username], stdout=subprocess.PIPE, stderr=subprocess.PIPE
            ).communicate()[0]
            for line in q.splitlines():
                if 'User name' in line:
                    r['User'] = re.search(r'User name[^\w]+([\w_\-0-9\.\!\$\^]+)', line).group(1)
                elif 'Full Name' in line:
                    r['Full Name'] = re.search(r'Full Name[^\w]+([\w ]+)', line).group(1)
                elif 'Account active' in line:
                    r['Account Active'] = re.search(r'Account active[^\w]+([\w]+)', line).group(1)
                elif 'Last logon' in line:
                    r['Last Logon'] = re.search(r'Last logon[^\w\d]+([\w\d\/]+)', line).group(1)
                elif 'Password last set' in line:
                    r['Password Set'] = re.search(r'Password last set[^\d]+([\d\/]+)', line).group(1)
                elif 'Password expires' in line:
                    r['Password Expires'] = re.search(r'Password expires[^\w\d]+([\w\d\/]+)', line).group(1)
        except:
            return
        rq.put(r)
        if uq.empty():
            return


def queryforusers():
    """Query domain for users."""
    users = []
    results = subprocess.Popen(
        ['net', 'user', '/domain'], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).communicate()[0]
    seek = False
    for line in results.splitlines():
        if '----------' in line:
            seek = True
            continue
        if 'The command completed successfully.' in line:
            continue
        if not seek:
            continue
        users += [x for x in re.findall('[^\s]+', line) if (not x.startswith('$') or not x.endswith('$')) and x]
    return users


def main():
    """Our Main Codeblock."""
    proclist = []
    userlist = queryforusers()
    print 'Identified %s users!' % len(userlist)
    outfilename = 'adlookup_%s_output.csv' % int(time.time())
    try:
        for user in userlist:
            user_queue.put(user)
        for i in range(12):
            proc = threading.Thread(target=queryuser, args=(user_queue, resp_queue,))
            proclist.append(proc)
            proc.start()
        for p in proclist:
            p.join()
        fn = ['User', 'Full Name', 'Account Active', 'Last Logon', 'Password Set', 'Password Expires']
        outf = open(outfilename, 'wb')
        wr = csv.DictWriter(outf, fn, delimiter=',', lineterminator='\n', quotechar='"')
        wr.writeheader()
        while not resp_queue.empty():
            dict_data = resp_queue.get()
            wr.writerow(dict_data)
        outf.close()
        print 'Wrote file: %s' % outfilename
    except KeyboardInterrupt:
        for p in proclist:
            p.stop()
        outf.close()
        sys.exit('Captured Control-C')


if __name__ == '__main__':
    main()
