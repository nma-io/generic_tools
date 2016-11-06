#!/usr/bin/python
"""
UserAgent Malicious Probability Tool.

MIT License

Copyright (c) 2016,  Nicholas Albright

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

The goal is to identify suspicious UserAgents using identified classifers.
Over time, we might be able to use these classifiers to build an ML model.
"""
import sys
import json
import pyngram
import woothee
import argparse

__author__ = 'Nicholas Albright, 2016'
__license__ = 'MIT'
<<<<<<< HEAD
__version__ = 0.2
=======
__version__ = 0.1
>>>>>>> 7f219a7fd9fe0c53b9f578c405ce2c7e78749e94


def _score(jblob):
    """Internal function to return a score based on descriptive value of Useragents.

<<<<<<< HEAD
    Response will be a list of tuples: [(useragent, score, risk)]
=======
    Response will be a list of tuples: [(useragent, score)]
>>>>>>> 7f219a7fd9fe0c53b9f578c405ce2c7e78749e94
    """
    r = []
    for agent in jblob['results']:
        score, risk = 0, 'Low'
        m = jblob['results'][agent]
        score += len(m['ngrams'])  # Repeating ngrams scares me.
        score += m['length'] / 10
        if m['malformed_semicolon']: score += 10
        if m['blacklisted']: score += 100
        if m['malformed_hacklang']: score += 10
        if m['malformed_noparen']: score += 10
        if m['unbalanced']: score += 30
        if m['tokens'] < 3: score += m['tokens'] + score * 10
        if m['tokens'] > 15: score += m['tokens'] - 15
        if m['os'].upper() == 'UNKNOWN' or m['vendor'].upper() == 'UNKNOWN': score += 10
        if m['category'].upper() == 'UNKNOWN' or m['os_version'].upper() == 'UNKNOWN': score += 10
        if m['version'].upper() == 'UNKNOWN' or m['name'].upper() == 'UNNKOWN': score += 20
        if m['whitelisted']: score = 0
        if score > 100: score = 100
        if score > 60: risk = 'Moderate'
        if score > 80: risk = 'High'
        if score > 95: risk = 'Extreme'
<<<<<<< HEAD
        if agent and score and risk:
            r.append((agent, score, risk))
    if r:
        return r
=======
        r.append((agent, score, risk))
    return r
>>>>>>> 7f219a7fd9fe0c53b9f578c405ce2c7e78749e94


def define_useragent(useragents, output='score'):
    """Define individual elements of hte useragent.

    Useragents should be a list of suspect useragents to evaluate.
    Default output will be JSON Blob containing descriptive information.
    Set output='score' to receive a threat score for each UA.
<<<<<<< HEAD

    If you're calling this from your own application, be sure 'useragents' is a list.
    If you're expecting score to be returned, leave output alone, if you want the
    features, change output to json.
=======
>>>>>>> 7f219a7fd9fe0c53b9f578c405ce2c7e78749e94
    """
    response_dict = {'results': {}}
    whitelist = ('curl', 'mobileasset', 'microsoft ncsi')  # Always whitelist these agents
    blacklist = ('mozilla/4.0')  # Always blacklist these user agents
    for agent in useragents:
        pua = woothee.parse(agent)
        open_count = len([x for x in list(agent) if x in ['(', '[']])
        close_count = len([x for x in list(agent) if x in [')', ']']])
        response_dict['results'].update({agent: {}})
        white = black = False
<<<<<<< HEAD
        if agent.split(' ')[0].lower() in whitelist:
            white = True
        elif agent.split(' ')[0].lower() in blacklist:
=======
        if agent.split('/')[0].lower() in whitelist:
            white = True
        elif agent.split('/')[0].lower() in blacklist:
>>>>>>> 7f219a7fd9fe0c53b9f578c405ce2c7e78749e94
            black = True
        response_dict['results'][agent].update(pua)
        response_dict['results'][agent].update({'whitelisted': white})
        response_dict['results'][agent].update({'blacklisted': black})
        response_dict['results'][agent].update({'tokens': len(agent.split(' '))})
        response_dict['results'][agent].update({'ngrams': [x for x in pyngram.calc_ngram(agent, 2) if x[1] > 1]})
        if open_count != close_count:  # unbalanced
            response_dict['results'][agent].update({'unbalanced': True})
        else:
            response_dict['results'][agent].update({'unbalanced': False})
        if ';' in agent and '; ' not in agent:  # Malformed, should be '; ' between settings
            response_dict['results'][agent].update({'malformed_semicolon': True})
        else:
            response_dict['results'][agent].update({'malformed_semicolon': False})
        if '/' in agent and ' ' in agent and '(' not in agent:
            response_dict['results'][agent].update({'malformed_noparen': True})
        else:
            response_dict['results'][agent].update({'malformed_noparen': False})
        if '==' in agent or '<' in agent or '>' in agent or '`' in agent:  # SQLi/XSS Tactics
            response_dict['results'][agent].update({'malformed_hacklang': True})
        else:
            response_dict['results'][agent].update({'malformed_hacklang': False})
        response_dict['results'][agent].update({'length': len(agent)})  # Length is kinda interesting

    if output == 'json':
        return response_dict
    else:
        return _score(response_dict)


if __name__ == '__main__':
    opts = argparse.ArgumentParser(description='UserAgent Threat Score Tool (v%s) - %s' % (__version__, __author__))
    opts.add_argument('value', help='If parsing useragents on commandline, use pipe\'s (|) to separate')
    opts.add_argument('-f', '--file', action='store_true', help='Review file containing list of useragents')
    opts.add_argument('-j', '--json', action='store_true', help='Return classifier output in JSON format (default only returns risk score)')
    if len(sys.argv) < 2:
        opts.print_help()
        sys.exit()
    args = opts.parse_args()

    if args.json: outtype = 'json'
    else: outtype = 'score'

    if args.file:
        ualist = open(args.value, 'r').read().splitlines()
    else:
        ualist = args.value.split('|')

    output = define_useragent(ualist, output=outtype)
    if outtype == 'score':
        for line in output:
            print '[%s]\t%s\t%s' % (line[0], line[2], line[1])
    elif outtype == 'json':
        print json.dumps(output, indent=4)
