# -*- coding: utf-8 -*-

import os.path
import re
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_uncover(SpiderFootPlugin):

    meta = {
        'name': "Tool - Uncover",
        'summary': "Discover exposed hosts/services from internet search engines using ProjectDiscovery uncover.",
        'flags': ["tool", "slow", "passive"],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["Passive DNS"],
        'toolDetails': {
            'name': "uncover",
            'description': "Query Shodan/Censys/FOFA and other engines through a single CLI.",
            'website': "https://github.com/projectdiscovery/uncover",
            'repository': "https://github.com/projectdiscovery/uncover"
        }
    }

    opts = {
        'uncover_path': '/usr/local/bin/uncover',
        'engine': 'shodan-idb',
        'field': 'ip:port',
        'limit': 100,
        'timeout': 45,
        'domain_query_prefix': 'hostname:'
    }

    optdescs = {
        'uncover_path': 'Path to uncover binary.',
        'engine': 'Search engine to use (e.g. shodan-idb, shodan, censys, fofa, zoomeye, netlas, greynoise).',
        'field': 'Output field to request (ip, port, host, ip:port).',
        'limit': 'Maximum number of results returned by uncover.',
        'timeout': 'Timeout in seconds per target query.',
        'domain_query_prefix': 'Prefix added for DOMAIN_NAME/INTERNET_NAME queries (e.g. hostname:).'
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['IP_ADDRESS', 'DOMAIN_NAME', 'INTERNET_NAME']

    def producedEvents(self):
        return ['TCP_PORT_OPEN', 'INTERNET_NAME', 'RAW_RIR_DATA']

    def handleEvent(self, event):
        target = str(event.data).strip().lower()

        if self.errorState:
            return
        if event.module == self.__name__:
            return

        key = f"{event.eventType}:{target}"
        if key in self.results:
            return
        self.results[key] = True

        exe = self.opts.get('uncover_path', '')
        if exe.endswith('/'):
            exe = exe + 'uncover'
        if not exe or not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        query = target
        if event.eventType in ['DOMAIN_NAME', 'INTERNET_NAME']:
            prefix = str(self.opts.get('domain_query_prefix', 'hostname:')).strip()
            query = f"{prefix}{target}" if prefix else target

        args = [
            exe,
            '-silent',
            '-e', str(self.opts.get('engine', 'shodan-idb')),
            '-f', str(self.opts.get('field', 'ip:port')),
            '-l', str(self.opts.get('limit', 100)),
            '-q', query,
        ]

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 45)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"uncover timed out for {target}")
            return
        except Exception as e:
            self.error(f"Unable to run uncover: {e}")
            return

        out = (stdout or b'').decode('utf-8', errors='replace').strip()
        err = (stderr or b'').decode('utf-8', errors='replace').strip()
        content = (out + "\n" + err).strip()
        if not content:
            return

        self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', content[:4000], self.__name__, event))

        seen = self.tempStorage()
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            if line in seen:
                continue
            seen[line] = True

            m = re.match(r'^([^\s:]+):(\d{1,5})$', line)
            if m:
                host = m.group(1).lower()
                port = m.group(2)
                self.notifyListeners(SpiderFootEvent('TCP_PORT_OPEN', f"{host}:{port}", self.__name__, event))
                if self.sf.isDomain(host, self.opts['_internettlds']):
                    self.notifyListeners(SpiderFootEvent('INTERNET_NAME', host, self.__name__, event))
                continue

            host = re.sub(r'^https?://', '', line).split('/')[0].split(':')[0].lower()
            if host and self.sf.isDomain(host, self.opts['_internettlds']):
                self.notifyListeners(SpiderFootEvent('INTERNET_NAME', host, self.__name__, event))

# End of sfp_tool_uncover class
