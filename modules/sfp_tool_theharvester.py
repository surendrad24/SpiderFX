# -*- coding: utf-8 -*-

import json
import os.path
import re
import tempfile
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_theharvester(SpiderFootPlugin):

    meta = {
        'name': "Tool - theHarvester",
        'summary': "Gather emails, hosts and IPs using theHarvester.",
        'flags': ["tool", "slow"],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "theHarvester",
            'description': "OSINT tool for emails, subdomains, and host intelligence.",
            'website': "https://github.com/laramies/theHarvester",
            'repository': "https://github.com/laramies/theHarvester"
        }
    }

    opts = {
        'theharvester_path': '/usr/local/bin/theHarvester',
        'timeout': 180,
        'limit': 200,
        'source': 'all'
    }

    optdescs = {
        'theharvester_path': 'Path to theHarvester binary.',
        'timeout': 'Timeout in seconds per domain.',
        'limit': 'Maximum results to request from theHarvester.',
        'source': 'Data source(s), e.g. all, crtsh, securityTrails, etc.'
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
        return ['DOMAIN_NAME']

    def producedEvents(self):
        return ['EMAILADDR', 'EMAILADDR_GENERIC', 'INTERNET_NAME', 'IP_ADDRESS', 'RAW_RIR_DATA']

    def _binary(self):
        exe = self.opts.get('theharvester_path', '')
        if not exe:
            return None
        if exe.endswith('/'):
            exe = exe + 'theHarvester'
        return exe

    def handleEvent(self, event):
        domain = event.data.strip().lower()

        if self.errorState:
            return
        if event.module == self.__name__:
            return
        if domain in self.results:
            return
        self.results[domain] = True

        if not self.sf.isDomain(domain, self.opts['_internettlds']):
            return

        exe = self._binary()
        if not exe or not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        with tempfile.TemporaryDirectory(prefix='sf_th_') as td:
            outbase = os.path.join(td, 'harvest')
            args = [
                exe,
                '-d', domain,
                '-b', str(self.opts.get('source', 'all')),
                '-l', str(self.opts.get('limit', 200)),
                '-q',
                '-f', outbase,
            ]
            try:
                p = Popen(args, stdout=PIPE, stderr=PIPE)
                stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 180)))
            except TimeoutExpired:
                p.kill()
                self.debug(f"theHarvester timed out for {domain}")
                return
            except Exception as e:
                self.error(f"Unable to run theHarvester: {e}")
                return

            raw = (stdout or b'').decode('utf-8', errors='replace')
            if stderr:
                raw += "\n" + stderr.decode('utf-8', errors='replace')
            if raw.strip():
                self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', raw[:4000], self.__name__, event))

            jpath = outbase + '.json'
            content = ''
            if os.path.isfile(jpath):
                try:
                    with open(jpath, 'r', encoding='utf-8', errors='replace') as fh:
                        content = fh.read()
                except Exception:
                    content = ''
            if not content:
                content = raw

            emails = set(re.findall(r'[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}', content, re.I))
            hosts = set(re.findall(r'\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,}\b', content, re.I))
            ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content))

            for email in sorted(emails):
                et = 'EMAILADDR_GENERIC' if email.lower().startswith(('info@', 'admin@', 'support@', 'contact@')) else 'EMAILADDR'
                self.notifyListeners(SpiderFootEvent(et, email.lower(), self.__name__, event))

            for host in sorted(hosts):
                h = host.lower()
                if self.sf.isDomain(h, self.opts['_internettlds']):
                    self.notifyListeners(SpiderFootEvent('INTERNET_NAME', h, self.__name__, event))

            for ip in sorted(ips):
                if self.sf.validIP(ip):
                    self.notifyListeners(SpiderFootEvent('IP_ADDRESS', ip, self.__name__, event))

# End of sfp_tool_theharvester class
