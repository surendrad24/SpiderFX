# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_amass
# Purpose:      SpiderFoot plug-in for using amass to discover subdomains.
#
# Created:      2026-04-16
# Licence:      MIT
# -------------------------------------------------------------------------------

import os.path
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_amass(SpiderFootPlugin):

    meta = {
        'name': "Tool - Amass",
        'summary': "Subdomain discovery with OWASP Amass.",
        'flags': ["tool", "slow"],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Passive DNS"],
        'toolDetails': {
            'name': "amass",
            'description': "In-depth attack surface mapping and external asset discovery.",
            'website': "https://github.com/owasp-amass/amass",
            'repository': "https://github.com/owasp-amass/amass"
        }
    }

    opts = {
        'amass_path': '/usr/local/bin/amass',
        'timeout': 180,
        'passive_only': True,
    }

    optdescs = {
        'amass_path': 'Path to the amass binary. Must be set.',
        'timeout': 'Timeout in seconds per domain.',
        'passive_only': 'Run amass in passive mode?'
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
        return ['INTERNET_NAME', 'DOMAIN_NAME']

    def _binary(self):
        exe = self.opts.get('amass_path', '')
        if not exe:
            return None
        if exe.endswith('/'):
            exe = exe + 'amass'
        return exe

    def _run_amass(self, exe, domain):
        args = [exe, 'enum', '-d', domain]
        if self.opts.get('passive_only', True):
            args.append('-passive')

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 180)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"amass timed out for {domain}")
            return []
        except Exception as e:
            self.error(f"Unable to run amass: {e}")
            return []

        if p.returncode not in [0, 1]:
            self.debug(f"amass returned non-zero status: {p.returncode}, stderr={stderr}")

        content = stdout.decode('utf-8', errors='replace')
        if not content:
            return []

        hosts = []
        for line in content.splitlines():
            h = line.strip().lower()
            if not h:
                continue
            if ' ' in h:
                # Some amass outputs contain extra columns; last token often domain.
                h = h.split()[-1]
            hosts.append(h)

        return hosts

    def handleEvent(self, event):
        domain = event.data.lower().strip()

        if self.errorState:
            return

        if event.module == self.__name__:
            return

        if not self.opts.get('amass_path'):
            self.error('You enabled sfp_tool_amass but did not set amass_path!')
            self.errorState = True
            return

        exe = self._binary()
        if not exe or not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        if not self.sf.isDomain(domain, self.opts['_internettlds']):
            self.debug(f"Invalid domain input, skipping: {domain}")
            return

        if domain in self.results:
            self.debug(f"Skipping {domain} as already scanned.")
            return

        self.results[domain] = True

        hosts = self._run_amass(exe, domain)
        if not hosts:
            return

        seen = self.tempStorage()
        for host in hosts:
            if host in seen:
                continue
            seen[host] = True

            if not self.sf.isDomain(host, self.opts['_internettlds']):
                continue

            evt = SpiderFootEvent('INTERNET_NAME', host, self.__name__, event)
            self.notifyListeners(evt)

            if host.endswith('.' + domain) or host == domain:
                evt2 = SpiderFootEvent('DOMAIN_NAME', host, self.__name__, evt)
                self.notifyListeners(evt2)

# End of sfp_tool_amass class
