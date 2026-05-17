# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_dnsx
# Purpose:      SpiderFoot plug-in for using dnsx to resolve DNS records.
#
# Created:      2026-04-16
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import os.path
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_dnsx(SpiderFootPlugin):

    meta = {
        'name': "Tool - Dnsx",
        'summary': "DNS resolution and enrichment using projectdiscovery/dnsx.",
        'flags': ["tool", "slow"],
        'useCases': ["Footprint", "Passive"],
        'categories': ["DNS"],
        'toolDetails': {
            'name': "dnsx",
            'description': "Dnsx is a fast and multi-purpose DNS toolkit.",
            'website': "https://github.com/projectdiscovery/dnsx",
            'repository': "https://github.com/projectdiscovery/dnsx"
        }
    }

    opts = {
        'dnsx_path': '/usr/local/bin/dnsx',
        'timeout': 45,
    }

    optdescs = {
        'dnsx_path': 'Path to the dnsx binary.',
        'timeout': 'Timeout in seconds per query.'
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
        return ['DOMAIN_NAME', 'INTERNET_NAME']

    def producedEvents(self):
        return ['INTERNET_NAME', 'IP_ADDRESS', 'RAW_DNS_RECORDS']

    def _binary(self):
        exe = self.opts.get('dnsx_path', '')
        if not exe:
            return None
        if exe.endswith('/'):
            exe = exe + 'dnsx'
        return exe

    def _run_dnsx(self, exe, target):
        args = [
            exe,
            '-silent',
            '-j',
            '-a',
            '-aaaa',
            '-cname',
            '-resp',
            '-l',
            '-',
        ]

        try:
            p = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE, text=True)
            stdout, stderr = p.communicate(target + '\n', timeout=int(self.opts.get('timeout', 45)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"dnsx timed out for {target}")
            return []
        except Exception as e:
            self.error(f"Unable to run dnsx: {e}")
            return []

        if p.returncode not in [0, 1]:
            self.debug(f"dnsx returned non-zero status: {p.returncode}, stderr={stderr}")

        if not stdout:
            return []

        rows = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue

        return rows

    def handleEvent(self, event):
        target = event.data.strip().lower()

        if self.errorState:
            return

        if event.module == self.__name__:
            return

        if target in self.results:
            self.debug(f"Skipping {target} as already scanned.")
            return

        self.results[target] = True

        exe = self._binary()
        if not exe:
            self.error('You enabled sfp_tool_dnsx but did not set dnsx_path!')
            self.errorState = True
            return

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        rows = self._run_dnsx(exe, target)
        if not rows:
            return

        seen = self.tempStorage()
        for row in rows:
            host = str(row.get('host', '')).strip().lower()
            if host and host not in seen and self.sf.isDomain(host, self.opts['_internettlds']):
                seen[host] = True
                host_evt = SpiderFootEvent('INTERNET_NAME', host, self.__name__, event)
                self.notifyListeners(host_evt)

            if row.get('raw'):
                raw_evt = SpiderFootEvent('RAW_DNS_RECORDS', str(row.get('raw')), self.__name__, event)
                self.notifyListeners(raw_evt)

            for answer in row.get('a', []) or []:
                ip = str(answer).strip()
                if not ip:
                    continue
                if not self.sf.validIP(ip):
                    continue
                ip_evt = SpiderFootEvent('IP_ADDRESS', ip, self.__name__, event)
                self.notifyListeners(ip_evt)

# End of sfp_tool_dnsx class
