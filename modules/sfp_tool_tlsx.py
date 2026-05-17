# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_tlsx
# Purpose:      SpiderFoot plug-in for using tlsx to extract TLS certificate info.
#
# Created:      2026-04-16
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import os.path
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_tlsx(SpiderFootPlugin):

    meta = {
        'name': "Tool - Tlsx",
        'summary': "Gather TLS/certificate metadata using projectdiscovery/tlsx.",
        'flags': ["tool", "slow", "invasive"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "tlsx",
            'description': "Fast TLS grabber and fingerprinting tool.",
            'website': "https://github.com/projectdiscovery/tlsx",
            'repository': "https://github.com/projectdiscovery/tlsx"
        }
    }

    opts = {
        'tlsx_path': '/usr/local/bin/tlsx',
        'timeout': 60,
    }

    optdescs = {
        'tlsx_path': 'Path to the tlsx binary.',
        'timeout': 'Timeout in seconds per target.'
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
        return ['INTERNET_NAME', 'IP_ADDRESS', 'DOMAIN_NAME']

    def producedEvents(self):
        return ['SSL_CERTIFICATE_ISSUED', 'INTERNET_NAME', 'TCP_PORT_OPEN']

    def _binary(self):
        exe = self.opts.get('tlsx_path', '')
        if not exe:
            return None
        if exe.endswith('/'):
            exe = exe + 'tlsx'
        return exe

    def _run_tlsx(self, exe, target):
        args = [
            exe,
            '-silent',
            '-json',
            '-u',
            target,
        ]

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 60)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"tlsx timed out for {target}")
            return []
        except Exception as e:
            self.error(f"Unable to run tlsx: {e}")
            return []

        if p.returncode not in [0, 1]:
            self.debug(f"tlsx returned non-zero status: {p.returncode}, stderr={stderr}")

        content = stdout.decode('utf-8', errors='replace')
        if not content:
            return []

        rows = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue

        return rows

    def handleEvent(self, event):
        target = event.data.strip()

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
            self.error('You enabled sfp_tool_tlsx but did not set tlsx_path!')
            self.errorState = True
            return

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        rows = self._run_tlsx(exe, target)
        if not rows:
            return

        seen_hosts = self.tempStorage()
        for row in rows:
            host = str(row.get('host', '')).strip().lower()
            if host and host not in seen_hosts and self.sf.isDomain(host, self.opts['_internettlds']):
                seen_hosts[host] = True
                host_evt = SpiderFootEvent('INTERNET_NAME', host, self.__name__, event)
                self.notifyListeners(host_evt)

            port = str(row.get('port', '')).strip()
            if port and port.isdigit():
                pevt = SpiderFootEvent('TCP_PORT_OPEN', port, self.__name__, event)
                self.notifyListeners(pevt)

            subject_cn = str(row.get('subject_cn', '')).strip()
            issuer_cn = str(row.get('issuer_cn', '')).strip()
            tls_version = str(row.get('tls_version', '')).strip()

            details = []
            if subject_cn:
                details.append(f"Subject CN: {subject_cn}")
            if issuer_cn:
                details.append(f"Issuer CN: {issuer_cn}")
            if tls_version:
                details.append(f"TLS Version: {tls_version}")
            if host:
                details.append(f"Host: {host}")

            if details:
                cert_evt = SpiderFootEvent('SSL_CERTIFICATE_ISSUED', '\n'.join(details), self.__name__, event)
                self.notifyListeners(cert_evt)

# End of sfp_tool_tlsx class
