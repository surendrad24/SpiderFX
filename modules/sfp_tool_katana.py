# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_katana
# Purpose:      SpiderFoot plug-in for using katana to crawl and discover URLs.
#
# Created:      2026-04-16
# Licence:      MIT
# -------------------------------------------------------------------------------

import os.path
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_katana(SpiderFootPlugin):

    meta = {
        'name': "Tool - Katana",
        'summary': "Fast web crawling and URL discovery using projectdiscovery/katana.",
        'flags': ["tool", "slow", "invasive"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "katana",
            'description': "Katana is a next-generation crawling and spidering framework.",
            'website': "https://github.com/projectdiscovery/katana",
            'repository': "https://github.com/projectdiscovery/katana"
        }
    }

    opts = {
        'katana_path': '/usr/local/bin/katana',
        'timeout': 120,
        'depth': 2,
    }

    optdescs = {
        'katana_path': 'Path to the katana binary.',
        'timeout': 'Timeout in seconds per target.',
        'depth': 'Crawl depth (katana -d).'
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
        return ['URL_STATIC', 'LINKED_URL_INTERNAL', 'INTERNET_NAME', 'DOMAIN_NAME']

    def producedEvents(self):
        return ['URL_STATIC', 'LINKED_URL_INTERNAL']

    def _binary(self):
        exe = self.opts.get('katana_path', '')
        if not exe:
            return None
        if exe.endswith('/'):
            exe = exe + 'katana'
        return exe

    def _is_url(self, val):
        return isinstance(val, str) and (val.startswith('http://') or val.startswith('https://'))

    def _to_url(self, val):
        if self._is_url(val):
            return val
        return 'https://' + val.strip()

    def _crawl(self, exe, target):
        args = [
            exe,
            '-u', target,
            '-silent',
            '-d', str(self.opts.get('depth', 2)),
        ]

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 120)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"katana timed out for {target}")
            return []
        except Exception as e:
            self.error(f"Unable to run katana: {e}")
            return []

        if p.returncode not in [0, 1]:
            self.debug(f"katana returned non-zero status: {p.returncode}, stderr={stderr}")

        content = stdout.decode('utf-8', errors='replace')
        if not content:
            return []

        return [ln.strip() for ln in content.splitlines() if ln.strip()]

    def handleEvent(self, event):
        event_data = event.data

        if self.errorState:
            return

        if event.module == self.__name__:
            return

        exe = self._binary()
        if not exe:
            self.error('You enabled sfp_tool_katana but did not set katana_path!')
            self.errorState = True
            return

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        target = self._to_url(event_data)

        if target in self.results:
            self.debug(f"Skipping {target} as already scanned.")
            return

        self.results[target] = True

        urls = self._crawl(exe, target)
        if not urls:
            return

        seen = self.tempStorage()
        for url in urls:
            if not self._is_url(url):
                continue
            if url in seen:
                continue
            seen[url] = True

            evt = SpiderFootEvent('URL_STATIC', url, self.__name__, event)
            self.notifyListeners(evt)

            linked_evt = SpiderFootEvent('LINKED_URL_INTERNAL', url, self.__name__, evt)
            self.notifyListeners(linked_evt)

# End of sfp_tool_katana class
