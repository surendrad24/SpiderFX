# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_gau
# Purpose:      SpiderFoot plug-in for using gau to fetch known historical URLs.
#
# Created:      2026-04-16
# Licence:      MIT
# -------------------------------------------------------------------------------

import os.path
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_gau(SpiderFootPlugin):

    meta = {
        'name': "Tool - Gau",
        'summary': "Gather known URLs from multiple providers using lc/gau.",
        'flags': ["tool", "slow"],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "gau",
            'description': "Fetch known URLs from AlienVault's OTX, Common Crawl, and Wayback Machine.",
            'website': "https://github.com/lc/gau",
            'repository': "https://github.com/lc/gau"
        }
    }

    opts = {
        'gau_path': '/usr/local/bin/gau',
        'timeout': 120,
        'subs': True,
    }

    optdescs = {
        'gau_path': 'Path to the gau binary.',
        'timeout': 'Timeout in seconds per target.',
        'subs': 'Include subdomains?'
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
        return ['URL_STATIC', 'LINKED_URL_INTERNAL']

    def _binary(self):
        exe = self.opts.get('gau_path', '')
        if not exe:
            return None
        if exe.endswith('/'):
            exe = exe + 'gau'
        return exe

    def _run_gau(self, exe, target):
        args = [exe]
        if self.opts.get('subs', True):
            args.append('--subs')
        args.append(target)

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 120)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"gau timed out for {target}")
            return []
        except Exception as e:
            self.error(f"Unable to run gau: {e}")
            return []

        if p.returncode not in [0, 1]:
            self.debug(f"gau returned non-zero status: {p.returncode}, stderr={stderr}")

        content = stdout.decode('utf-8', errors='replace')
        if not content:
            return []

        return [ln.strip() for ln in content.splitlines() if ln.strip()]

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
            self.error('You enabled sfp_tool_gau but did not set gau_path!')
            self.errorState = True
            return

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        urls = self._run_gau(exe, target)
        if not urls:
            return

        seen = self.tempStorage()
        for url in urls:
            if not (url.startswith('http://') or url.startswith('https://')):
                continue
            if url in seen:
                continue
            seen[url] = True

            evt = SpiderFootEvent('URL_STATIC', url, self.__name__, event)
            self.notifyListeners(evt)

            evt2 = SpiderFootEvent('LINKED_URL_INTERNAL', url, self.__name__, evt)
            self.notifyListeners(evt2)

# End of sfp_tool_gau class
