# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_waybackurls
# Purpose:      SpiderFoot plug-in for using waybackurls to fetch archived URLs.
#
# Created:      2026-04-16
# Licence:      MIT
# -------------------------------------------------------------------------------

import os.path
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_waybackurls(SpiderFootPlugin):

    meta = {
        'name': "Tool - Waybackurls",
        'summary': "Fetch historical URLs from the Wayback Machine index.",
        'flags': ["tool", "slow"],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "waybackurls",
            'description': "Fetch all known URLs from the Wayback Machine for a domain.",
            'website': "https://github.com/tomnomnom/waybackurls",
            'repository': "https://github.com/tomnomnom/waybackurls"
        }
    }

    opts = {
        'waybackurls_path': '/usr/local/bin/waybackurls',
        'timeout': 120,
    }

    optdescs = {
        'waybackurls_path': 'Path to the waybackurls binary.',
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
        return ['DOMAIN_NAME', 'INTERNET_NAME']

    def producedEvents(self):
        return ['URL_STATIC', 'LINKED_URL_INTERNAL']

    def _binary(self):
        exe = self.opts.get('waybackurls_path', '')
        if not exe:
            return None
        if exe.endswith('/'):
            exe = exe + 'waybackurls'
        return exe

    def _run_waybackurls(self, exe, target):
        try:
            p = Popen([exe], stdin=PIPE, stdout=PIPE, stderr=PIPE, text=True)
            stdout, stderr = p.communicate(target + '\n', timeout=int(self.opts.get('timeout', 120)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"waybackurls timed out for {target}")
            return []
        except Exception as e:
            self.error(f"Unable to run waybackurls: {e}")
            return []

        if p.returncode not in [0, 1]:
            self.debug(f"waybackurls returned non-zero status: {p.returncode}, stderr={stderr}")

        if not stdout:
            return []

        return [ln.strip() for ln in stdout.splitlines() if ln.strip()]

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
            self.error('You enabled sfp_tool_waybackurls but did not set waybackurls_path!')
            self.errorState = True
            return

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        urls = self._run_waybackurls(exe, target)
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

# End of sfp_tool_waybackurls class
