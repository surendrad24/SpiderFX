# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_subfinder
# Purpose:      SpiderFoot plug-in for using subfinder to discover subdomains.
#
# Created:      2026-04-16
# Licence:      MIT
# -------------------------------------------------------------------------------

import os.path
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_subfinder(SpiderFootPlugin):

    meta = {
        'name': "Tool - Subfinder",
        'summary': "Fast passive subdomain discovery using projectdiscovery/subfinder.",
        'flags': ["tool", "slow"],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Passive DNS"],
        'toolDetails': {
            'name': "subfinder",
            'description': "Subfinder is a subdomain discovery tool that discovers valid subdomains for websites.",
            'website': "https://github.com/projectdiscovery/subfinder",
            'repository': "https://github.com/projectdiscovery/subfinder"
        }
    }

    opts = {
        'subfinder_path': '/usr/local/bin/subfinder',
        'timeout': 90,
        'silent': True
    }

    optdescs = {
        'subfinder_path': 'Path to the subfinder binary. Must be set.',
        'timeout': 'Timeout in seconds per query.',
        'silent': 'Run subfinder with -silent?'
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

    def handleEvent(self, event):
        event_data = event.data

        if self.errorState:
            return

        if event.module == self.__name__:
            return

        if event_data in self.results:
            self.debug(f"Skipping {event_data} as already scanned.")
            return

        self.results[event_data] = True

        if not self.opts.get('subfinder_path'):
            self.error('You enabled sfp_tool_subfinder but did not set subfinder_path!')
            self.errorState = True
            return

        exe = self.opts['subfinder_path']
        if exe.endswith('/'):
            exe = exe + 'subfinder'

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        if not self.sf.isDomain(event_data, self.opts['_internettlds']):
            self.debug(f"Invalid domain input, skipping: {event_data}")
            return

        args = [exe, '-d', event_data]
        if self.opts.get('silent', True):
            args.append('-silent')

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 90)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"subfinder timed out for {event_data}")
            return
        except Exception as e:
            self.error(f"Unable to run subfinder: {e}")
            return

        if p.returncode not in [0, 1]:
            self.debug(f"subfinder returned non-zero status: {p.returncode}, stderr={stderr}")

        content = stdout.decode('utf-8', errors='replace')
        if not content:
            return

        seen = self.tempStorage()
        for line in content.splitlines():
            host = line.strip().lower()
            if not host:
                continue
            if host in seen:
                continue
            seen[host] = True

            if not self.sf.isDomain(host, self.opts['_internettlds']):
                continue

            evt = SpiderFootEvent('INTERNET_NAME', host, self.__name__, event)
            self.notifyListeners(evt)

            if host.endswith('.' + event_data) or host == event_data:
                evt2 = SpiderFootEvent('DOMAIN_NAME', host, self.__name__, evt)
                self.notifyListeners(evt2)

# End of sfp_tool_subfinder class
