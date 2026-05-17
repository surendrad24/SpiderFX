# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_httpx
# Purpose:      SpiderFoot plug-in for using httpx to probe HTTP services.
#
# Created:      2026-04-16
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import os.path
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_httpx(SpiderFootPlugin):

    meta = {
        'name': "Tool - Httpx",
        'summary': "Probe hosts for HTTP services and emit status/technology findings.",
        'flags': ["tool", "slow", "invasive"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "httpx",
            'description': "httpx is a fast and multi-purpose HTTP toolkit by ProjectDiscovery.",
            'website': "https://github.com/projectdiscovery/httpx",
            'repository': "https://github.com/projectdiscovery/httpx"
        }
    }

    opts = {
        'httpx_path': '/usr/local/bin/httpx',
        'timeout': 45,
    }

    optdescs = {
        'httpx_path': 'Path to the httpx binary. Must be set.',
        'timeout': 'Timeout in seconds per probe.'
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
        return ['INTERNET_NAME', 'DOMAIN_NAME', 'IP_ADDRESS']

    def producedEvents(self):
        return ['URL_STATIC', 'HTTP_CODE', 'WEBSERVER_TECHNOLOGY', 'WEBSERVER_BANNER']

    def handleEvent(self, event):
        target = event.data

        if self.errorState:
            return

        if event.module == self.__name__:
            return

        if target in self.results:
            self.debug(f"Skipping {target} as already scanned.")
            return

        self.results[target] = True

        if not self.opts.get('httpx_path'):
            self.error('You enabled sfp_tool_httpx but did not set httpx_path!')
            self.errorState = True
            return

        exe = self.opts['httpx_path']
        if exe.endswith('/'):
            exe = exe + 'httpx'

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        args = [
            exe,
            '-json',
            '-silent',
            '-status-code',
            '-title',
            '-tech-detect',
            '-server',
            '-u',
            target,
        ]

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 45)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"httpx timed out for {target}")
            return
        except Exception as e:
            self.error(f"Unable to run httpx: {e}")
            return

        if p.returncode not in [0, 1]:
            self.debug(f"httpx returned non-zero status: {p.returncode}, stderr={stderr}")

        content = stdout.decode('utf-8', errors='replace').strip()
        if not content:
            return

        for line in content.splitlines():
            try:
                row = json.loads(line)
            except Exception:
                continue

            url = row.get('url')
            if url:
                evt = SpiderFootEvent('URL_STATIC', url, self.__name__, event)
                self.notifyListeners(evt)
            else:
                evt = event

            status = row.get('status-code')
            if status is not None:
                http_evt = SpiderFootEvent('HTTP_CODE', str(status), self.__name__, evt)
                self.notifyListeners(http_evt)

            server = row.get('webserver')
            if server:
                banner_evt = SpiderFootEvent('WEBSERVER_BANNER', str(server), self.__name__, evt)
                self.notifyListeners(banner_evt)

            techs = row.get('tech')
            if isinstance(techs, list):
                for tech in techs:
                    if not tech:
                        continue
                    tech_evt = SpiderFootEvent('WEBSERVER_TECHNOLOGY', str(tech), self.__name__, evt)
                    self.notifyListeners(tech_evt)

# End of sfp_tool_httpx class
