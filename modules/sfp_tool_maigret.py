# -*- coding: utf-8 -*-

import os.path
import re
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_maigret(SpiderFootPlugin):

    meta = {
        'name': "Tool - Maigret",
        'summary': "Advanced username intelligence and account discovery.",
        'flags': ["tool", "slow"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Social Media"],
        'toolDetails': {
            'name': "maigret",
            'description': "Collect links and metadata related to usernames across many sites.",
            'website': "https://github.com/soxoj/maigret",
            'repository': "https://github.com/soxoj/maigret"
        }
    }

    opts = {
        'maigret_path': '/usr/local/bin/maigret',
        'timeout': 180,
    }

    optdescs = {
        'maigret_path': 'Path to the maigret binary.',
        'timeout': 'Timeout in seconds per username.'
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
        return ['USERNAME']

    def producedEvents(self):
        return ['ACCOUNT_EXTERNAL_OWNED', 'SOCIAL_MEDIA', 'RAW_RIR_DATA']

    def handleEvent(self, event):
        username = event.data.strip()

        if self.errorState:
            return
        if event.module == self.__name__:
            return
        if username in self.results:
            return
        self.results[username] = True

        exe = self.opts.get('maigret_path', '')
        if exe.endswith('/'):
            exe = exe + 'maigret'
        if not exe or not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        args = [exe, '--no-color', '--no-progressbar', '--print-errors', username]

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 180)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"maigret timed out for {username}")
            return
        except Exception as e:
            self.error(f"Unable to run maigret: {e}")
            return

        out = (stdout or b'').decode('utf-8', errors='replace')
        err = (stderr or b'').decode('utf-8', errors='replace')
        content = (out + "\n" + err).strip()
        if not content:
            return

        self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', content[:4000], self.__name__, event))

        urls = set(re.findall(r'https?://[^\s\]\)]+', content))
        for url in sorted(urls):
            self.notifyListeners(SpiderFootEvent('SOCIAL_MEDIA', f"Maigret: <SFURL>{url}</SFURL>", self.__name__, event))
            host = re.sub(r'^https?://', '', url).split('/')[0].lower()
            self.notifyListeners(SpiderFootEvent('ACCOUNT_EXTERNAL_OWNED', f"{host}: {username}", self.__name__, event))

# End of sfp_tool_maigret class
