# -*- coding: utf-8 -*-

import os.path
import re
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_sherlock(SpiderFootPlugin):

    meta = {
        'name': "Tool - Sherlock",
        'summary': "Find social profiles by username using Sherlock.",
        'flags': ["tool", "slow"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Social Media"],
        'toolDetails': {
            'name': "sherlock",
            'description': "Hunt down social media accounts by username.",
            'website': "https://github.com/sherlock-project/sherlock",
            'repository': "https://github.com/sherlock-project/sherlock"
        }
    }

    opts = {
        'sherlock_path': '/usr/local/bin/sherlock',
        'timeout': 120,
    }

    optdescs = {
        'sherlock_path': 'Path to the sherlock binary.',
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

        exe = self.opts.get('sherlock_path', '')
        if exe.endswith('/'):
            exe = exe + 'sherlock'
        if not exe or not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        args = [exe, '--print-found', '--no-color', '--no-txt', username]

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 120)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"sherlock timed out for {username}")
            return
        except Exception as e:
            self.error(f"Unable to run sherlock: {e}")
            return

        out = (stdout or b'').decode('utf-8', errors='replace')
        err = (stderr or b'').decode('utf-8', errors='replace')
        content = (out + "\n" + err).strip()
        if not content:
            return

        self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', content[:4000], self.__name__, event))

        urls = set(re.findall(r'https?://[^\s\]\)]+', content))
        for url in sorted(urls):
            self.notifyListeners(SpiderFootEvent('SOCIAL_MEDIA', f"Account: <SFURL>{url}</SFURL>", self.__name__, event))
            host = re.sub(r'^https?://', '', url).split('/')[0].lower()
            acct = f"{host}: {username}"
            self.notifyListeners(SpiderFootEvent('ACCOUNT_EXTERNAL_OWNED', acct, self.__name__, event))

# End of sfp_tool_sherlock class
