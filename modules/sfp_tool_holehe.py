# -*- coding: utf-8 -*-

import os.path
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_holehe(SpiderFootPlugin):

    meta = {
        'name': "Tool - Holehe",
        'summary': "Check where an email is registered using holehe.",
        'flags': ["tool", "slow"],
        'useCases': ["Investigate", "Footprint"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "holehe",
            'description': "Email account existence checker across many services.",
            'website': "https://github.com/megadose/holehe",
            'repository': "https://github.com/megadose/holehe"
        }
    }

    opts = {
        'holehe_path': '/usr/local/bin/holehe',
        'timeout': 90,
        'only_used': True,
    }

    optdescs = {
        'holehe_path': 'Path to the holehe binary.',
        'timeout': 'Timeout in seconds per email.',
        'only_used': 'Use --only-used to return only matched services.'
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
        return ['EMAILADDR']

    def producedEvents(self):
        return ['ACCOUNT_EXTERNAL_OWNED', 'RAW_RIR_DATA']

    def handleEvent(self, event):
        email = event.data.strip().lower()

        if self.errorState:
            return
        if event.module == self.__name__:
            return
        if email in self.results:
            return
        self.results[email] = True

        exe = self.opts.get('holehe_path', '')
        if exe.endswith('/'):
            exe = exe + 'holehe'
        if not exe or not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        args = [exe, '--no-color', '--no-clear']
        if self.opts.get('only_used', True):
            args.append('--only-used')
        args.append(email)

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 90)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"holehe timed out for {email}")
            return
        except Exception as e:
            self.error(f"Unable to run holehe: {e}")
            return

        out = (stdout or b'').decode('utf-8', errors='replace')
        err = (stderr or b'').decode('utf-8', errors='replace')
        content = (out + "\n" + err).strip()
        if not content:
            return

        self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', content[:4000], self.__name__, event))

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith('[+]'):
                site = line.replace('[+]', '').strip()
                if site:
                    data = f"{site}: {email}"
                    self.notifyListeners(SpiderFootEvent('ACCOUNT_EXTERNAL_OWNED', data, self.__name__, event))

# End of sfp_tool_holehe class
