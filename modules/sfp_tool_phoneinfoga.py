# -*- coding: utf-8 -*-

import os.path
import re
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_phoneinfoga(SpiderFootPlugin):

    meta = {
        'name': "Tool - PhoneInfoga",
        'summary': "Phone number OSINT using PhoneInfoga.",
        'flags': ["tool", "slow"],
        'useCases': ["Investigate", "Footprint"],
        'categories': ["Content Analysis"],
        'toolDetails': {
            'name': "phoneinfoga",
            'description': "Advanced phone number OSINT tool using free resources.",
            'website': "https://github.com/sundowndev/phoneinfoga",
            'repository': "https://github.com/sundowndev/phoneinfoga"
        }
    }

    opts = {
        'phoneinfoga_path': '/usr/local/bin/phoneinfoga',
        'timeout': 150,
    }

    optdescs = {
        'phoneinfoga_path': 'Path to the phoneinfoga binary.',
        'timeout': 'Timeout in seconds per phone number.'
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
        return ['PHONE_NUMBER']

    def producedEvents(self):
        return ['RAW_RIR_DATA', 'SOCIAL_MEDIA']

    def handleEvent(self, event):
        number = event.data.strip()

        if self.errorState:
            return
        if event.module == self.__name__:
            return
        if number in self.results:
            return
        self.results[number] = True

        exe = self.opts.get('phoneinfoga_path', '')
        if exe.endswith('/'):
            exe = exe + 'phoneinfoga'
        if not exe or not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        args = [exe, 'scan', '-n', number]

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 150)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"phoneinfoga timed out for {number}")
            return
        except Exception as e:
            self.error(f"Unable to run phoneinfoga: {e}")
            return

        out = (stdout or b'').decode('utf-8', errors='replace')
        err = (stderr or b'').decode('utf-8', errors='replace')
        content = (out + "\n" + err).strip()
        if not content:
            return

        self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', content[:4000], self.__name__, event))

        urls = set(re.findall(r'https?://[^\s\]\)]+', content))
        for url in sorted(urls):
            self.notifyListeners(SpiderFootEvent('SOCIAL_MEDIA', f"Phone OSINT: <SFURL>{url}</SFURL>", self.__name__, event))

# End of sfp_tool_phoneinfoga class
