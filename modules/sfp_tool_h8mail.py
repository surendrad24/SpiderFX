# -*- coding: utf-8 -*-

import json
import os
import os.path
import re
import tempfile
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_h8mail(SpiderFootPlugin):

    meta = {
        'name': "Tool - h8mail",
        'summary': "Query breach aggregators for compromised emails using h8mail.",
        'flags': ["tool", "slow"],
        'useCases': ["Investigate", "Footprint"],
        'categories': ["Leaks, Dumps and Breaches"],
        'toolDetails': {
            'name': "h8mail",
            'description': "Email OSINT and breach lookup utility.",
            'website': "https://github.com/khast3x/h8mail",
            'repository': "https://github.com/khast3x/h8mail"
        }
    }

    opts = {
        'h8mail_path': '/usr/local/bin/h8mail',
        'timeout': 120,
        'skip_defaults': True,
        'hide_passwords': False,
    }

    optdescs = {
        'h8mail_path': 'Path to h8mail binary.',
        'timeout': 'Timeout in seconds per email query.',
        'skip_defaults': 'Use --skip-defaults to avoid remote defaults/API checks.',
        'hide_passwords': 'Mask password values before emitting PASSWORD_COMPROMISED events.'
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
        return ['EMAILADDR_COMPROMISED', 'PASSWORD_COMPROMISED', 'RAW_RIR_DATA']

    def _mask(self, value):
        txt = str(value)
        if not self.opts.get('hide_passwords', False):
            return txt
        if len(txt) <= 4:
            return '****'
        return txt[:4] + ('*' * (len(txt) - 4))

    def handleEvent(self, event):
        email = str(event.data).strip().lower()

        if self.errorState:
            return
        if event.module == self.__name__:
            return
        if email in self.results:
            return
        self.results[email] = True

        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            return

        exe = self.opts.get('h8mail_path', '')
        if exe.endswith('/'):
            exe = exe + 'h8mail'
        if not exe or not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        outfd, outpath = tempfile.mkstemp(prefix='sf-h8mail-', suffix='.json')
        os.close(outfd)

        args = [exe, '-t', email, '-j', outpath]
        if self.opts.get('skip_defaults', True):
            args.append('--skip-defaults')

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 120)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"h8mail timed out for {email}")
            return
        except Exception as e:
            self.error(f"Unable to run h8mail: {e}")
            return

        out = (stdout or b'').decode('utf-8', errors='replace')
        err = (stderr or b'').decode('utf-8', errors='replace')
        content = (out + "\n" + err).strip()
        if content:
            self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', content[:4000], self.__name__, event))

        if not os.path.isfile(outpath):
            return

        try:
            with open(outpath, 'r', encoding='utf-8', errors='replace') as f:
                data = json.load(f)
        except Exception:
            return
        finally:
            try:
                os.unlink(outpath)
            except Exception:
                pass

        targets = data.get('targets', []) if isinstance(data, dict) else []
        for target in targets:
            leaks = target.get('data', []) if isinstance(target, dict) else []
            for leak in leaks:
                if not isinstance(leak, dict):
                    continue
                source = str(leak.get('source') or leak.get('breach') or leak.get('name') or 'Unknown')
                self.notifyListeners(SpiderFootEvent('EMAILADDR_COMPROMISED', f"{email} [{source}]", self.__name__, event))

                for k, v in leak.items():
                    if v is None:
                        continue
                    lk = str(k).lower()
                    if lk not in ['password', 'pass', 'passwd', 'pwd']:
                        continue
                    pw = str(v).strip()
                    if not pw:
                        continue
                    evt = f"{email}:{self._mask(pw)} [{source}]"
                    self.notifyListeners(SpiderFootEvent('PASSWORD_COMPROMISED', evt, self.__name__, event))

# End of sfp_tool_h8mail class
