# -*- coding: utf-8 -*-

import os
import os.path
import re
import tempfile
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_bbot(SpiderFootPlugin):

    meta = {
        'name': "Tool - BBOT",
        'summary': "Run BBOT passive subdomain enumeration and ingest discovered domains.",
        'flags': ["tool", "slow", "passive"],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["Passive DNS"],
        'toolDetails': {
            'name': "bbot",
            'description': "Bighuge BLS OSINT Tool framework for recon and discovery.",
            'website': "https://github.com/blacklanternsecurity/bbot",
            'repository': "https://github.com/blacklanternsecurity/bbot"
        }
    }

    opts = {
        'bbot_path': '/usr/local/bin/bbot',
        'timeout': 180,
        'preset': 'subdomain-enum',
        'passive_only': True,
        'max_lines': 2000,
    }

    optdescs = {
        'bbot_path': 'Path to bbot binary.',
        'timeout': 'Timeout in seconds per target.',
        'preset': 'BBOT preset to run (e.g. subdomain-enum).',
        'passive_only': 'Apply -rf passive to reduce active/intrusive modules.',
        'max_lines': 'Maximum stdout/stderr lines to parse.'
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
        return ['INTERNET_NAME', 'DOMAIN_NAME', 'RAW_RIR_DATA']

    def handleEvent(self, event):
        target = str(event.data).strip().lower()

        if self.errorState:
            return
        if event.module == self.__name__:
            return
        if target in self.results:
            return
        self.results[target] = True

        exe = self.opts.get('bbot_path', '')
        if exe.endswith('/'):
            exe = exe + 'bbot'
        if not exe or not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        tmpdir = tempfile.mkdtemp(prefix='sf-bbot-')
        args = [
            exe,
            '-t', target,
            '-p', str(self.opts.get('preset', 'subdomain-enum')),
            '--fast-mode',
            '--no-deps',
            '--ignore-failed-deps',
            '-y',
            '-s',
            '--brief',
            '--event-types', 'DNS_NAME',
            '-o', tmpdir,
            '-om', 'stdout',
        ]
        if self.opts.get('passive_only', True):
            args.extend(['-rf', 'passive'])

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 180)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"bbot timed out for {target}")
            return
        except Exception as e:
            self.error(f"Unable to run bbot: {e}")
            return
        finally:
            try:
                for root, dirs, files in os.walk(tmpdir, topdown=False):
                    for fn in files:
                        os.unlink(os.path.join(root, fn))
                    for dn in dirs:
                        os.rmdir(os.path.join(root, dn))
                os.rmdir(tmpdir)
            except Exception:
                pass

        out = (stdout or b'').decode('utf-8', errors='replace')
        err = (stderr or b'').decode('utf-8', errors='replace')
        content = (out + "\n" + err).strip()
        if content:
            self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', content[:4000], self.__name__, event))

        seen = self.tempStorage()
        max_lines = int(self.opts.get('max_lines', 2000))
        for idx, line in enumerate((out + "\n" + err).splitlines()):
            if idx > max_lines:
                break
            line = line.strip().lower()
            if not line:
                continue

            for d in re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b', line):
                if d in seen:
                    continue
                seen[d] = True
                if not self.sf.isDomain(d, self.opts['_internettlds']):
                    continue

                evt = SpiderFootEvent('INTERNET_NAME', d, self.__name__, event)
                self.notifyListeners(evt)
                if d.endswith('.' + target) or d == target:
                    self.notifyListeners(SpiderFootEvent('DOMAIN_NAME', d, self.__name__, evt))

# End of sfp_tool_bbot class
