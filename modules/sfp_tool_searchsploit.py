# -*- coding: utf-8 -*-

import json
import os.path
import re
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_searchsploit(SpiderFootPlugin):

    meta = {
        'name': "Tool - SearchSploit",
        'summary': "Correlate discovered software with Exploit-DB entries using searchsploit.",
        'flags': ["tool", "slow", "invasive"],
        'useCases': ["Investigate", "Footprint"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "searchsploit",
            'description': "Offline Exploit-DB search utility for known exploit references.",
            'website': "https://www.exploit-db.com/",
            'repository': "https://gitlab.com/exploit-database/exploitdb"
        }
    }

    opts = {
        'searchsploit_path': '/usr/local/bin/searchsploit',
        'timeout': 40,
        'max_results': 15,
        'min_term_length': 3,
    }

    optdescs = {
        'searchsploit_path': 'Path to searchsploit binary/script.',
        'timeout': 'Timeout in seconds per query.',
        'max_results': 'Maximum exploit rows emitted per query.',
        'min_term_length': 'Minimum term length to query.'
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
        return ['WEBSERVER_TECHNOLOGY', 'SOFTWARE_USED', 'OPERATING_SYSTEM', 'WEBSERVER_BANNER', 'TCP_PORT_OPEN_BANNER']

    def producedEvents(self):
        return ['VULNERABILITY_DISCLOSURE', 'VULNERABILITY_CVE_CRITICAL', 'VULNERABILITY_CVE_HIGH', 'VULNERABILITY_CVE_MEDIUM', 'VULNERABILITY_CVE_LOW']

    def _normalize_term(self, data):
        txt = str(data or '').replace('\n', ' ').strip()
        txt = re.sub(r'\s+', ' ', txt)
        # Keep query concise to avoid noisy matches.
        txt = ' '.join(txt.split(' ')[:5])
        txt = re.sub(r'[^A-Za-z0-9._ +:-]', ' ', txt)
        txt = re.sub(r'\s+', ' ', txt).strip()
        return txt

    def handleEvent(self, event):
        if self.errorState:
            return
        if event.module == self.__name__:
            return

        exe = self.opts.get('searchsploit_path', '')
        if exe.endswith('/'):
            exe = exe + 'searchsploit'
        if not exe or not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        term = self._normalize_term(event.data)
        if len(term) < int(self.opts.get('min_term_length', 3)):
            return

        cache_key = f"{event.eventType}:{term.lower()}"
        if cache_key in self.results:
            return
        self.results[cache_key] = True

        args = [exe, '--disable-colour', '--json', term]

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 40)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"searchsploit timed out for term: {term}")
            return
        except Exception as e:
            self.error(f"Unable to run searchsploit: {e}")
            return

        out = (stdout or b'').decode('utf-8', errors='replace').strip()
        if not out:
            return

        try:
            data = json.loads(out)
        except Exception as e:
            self.debug(f"Unable to parse searchsploit output: {e}")
            return

        rows = data.get('RESULTS_EXPLOIT', []) or []
        max_results = int(self.opts.get('max_results', 15))

        for row in rows[:max_results]:
            title = str(row.get('Title', '')).strip()
            edb = str(row.get('EDB-ID', '')).strip()
            codes = str(row.get('Codes', '')).strip()
            path = str(row.get('Path', '')).strip()

            if not title:
                continue

            url = f"https://www.exploit-db.com/exploits/{edb}" if edb else ''
            parts = [f"Search term: {term}", f"Title: {title}"]
            if edb:
                parts.append(f"EDB-ID: {edb}")
            if codes:
                parts.append(f"Codes: {codes}")
            if url:
                parts.append(f"URL: <SFURL>{url}</SFURL>")
            if path:
                parts.append(f"Local Path: {path}")

            self.notifyListeners(SpiderFootEvent('VULNERABILITY_DISCLOSURE', '\n'.join(parts), self.__name__, event))

            for cve in set(re.findall(r'CVE-\d{4}-\d{4,7}', codes, re.I)):
                etype, cvetext = self.sf.cveInfo(cve.upper())
                self.notifyListeners(SpiderFootEvent(etype, cvetext, self.__name__, event))

# End of sfp_tool_searchsploit class
