# -*- coding: utf-8 -*-

import os.path
import re
import tempfile
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_metagoofil(SpiderFootPlugin):

    meta = {
        'name': "Tool - Metagoofil",
        'summary': "Discover public document metadata using Metagoofil.",
        'flags': ["tool", "slow", "invasive"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "metagoofil",
            'description': "Search and download documents, then extract metadata and references.",
            'website': "https://github.com/opsdisk/metagoofil",
            'repository': "https://github.com/opsdisk/metagoofil"
        }
    }

    opts = {
        'metagoofil_path': '/usr/local/bin/metagoofil',
        'timeout': 180,
        'file_types': 'pdf,doc,docx,xls,xlsx,ppt,pptx',
        'search_max': 40,
        'download_limit': 20,
    }

    optdescs = {
        'metagoofil_path': 'Path to the metagoofil binary/script.',
        'timeout': 'Timeout in seconds per domain.',
        'file_types': 'Comma separated file types to search for.',
        'search_max': 'Maximum search results.',
        'download_limit': 'Maximum files per filetype to download.'
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
        return ['INTERESTING_FILE', 'EMAILADDR', 'EMAILADDR_GENERIC', 'RAW_FILE_META_DATA']

    def handleEvent(self, event):
        domain = event.data.strip().lower()

        if self.errorState:
            return
        if event.module == self.__name__:
            return
        if domain in self.results:
            return
        self.results[domain] = True

        if not self.sf.isDomain(domain, self.opts['_internettlds']):
            return

        exe = self.opts.get('metagoofil_path', '')
        if exe.endswith('/'):
            exe = exe + 'metagoofil'
        if not exe or not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        with tempfile.TemporaryDirectory(prefix='sf_mg_') as td:
            args = [
                exe,
                '-d', domain,
                '-t', str(self.opts.get('file_types', 'pdf,doc,docx,xls,xlsx,ppt,pptx')),
                '-l', str(self.opts.get('search_max', 40)),
                '-n', str(self.opts.get('download_limit', 20)),
                '-o', td,
                '-w',
            ]
            try:
                p = Popen(args, stdout=PIPE, stderr=PIPE)
                stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 180)))
            except TimeoutExpired:
                p.kill()
                self.debug(f"metagoofil timed out for {domain}")
                return
            except Exception as e:
                self.error(f"Unable to run metagoofil: {e}")
                return

            out = (stdout or b'').decode('utf-8', errors='replace')
            err = (stderr or b'').decode('utf-8', errors='replace')
            content = (out + "\n" + err).strip()
            if not content:
                return

            self.notifyListeners(SpiderFootEvent('RAW_FILE_META_DATA', content[:4000], self.__name__, event))

            file_urls = set(re.findall(r'https?://[^\s\]\)]+\.(?:pdf|docx?|xlsx?|pptx?)', content, re.I))
            for u in sorted(file_urls):
                self.notifyListeners(SpiderFootEvent('INTERESTING_FILE', u, self.__name__, event))

            emails = set(re.findall(r'[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}', content, re.I))
            for email in sorted(emails):
                et = 'EMAILADDR_GENERIC' if email.lower().startswith(('info@', 'admin@', 'support@', 'contact@')) else 'EMAILADDR'
                self.notifyListeners(SpiderFootEvent(et, email.lower(), self.__name__, event))

# End of sfp_tool_metagoofil class
