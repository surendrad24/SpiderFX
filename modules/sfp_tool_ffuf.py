# -*- coding: utf-8 -*-

import json
import os
import os.path
import tempfile
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_ffuf(SpiderFootPlugin):

    meta = {
        'name': "Tool - Ffuf",
        'summary': "Content/path fuzzing of known URLs using ffuf.",
        'flags': ["tool", "slow", "invasive"],
        'useCases': ["Investigate"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "ffuf",
            'description': "Fast web fuzzer for hidden paths/parameters/vhosts.",
            'website': "https://github.com/ffuf/ffuf",
            'repository': "https://github.com/ffuf/ffuf"
        }
    }

    opts = {
        'ffuf_path': '/usr/local/bin/ffuf',
        'wordlist': '/usr/share/seclists/Discovery/Web-Content/common.txt',
        'threads': 40,
        'maxtime': 30,
        'timeout': 45,
        'match_codes': '200,204,301,302,307,401,403,405',
    }

    optdescs = {
        'ffuf_path': 'Path to ffuf binary.',
        'wordlist': 'Wordlist path. If missing, a small built-in list is used.',
        'threads': 'Number of ffuf worker threads.',
        'maxtime': 'Maximum ffuf runtime in seconds per URL.',
        'timeout': 'Process timeout in seconds (hard timeout).',
        'match_codes': 'HTTP codes to match, comma separated.'
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
        return ['URL_STATIC']

    def producedEvents(self):
        return ['URL_STATIC', 'HTTP_CODE', 'RAW_RIR_DATA']

    def _mini_wordlist(self):
        entries = [
            'admin', 'login', 'dashboard', 'api', 'backup', 'config', 'test',
            '.git', '.env', 'robots.txt', 'sitemap.xml', 'phpinfo.php'
        ]
        fd, path = tempfile.mkstemp(prefix='sf-ffuf-', suffix='.txt')
        with os.fdopen(fd, 'w', encoding='utf-8', errors='ignore') as f:
            f.write("\n".join(entries) + "\n")
        return path

    def handleEvent(self, event):
        url = str(event.data).strip()

        if self.errorState:
            return
        if event.module == self.__name__:
            return
        if url in self.results:
            return
        self.results[url] = True

        exe = self.opts.get('ffuf_path', '')
        if exe.endswith('/'):
            exe = exe + 'ffuf'
        if not exe or not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        base = url if url.endswith('/') else f"{url}/"
        fuzz_url = f"{base}FUZZ"

        wordlist = str(self.opts.get('wordlist', '')).strip()
        temp_wordlist = None
        if not wordlist or not os.path.isfile(wordlist):
            temp_wordlist = self._mini_wordlist()
            wordlist = temp_wordlist

        outfd, outpath = tempfile.mkstemp(prefix='sf-ffuf-', suffix='.json')
        os.close(outfd)

        args = [
            exe,
            '-noninteractive',
            '-s',
            '-u', fuzz_url,
            '-w', wordlist,
            '-mc', str(self.opts.get('match_codes', '200,204,301,302,307,401,403,405')),
            '-t', str(self.opts.get('threads', 40)),
            '-maxtime', str(self.opts.get('maxtime', 30)),
            '-timeout', '10',
            '-of', 'json',
            '-o', outpath,
        ]

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 45)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"ffuf timed out for {url}")
            return
        except Exception as e:
            self.error(f"Unable to run ffuf: {e}")
            return
        finally:
            if temp_wordlist and os.path.isfile(temp_wordlist):
                try:
                    os.unlink(temp_wordlist)
                except Exception:
                    pass

        out = (stdout or b'').decode('utf-8', errors='replace')
        err = (stderr or b'').decode('utf-8', errors='replace')
        text = (out + "\n" + err).strip()
        if text:
            self.notifyListeners(SpiderFootEvent('RAW_RIR_DATA', text[:4000], self.__name__, event))

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

        results = data.get('results', []) if isinstance(data, dict) else []
        for row in results:
            found = row.get('url')
            if not found:
                continue
            evt = SpiderFootEvent('URL_STATIC', str(found), self.__name__, event)
            self.notifyListeners(evt)

            status = row.get('status')
            if status is not None:
                self.notifyListeners(SpiderFootEvent('HTTP_CODE', str(status), self.__name__, evt))

# End of sfp_tool_ffuf class
