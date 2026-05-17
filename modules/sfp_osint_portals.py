# -*- coding: utf-8 -*-

import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_osint_portals(SpiderFootPlugin):

    meta = {
        'name': "OSINT Portals",
        'summary': "Generate pivot links for OSINT Framework, Epieos, PimEyes, TinEye, Google Images, HaveIBeenPwned, GreyNoise and IntelX.",
        'flags': ["passive"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    opts = {
        'emit_osintframework': True,
        'emit_epieos': True,
        'emit_pimeyes': True,
        'emit_tineye': True,
        'emit_google_images': True,
        'emit_haveibeenpwned': True,
        'emit_greynoise': True,
        'emit_intelx': True,
    }

    optdescs = {
        'emit_osintframework': 'Emit OSINT Framework landing link.',
        'emit_epieos': 'Emit Epieos landing link.',
        'emit_pimeyes': 'Emit PimEyes landing link.',
        'emit_tineye': 'Emit TinEye pivot links for image URLs.',
        'emit_google_images': 'Emit Google Images text/reverse-image pivots.',
        'emit_haveibeenpwned': 'Emit HaveIBeenPwned pivot links.',
        'emit_greynoise': 'Emit GreyNoise Visualizer pivot links.',
        'emit_intelx': 'Emit Intelligence X pivot links.',
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['EMAILADDR', 'PHONE_NUMBER', 'USERNAME', 'HUMAN_NAME', 'URL_STATIC', 'DOMAIN_NAME']

    def producedEvents(self):
        return ['SEARCH_ENGINE_WEB_CONTENT']

    def _emit(self, text, event):
        key = self.sf.hashstring(text)
        if key in self.results:
            return
        self.results[key] = True
        self.notifyListeners(SpiderFootEvent('SEARCH_ENGINE_WEB_CONTENT', text, self.__name__, event))

    def handleEvent(self, event):
        val = event.data.strip()
        enc = urllib.parse.quote_plus(val)

        if self.opts.get('emit_osintframework', True):
            self._emit('OSINT Framework: <SFURL>https://osintframework.com/</SFURL>', event)

        if self.opts.get('emit_epieos', True):
            self._emit(f'Epieos pivot for {val}: <SFURL>https://epieos.com/</SFURL>', event)

        if self.opts.get('emit_pimeyes', True):
            self._emit('PimEyes reverse face search: <SFURL>https://pimeyes.com/en</SFURL>', event)

        if self.opts.get('emit_google_images', True):
            self._emit(f'Google Images text query for {val}: <SFURL>https://www.google.com/search?tbm=isch&q={enc}</SFURL>', event)
        if self.opts.get('emit_haveibeenpwned', True):
            self._emit(f'HaveIBeenPwned query for {val}: <SFURL>https://haveibeenpwned.com/</SFURL>', event)
        if self.opts.get('emit_greynoise', True):
            self._emit(f'GreyNoise Visualizer for {val}: <SFURL>https://viz.greynoise.io/</SFURL>', event)
        if self.opts.get('emit_intelx', True):
            self._emit(f'Intelligence X for {val}: <SFURL>https://intelx.io/</SFURL>', event)

        if event.eventType == 'URL_STATIC' and val.lower().startswith(('http://', 'https://')):
            lval = val.lower()
            is_img = any(lval.endswith(x) for x in ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff'])
            if is_img:
                q = urllib.parse.quote_plus(val)
                if self.opts.get('emit_tineye', True):
                    self._emit(f'TinEye reverse image for {val}: <SFURL>https://tineye.com/search?url={q}</SFURL>', event)
                if self.opts.get('emit_google_images', True):
                    self._emit(f'Google reverse image for {val}: <SFURL>https://www.google.com/searchbyimage?image_url={q}</SFURL>', event)

# End of sfp_osint_portals class
