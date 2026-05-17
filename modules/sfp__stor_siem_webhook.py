# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp__stor_siem_webhook
# Purpose:      SpiderFoot storage plug-in to forward events to SIEM/webhook targets.
#
# Created:      2026-04-16
# Licence:      MIT
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootPlugin


class sfp__stor_siem_webhook(SpiderFootPlugin):

    meta = {
        'name': "SIEM Webhook Export",
        'summary': "Forward SpiderFoot events to a SIEM/webhook endpoint in JSON format."
    }

    _priority = 0
    errorState = False

    opts = {
        'webhook_url': '',
        'api_key': '',
        'auth_header': 'Authorization',
        'auth_scheme': 'Bearer',
        'verify_tls': True,
        'event_allowlist': '*',
        'event_denylist': '',
        'include_source_event': True,
        'send_root': False,
    }

    optdescs = {
        'webhook_url': 'Destination webhook URL (for example Splunk HEC, Elastic intake, custom API).',
        'api_key': 'Optional API token for the webhook.',
        'auth_header': 'HTTP auth header name (Authorization, X-API-Key, etc.).',
        'auth_scheme': 'Header token scheme (Bearer, Token). Leave empty to send raw token value.',
        'verify_tls': 'Verify TLS certificate for webhook requests?',
        'event_allowlist': 'Comma-separated event types to send, or * for all.',
        'event_denylist': 'Comma-separated event types to never send.',
        'include_source_event': 'Include source event data/hash in payload?',
        'send_root': 'Send ROOT events too? Usually leave disabled.'
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["*"]

    def _parse_csv_set(self, value):
        if not value:
            return set()
        if isinstance(value, str):
            return set(v.strip() for v in value.split(',') if v.strip())
        return set()

    def _allowed(self, event):
        if event.eventType == 'ROOT' and not self.opts.get('send_root', False):
            return False

        deny = self._parse_csv_set(self.opts.get('event_denylist', ''))
        if event.eventType in deny:
            return False

        allow_raw = self.opts.get('event_allowlist', '*')
        if allow_raw == '*':
            return True

        allow = self._parse_csv_set(allow_raw)
        return event.eventType in allow

    def _headers(self):
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        api_key = self.opts.get('api_key', '')
        if api_key:
            header_name = self.opts.get('auth_header', 'Authorization')
            scheme = str(self.opts.get('auth_scheme', 'Bearer')).strip()
            headers[header_name] = f"{scheme} {api_key}" if scheme else api_key

        return headers

    def _payload(self, event):
        payload = {
            'event': event.asDict(),
            'module': event.module,
            'event_type': event.eventType,
            'data': event.data,
        }

        if self.opts.get('include_source_event', True) and event.sourceEvent:
            payload['source_event'] = {
                'type': event.sourceEvent.eventType,
                'module': event.sourceEvent.module,
                'data': event.sourceEvent.data,
                'hash': event.sourceEvent.hash
            }

        return payload

    def handleEvent(self, event):
        if self.errorState:
            return

        if event.module == self.__name__:
            return

        if not self.opts.get('webhook_url'):
            self.error('You enabled sfp__stor_siem_webhook but did not set webhook_url!')
            self.errorState = True
            return

        if not self._allowed(event):
            return

        payload = self._payload(event)
        res = self.sf.fetchUrl(
            self.opts['webhook_url'],
            useragent=self.opts['_useragent'],
            timeout=self.opts['_fetchtimeout'],
            headers=self._headers(),
            postData=json.dumps(payload),
            verify=self.opts.get('verify_tls', True)
        )

        if res.get('content') is None and str(res.get('code', '')) not in ['200', '201', '202', '204']:
            self.debug(f"SIEM webhook returned code {res.get('code')} for {event.eventType}")

# End of sfp__stor_siem_webhook class
