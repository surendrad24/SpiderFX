# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_mcp_server
# Purpose:      Query one or more MCP-compatible HTTP endpoints for enrichment data.
#
# Created:      2026-04-16
# Licence:      MIT
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_mcp_server(SpiderFootPlugin):

    meta = {
        'name': "MCP Server",
        'summary': "Send observed entities to one or more MCP-compatible HTTP endpoints and ingest returned findings.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"],
        'dataSource': {
            'website': "https://modelcontextprotocol.io/",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://modelcontextprotocol.io/introduction",
                "https://modelcontextprotocol.io/specification"
            ],
            'apiKeyInstructions': [
                "Set up one or more MCP-compatible gateway endpoints.",
                "If endpoints require auth, generate API tokens.",
                "Configure endpoint JSON in mcp_endpoints or use legacy mcp_url + api_key fields."
            ],
            'favIcon': "https://modelcontextprotocol.io/favicon.ico",
            'logo': "https://modelcontextprotocol.io/favicon.ico",
            'description': "This module lets SpiderFoot enrich entities through external MCP-compatible HTTP services. "
            "It supports multi-endpoint orchestration and converts returned findings into SpiderFoot events."
        }
    }

    opts = {
        # Legacy single endpoint options (still supported)
        'mcp_url': '',
        'api_key': '',
        'auth_header': 'Authorization',
        'auth_scheme': 'Bearer',
        'tool_name': 'spiderfoot_enrich',
        'verify_tls': True,

        # New multi-endpoint option.
        # Example:
        # [
        #   {"url":"https://mcp1/api/enrich","api_key":"...","tool":"ti","enabled":true},
        #   {"url":"https://mcp2/api/enrich","header":"X-API-Key","scheme":"","api_key":"..."}
        # ]
        'mcp_endpoints': '[]',
        'continue_on_error': True,

        # Output behavior
        'max_results_per_endpoint': 50,
        'emit_raw_response': False,
    }

    optdescs = {
        'mcp_url': 'Legacy single MCP endpoint URL (used when mcp_endpoints is empty).',
        'api_key': 'Legacy API token for mcp_url.',
        'auth_header': 'Legacy auth header name for mcp_url (for example Authorization or X-API-Key).',
        'auth_scheme': 'Legacy auth scheme prefix (for example Bearer). Leave empty for raw token.',
        'tool_name': 'Legacy tool name sent to mcp_url.',
        'verify_tls': 'Verify TLS certificates when calling endpoints?',
        'mcp_endpoints': 'JSON array of endpoint configs for orchestration. See module source for shape.',
        'continue_on_error': 'Continue querying other endpoints if one fails?',
        'max_results_per_endpoint': 'Maximum findings emitted from each endpoint per input event.',
        'emit_raw_response': 'Emit RAW_RIR_DATA events with raw endpoint responses.'
    }

    results = None
    emitted = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.emitted = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "DOMAIN_NAME",
            "INTERNET_NAME",
            "IP_ADDRESS",
            "EMAILADDR",
            "PHONE_NUMBER",
            "BGP_AS_OWNER"
        ]

    def producedEvents(self):
        return [
            "RAW_RIR_DATA",
            "DOMAIN_NAME",
            "INTERNET_NAME",
            "IP_ADDRESS",
            "EMAILADDR",
            "PHONE_NUMBER",
            "BGP_AS_OWNER",
            "MALICIOUS_IPADDR",
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_EMAILADDR",
            "VULNERABILITY_GENERAL"
        ]

    def _parse_endpoints(self):
        endpoints = []

        # New style: JSON array
        data = self.opts.get('mcp_endpoints', '[]')
        if isinstance(data, str):
            try:
                parsed = json.loads(data)
            except Exception:
                parsed = []
        elif isinstance(data, list):
            parsed = data
        else:
            parsed = []

        if isinstance(parsed, list):
            for item in parsed:
                if not isinstance(item, dict):
                    continue
                if not item.get('url'):
                    continue
                if item.get('enabled', True) in [False, 0, '0', 'false', 'False']:
                    continue
                endpoints.append({
                    'name': item.get('name', item.get('url')),
                    'url': item.get('url'),
                    'api_key': item.get('api_key', ''),
                    'header': item.get('header', 'Authorization'),
                    'scheme': item.get('scheme', 'Bearer'),
                    'tool': item.get('tool', self.opts.get('tool_name', 'spiderfoot_enrich')),
                    'verify_tls': item.get('verify_tls', self.opts.get('verify_tls', True))
                })

        # Backward compatibility
        if not endpoints and self.opts.get('mcp_url'):
            endpoints.append({
                'name': 'legacy',
                'url': self.opts.get('mcp_url'),
                'api_key': self.opts.get('api_key', ''),
                'header': self.opts.get('auth_header', 'Authorization'),
                'scheme': self.opts.get('auth_scheme', 'Bearer'),
                'tool': self.opts.get('tool_name', 'spiderfoot_enrich'),
                'verify_tls': self.opts.get('verify_tls', True)
            })

        return endpoints

    def _headers(self, endpoint):
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        api_key = endpoint.get('api_key', '')
        if api_key:
            header_name = endpoint.get('header', 'Authorization')
            scheme = str(endpoint.get('scheme', 'Bearer')).strip()
            headers[header_name] = f"{scheme} {api_key}" if scheme else api_key

        return headers

    def _coerce_event_type(self, event_type):
        valid_types = set(self.producedEvents())
        if event_type in valid_types:
            return event_type
        return "RAW_RIR_DATA"

    def _extract_findings(self, response_json):
        findings = []

        if isinstance(response_json, dict):
            candidates = None
            for key in ["events", "results", "findings", "data", "items", "matches"]:
                if isinstance(response_json.get(key), list):
                    candidates = response_json.get(key)
                    break

            if candidates is None:
                candidates = [response_json]

            for item in candidates:
                if isinstance(item, dict):
                    ev_type = self._coerce_event_type(item.get("type", "RAW_RIR_DATA"))
                    ev_data = item.get("data")
                    if ev_data is None:
                        ev_data = json.dumps(item, sort_keys=True)
                    findings.append((ev_type, str(ev_data)))
                else:
                    findings.append(("RAW_RIR_DATA", str(item)))

        elif isinstance(response_json, list):
            for item in response_json:
                if isinstance(item, dict):
                    ev_type = self._coerce_event_type(item.get("type", "RAW_RIR_DATA"))
                    ev_data = item.get("data")
                    if ev_data is None:
                        ev_data = json.dumps(item, sort_keys=True)
                    findings.append((ev_type, str(ev_data)))
                else:
                    findings.append(("RAW_RIR_DATA", str(item)))

        else:
            findings.append(("RAW_RIR_DATA", str(response_json)))

        return findings

    def query_endpoint(self, endpoint, event_name, event_data, event):
        payload = {
            "tool": endpoint.get('tool', 'spiderfoot_enrich'),
            "event_type": event_name,
            "value": event_data,
            "context": {
                "source_module": event.module,
                "source_type": event_name
            }
        }

        res = self.sf.fetchUrl(
            endpoint['url'],
            useragent=self.opts['_useragent'],
            timeout=self.opts['_fetchtimeout'],
            headers=self._headers(endpoint),
            postData=json.dumps(payload),
            verify=endpoint.get('verify_tls', True)
        )

        if res.get('content') is None:
            self.debug(f"[{endpoint['name']}] No content returned for {event_data}")
            return None

        if str(res.get('code')) not in ["200", "201", "202"]:
            self.error(f"[{endpoint['name']}] Unexpected HTTP status: {res.get('code')}")
            return None

        try:
            return json.loads(res.get('content'))
        except Exception as e:
            self.error(f"[{endpoint['name']}] Error parsing JSON response: {e}")
            return None

    def handleEvent(self, event):
        event_name = event.eventType
        event_data = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {event_name}, from {event.module}")

        if event_name not in self.watchedEvents():
            return

        endpoints = self._parse_endpoints()
        if not endpoints:
            self.error("You enabled sfp_mcp_server but did not configure mcp_endpoints or mcp_url!")
            self.errorState = True
            return

        if event_data in self.results:
            self.debug(f"Skipping {event_data}, already checked.")
            return

        self.results[event_data] = True

        try:
            max_results = int(self.opts.get('max_results_per_endpoint', 50))
        except Exception:
            max_results = 50

        continue_on_error = self.opts.get('continue_on_error', True)
        any_success = False

        for endpoint in endpoints:
            data = self.query_endpoint(endpoint, event_name, event_data, event)
            if data is None:
                if not continue_on_error:
                    self.errorState = True
                    return
                continue

            any_success = True

            if self.opts.get('emit_raw_response', False):
                raw_evt = SpiderFootEvent(
                    "RAW_RIR_DATA",
                    f"MCP[{endpoint['name']}] raw response for {event_name}:{event_data}: {json.dumps(data)[:8000]}",
                    self.__name__,
                    event
                )
                self.notifyListeners(raw_evt)

            findings = self._extract_findings(data)
            for ev_type, ev_data in findings[:max_results]:
                key = f"{endpoint['name']}:{ev_type}:{ev_data}"
                if key in self.emitted:
                    continue
                self.emitted[key] = True

                evt = SpiderFootEvent(ev_type, ev_data, self.__name__, event)
                self.notifyListeners(evt)

        if not any_success and not continue_on_error:
            self.errorState = True

# End of sfp_mcp_server class
