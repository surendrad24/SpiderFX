# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_naabu
# Purpose:      SpiderFoot plug-in for using naabu to discover open TCP ports.
#
# Created:      2026-04-16
# Licence:      MIT
# -------------------------------------------------------------------------------

import os.path
from subprocess import PIPE, Popen, TimeoutExpired

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_naabu(SpiderFootPlugin):

    meta = {
        'name': "Tool - Naabu",
        'summary': "Fast port scan with projectdiscovery/naabu.",
        'flags': ["tool", "slow", "invasive"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "naabu",
            'description': "Naabu is a fast port scanning tool written in Go.",
            'website': "https://github.com/projectdiscovery/naabu",
            'repository': "https://github.com/projectdiscovery/naabu"
        }
    }

    opts = {
        'naabu_path': '/usr/local/bin/naabu',
        'timeout': 90,
        'top_ports': 100,
        'netblockscan': False,
        'netblockscanmax': 24
    }

    optdescs = {
        'naabu_path': 'Path to the naabu binary. Must be set.',
        'timeout': 'Timeout in seconds per target.',
        'top_ports': 'Top ports to scan (naabu -top-ports).',
        'netblockscan': 'Scan all IPs in owned netblocks?',
        'netblockscanmax': 'Maximum netblock size to scan if enabled (CIDR value).'
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
        return ['IP_ADDRESS', 'INTERNET_NAME', 'NETBLOCK_OWNER']

    def producedEvents(self):
        return ['TCP_PORT_OPEN', 'IP_ADDRESS', 'INTERNET_NAME']

    def _binary(self):
        exe = self.opts.get('naabu_path', '')
        if not exe:
            return None
        if exe.endswith('/'):
            exe = exe + 'naabu'
        return exe

    def _parse_target_port(self, line):
        line = line.strip()
        if not line:
            return None, None

        # Common naabu output is host:port, for IPv6 [ip]:port may appear.
        if line.startswith('[') and ']:' in line:
            host, port = line[1:].split(']:', 1)
            return host.strip(), port.strip()

        if ':' in line:
            host, port = line.rsplit(':', 1)
            return host.strip(), port.strip()

        return None, None

    def _scan_target(self, exe, target):
        args = [
            exe,
            '-host',
            target,
            '-silent',
            '-top-ports',
            str(self.opts.get('top_ports', 100)),
        ]

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(timeout=int(self.opts.get('timeout', 90)))
        except TimeoutExpired:
            p.kill()
            self.debug(f"naabu timed out for {target}")
            return []
        except Exception as e:
            self.error(f"Unable to run naabu: {e}")
            return []

        if p.returncode not in [0, 1]:
            self.debug(f"naabu returned non-zero status: {p.returncode}, stderr={stderr}")

        content = stdout.decode('utf-8', errors='replace')
        if not content:
            return []

        return [ln.strip() for ln in content.splitlines() if ln.strip()]

    def handleEvent(self, event):
        event_name = event.eventType
        event_data = event.data

        if self.errorState:
            return

        if event.module == self.__name__:
            return

        if not self.opts.get('naabu_path'):
            self.error('You enabled sfp_tool_naabu but did not set naabu_path!')
            self.errorState = True
            return

        exe = self._binary()
        if not exe or not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        targets = []
        if event_name == 'NETBLOCK_OWNER':
            if not self.opts.get('netblockscan', False):
                return
            try:
                net = IPNetwork(event_data)
                if net.prefixlen < int(self.opts.get('netblockscanmax', 24)):
                    self.debug(f"Skipping {event_data}, too big for netblock scan setting.")
                    return
                targets = [str(ip) for ip in net.iter_hosts()]
            except Exception as e:
                self.debug(f"Unable to parse netblock {event_data}: {e}")
                return
        else:
            targets = [event_data]

        for target in targets:
            cache_key = f"{event_name}:{target}"
            if cache_key in self.results:
                continue
            self.results[cache_key] = True

            lines = self._scan_target(exe, target)
            if not lines:
                continue

            for line in lines:
                host, port = self._parse_target_port(line)
                if not host or not port:
                    continue

                if self.sf.validIP(host):
                    host_evt = SpiderFootEvent('IP_ADDRESS', host, self.__name__, event)
                    self.notifyListeners(host_evt)
                    parent_evt = host_evt
                else:
                    host_evt = SpiderFootEvent('INTERNET_NAME', host, self.__name__, event)
                    self.notifyListeners(host_evt)
                    parent_evt = host_evt

                port_evt = SpiderFootEvent('TCP_PORT_OPEN', str(port), self.__name__, parent_evt)
                self.notifyListeners(port_evt)

# End of sfp_tool_naabu class
