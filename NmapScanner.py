# -*- coding: utf-8 -*-
import pprint
import sys
import Utils
import BaseModule
import nmap
import Decorators


@Decorators.ModuleDocstringParser
class NmapScanner(BaseModule.BaseModule):
    """
    Scan network with nmap and emit result as new event.

    Configuration template:

    - NmapScanner:
        network:                    # <type: string; is: required>
        netmask:                    # <default: '/24'; type: string; is: optional>
        ports:                      # <default: None; type: None||string; is: optional>
        arguments:                  # <default: '-O -F --osscan-limit'; type: string; is: optional>
        interval:                   # <default: 900; type: integer; is: optional>
        receivers:
          - NextModule
    """

    module_type = "input"
    """Set module type"""
    # TODO: This module can run in forked processes. We need some way to partition the network and give each process a
    # segment to scan.
    can_run_forked = False

    def configure(self, configuration):
        # Call parent configure method
        BaseModule.BaseModule.configure(self, configuration)
        self.network = self.getConfigurationValue('network')
        self.netmask = self.getConfigurationValue('netmask')
        self.arguments = self.getConfigurationValue('arguments')

    def getScannerFunc(self):
        @Decorators.setInterval(self.getConfigurationValue('interval'), call_on_init=True)
        def scanNetwork():
            # Get all alive hosts
            try:
                scan_results = self.scanner.scan('%s%s' % (self.network,self.netmask), arguments="-sn")
            except nmap.PortScannerError:
                etype, evalue, etb = sys.exc_info()
                self.logger.warning("Scanning failed. Exception: %s, Error: %s." % (etype, evalue))
                return
            for host, scan_result in scan_results['scan'].items():
                try:
                    host_scan_result = self.scanner.scan('%s/32' % (host), arguments=self.arguments)
                except nmap.PortScannerError:
                    etype, evalue, etb = sys.exc_info()
                    self.logger.warning("Scanning failed. Exception: %s, Error: %s." % (etype, evalue))
                    return
                if host in host_scan_result['scan']:
                    self.handleEvent(host, host_scan_result['scan'][host])
        return scanNetwork

    def handleEvent(self, host, scan_result):
        # Get OS from scan.
        if 'osmatch' in scan_result:
            os_info = sorted(scan_result['osmatch'], key=lambda k: int(k['accuracy']))
            scan_result['detected_os'] = os_info[0]['name']
            scan_result.pop('osmatch')
        if 'vendor' in scan_result and isinstance(scan_result['vendor'], dict) and len(scan_result['vendor']) > 0:
            scan_result['vendor'] = scan_result['vendor'].values()[0]
        # Drop some fields.
        if 'osclass' in scan_result:
            scan_result.pop('osclass')
        event = Utils.getDefaultEventDict(scan_result, caller_class_name=self.__class__.__name__)
        event['gambolputty']['event_type'] = 'nmap_scan'
        self.sendEvent(event)

    def start(self):
        self.scanner = nmap.PortScanner()
        timed_func = self.getScannerFunc()
        self.timed_func_handler = Utils.TimedFunctionManager.startTimedFunction(timed_func)
