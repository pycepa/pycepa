from core.Module import Module
from core.module_driver import modules

import logging
log = logging.getLogger(__name__)

# 2015-08-04 15:20:44,648:modules.Tor.directory: got microdescriptor: {'descriptor_id': '/wYcvOUPyq/b9CrzyBtgfJbTMbk', 'name': 'ObiOneBackup', 'ip': '149.91.83.223', 'or_port': '9001', 'flags': ['Exit', 'Fast', 'Running', 'V2Dir', 'Valid'], 'dir_port': '9030'}

class Tor(Module):
    def module_load(self):
        modules.load_module('Tor.Proxy')
        modules.load_module('Tor.TorSocket')
        log.info('initializing Tor.')

        self.guard_node = ['Guard', 'Stable', 'Fast', 'Valid', 'Running']

if __name__=='__main__':
    pass
