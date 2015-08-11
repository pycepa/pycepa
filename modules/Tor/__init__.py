from core.Module import Module
from core.module_driver import modules

import logging
log = logging.getLogger(__name__)

# 2015-08-04 15:20:44,648:modules.Tor.directory: got microdescriptor: {'descriptor_id': '/wYcvOUPyq/b9CrzyBtgfJbTMbk', 'name': 'ObiOneBackup', 'ip': '149.91.83.223', 'or_port': '9001', 'flags': ['Exit', 'Fast', 'Running', 'V2Dir', 'Valid'], 'dir_port': '9030'}

class Tor(Module):
    def module_load(self):
        modules.load_module('Tor.DirServ')
        modules.load_module('Tor.Router')
        log.info('initializing Tor.')

        self.guard_node = ['Guard', 'Stable', 'Fast', 'Valid', 'Running']

        self.register('tor_got_md_%s' % self.guard_node, self.guard)
        self.trigger_avail('tor_get_router', self.guard_node)

    def guard(self, md):
        self.unregister('tor_got_md_%s' % self.guard_node, self.guard)
        log.info('chosen guard node: %s' % md)
        self.trigger('tor_init_router', md)

if __name__=='__main__':
    pass
