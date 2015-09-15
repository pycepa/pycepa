from core.Module import Module
from core.module_driver import modules

import logging
log = logging.getLogger(__name__)

class Tor(Module):
    """
    Base Tor module, mostly here as a boiler plate for now.
    """
    dependencies = ['HTTPClient']

    def module_load(self):
        """
        Events raised:
            * tor_get_router <flags> - get a router with the given flags.
        """
        log.info('initializing Tor.')

        modules.load_module('Tor.Proxy')
        modules.load_module('Tor.DirServ')

        self.guard_node = ['Guard', 'Stable', 'Fast', 'Valid', 'Running']

        self.register('tor_got_md_%s' % self.guard_node, self.got_guard)
        # self.trigger('tor_get_router', self.guard_node)

    def got_guard(self, guard_node):
        log.info('Chosen guard node: %s' % guard_node)

if __name__=='__main__':
    pass
