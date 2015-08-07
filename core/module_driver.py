import os
import sys
import importlib
from core.events import events

class Modules(object):
    def __init__(self):
        self.modules = {}
        self.module_dir = 'modules'

    def loaded(self, module):
        return module in self.modules

    def load_all(self):
        for module_name in os.listdir(self.module_dir):
            if not module_name.endswith('.py') and not \
              os.path.isdir(os.path.join(self.module_dir, module_name)):
                continue

            if module_name.endswith('.py'):
                module_name = '.'.join(module_name.split('.')[:-1])

            if module_name in [ '__init__', 'Module' ]:
                continue

            self.load_module(module_name)

    def unload_all(self):
        for module_name in self.modules.keys():
            self.unload_module(module_name)

    def load_module(self, module_name):
        if module_name in self.modules:
            self.unload_module(module_name)

        module = importlib.import_module('%s.%s' % (self.module_dir, module_name))

        self.modules[module_name] = getattr(module, module_name.split('.')[-1])()
        self.modules[module_name].init_module()

    def unload_module(self, module_name):
        if module_name not in self.modules:
            return

        self.modules[module_name].module_unload()
        del sys.modules['%s.%s' % (self.module_dir, module_name)]
        del self.modules[module_name]
        events.trigger('module_unloaded_%s' % module_name, module_name)

modules = Modules()
