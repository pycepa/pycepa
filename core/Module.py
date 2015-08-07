from core.events import events
from core.module_driver import modules

class Module(object):
    def __init__(self):
        self.events = events
        self.modules = modules

        self.unsatisfied_depends = []
        self.check_depends()

    def check_depends(self):
        if self.unsatisfied_depends:
            return

        if hasattr(self, 'dependencies'):
            for dependency in self.dependencies:
                if self.module_loaded(dependency):
                    continue

                self.register('module_loaded_%s' % dependency, self.dependency_loaded)
                self.unsatisfied_depends.append(dependency)

    def dependency_loaded(self, dependency):
        if dependency not in self.unsatisfied_depends:
            return

        self.unsatisfied_depends.remove(dependency)
        self.init_module()

    def init_module(self):
        if self.unsatisfied_depends:
            return

        self.module_load()
        name = self.__class__.__name__
        self.trigger('module_loaded_%s' % name, name)

    def module_loaded(self, module):
        return self.modules.loaded(module)

    def module_load(self):
        pass

    def module_unload(self):
        pass

    def register(self, event, function):
        self.events.register(event, function)

    def register_first(self, event, function):
        self.events.register_first(event, function)

    def unregister(self, event, function):
        self.events.unregister(event, function)

    def trigger(self, event, *args, **kwargs):
        return self.events.trigger(event, *args, **kwargs)

    def trigger_avail(self, event, *args, **kwargs):
        return self.events.trigger_avail(event, *args, **kwargs)
