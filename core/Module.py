from core.events import events
from core.module_driver import modules

class Module(object):
    """
    Base Module class.
    """
    def __init__(self):
        self.events = events
        self.modules = modules

        self.unsatisfied_depends = []
        self.check_depends()

    def check_depends(self):
        """
        Checks to see if the module has any unloaded dependencies. If it does,
        the module will wait to continue loading until the dependencies have been
        loaded.

        The function will return immediately if the unsatisfied_depends list is not
        empty.

        Events registered:
            * module_loaded_<name> <name> - listens for module_loaded events for the
                                            module's dependencies.
        """
        if self.unsatisfied_depends:
            return

        if hasattr(self, 'dependencies'):
            for dependency in self.dependencies:
                if self.module_loaded(dependency):
                    continue

                self.register('module_loaded_%s' % dependency, self.dependency_loaded)
                self.unsatisfied_depends.append(dependency)

    def dependency_loaded(self, dependency):
        """
        Registered with the module_loaded_[name] event and will be called when
        a dependency is loaded.
        """
        if dependency not in self.unsatisfied_depends:
            return

        self.unsatisfied_depends.remove(dependency)
        self.init_module()

    def init_module(self):
        """
        If there are unsatisfied_depends this function will fail silently.
        Otherwise it will call the module_load function.

        Events raised:
            * module_loaded_<name> <name> - indicates that this module has completed
                                            loading and any modules that depend on this
                                            one are now safe to continue initializing.
        """
        if self.unsatisfied_depends:
            return

        self.module_load()
        name = self.__class__.__name__
        self.trigger('module_loaded_%s' % name, name)

    def module_loaded(self, module):
        """
        Checks to see if a module is loaded.
        """
        return self.modules.loaded(module)

    def module_load(self):
        """
        This function should be implemented by any modules as a sort of "__init__" function
        and will be called after the module setup (checking for dependencies, creating
        event objects, etc).
        """
        pass

    def module_unload(self):
        """
        Function called when the module is unloaded. Any registered events should be
        unregistered here.
        """
        pass

    def register(self, event, function):
        """
        Register a callback function for a global event.
        """
        self.events.register(event, function)

    def register_first(self, event, function):
        """
        Register a callback function first in the list for a global event.
        """
        self.events.register_first(event, function)

    def register_once(self, event, function):
        """
        Register a callback for a global event but unregister it when it is triggered.
        """
        self.events.register_once(event, function)

    def unregister(self, event, function):
        """
        Unregister a callback from a global event.
        """
        self.events.unregister(event, function)

    def trigger(self, event, *args, **kwargs):
        """
        Trigger a global event.
        """
        return self.events.trigger(event, *args, **kwargs)

    def trigger_avail(self, event, *args, **kwargs):
        """
        Trigger a global event once it is registered, if it isn't already.
        """
        return self.events.trigger_avail(event, *args, **kwargs)
