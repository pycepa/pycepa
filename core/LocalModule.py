import core.events
from core.Module import Module

class LocalModule(Module):
    """
    LocalModules have an internal event object that is accessible in addition to
    the global event object. This makes them good for socket plugins and other
    self-contained modules that don't need outide interference.
    """

    def __init__(self):
        super(LocalModule, self).__init__()

        self._events = core.events.Events()

    def register_local(self, event, function):
        """
        Register a local event.
        """
        self._events.register(event, function)

    def register_first_local(self, event, function):
        """
        Register a local event first in the list.
        """
        self._events.register_first(event, function)

    def register_once_local(self, event, function):
        """
        Register a local event and unregister it upon triggering.
        """
        self._events.register_once(event, function)

    def unregister_local(self, event, function):
        """
        Unregister a local event.
        """
        self._events.unregister(event, function)

    def trigger_local(self, event, *args, **kwargs):
        """
        Trigger a local event.
        """
        return self._events.trigger(event, *args, **kwargs)

    def trigger_avail_local(self, event, *args, **kwargs):
        """
        Trigger a local event once it is registered.
        """
        return self._events.trigger_avail(event, *args, **kwargs)
