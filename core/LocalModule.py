import core.events
from core.Module import Module

class LocalModule(Module):
    def __init__(self):
        super(LocalModule, self).__init__()

        self._events = core.events.Events()

    def register_local(self, event, function):
        self._events.register(event, function)

    def register_local(self, event, function):
        self._events.register_first(event, function)

    def unregister_local(self, event, function):
        self._events.unregister(event, function)

    def trigger_local(self, event, *args, **kwargs):
        return self._events.trigger(event, *args, **kwargs)

    def trigger_avail_local(self, event, *args, **kwargs):
        return self._events.trigger_avail(event, *args, **kwargs)
