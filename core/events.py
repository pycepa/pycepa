import os
import traceback
import logging
log = logging.getLogger(__name__)

class Events(object):
    """
    Event handler that allows registering and triggering events.
    """
    def __init__(self):
        self.events  = {}
        self.pending = {}
        self.self_destruct = {}

    def register(self, event, function, append=True):
        """
        Register an event. Events registered here will be placed
        at the end of the list by default.
        
        If the append argument is false, the event will be placed
        at the beginning of the list.
        """
        if event not in self.events:
            self.events[event] = []

        log.debug("registering '%s' in %s" % (event, self.do_trace()))

        if function not in self.events[event]:
            if append:
                self.events[event].append(function)
            else:
                self.events[event] = [ function ] + self.events[event]

        if event in self.pending:
            for pending in self.pending[event]:
                self.trigger(event, *pending[0], **pending[1])
            del self.pending[event]

    def register_first(self, event, function):
        """
        Register an event first in the list. This is useful if you want to ensure that
        your plugin can hook events for other plugins.
        """
        self.register(event, function, False)

    def register_once(self, event, function):
        """
        Registers an event once. Once it is triggered the callback function will be
        unregistered.
        """
        self.register(event, function)

        if event not in self.self_destruct:
            self.self_destruct[event] = []

        self.self_destruct[event].append(function)

    def unregister(self, event, function):
        """
        Unregisters a callback function from an event.
        """
        if event not in self.events:
            return

        if function in self.events[event]:
            self.events[event].remove(function)

        if not self.events[event]:
            del self.events[event]

    def unregister_all(self):
        """
        Resets the event object.
        """
        self.events  = {}
        self.pending = {}

    def trigger_avail(self, event, *args, **kwargs):
        """
        If the event is registered, it is triggered immediately otherwise
        the function gets added to the list of pending events and triggers
        once the event is registered.
        """
        if event not in self.events:
            if event in self.pending:
                self.pending[event].append([ args, kwargs ])
            else:
                self.pending[event] = [ [ args, kwargs] ]
        else:
            self.trigger(event, *args, **kwargs)

    def trigger(self, event, *args, **kwargs):
        """
        Raises an event. If the event does not exist it will do nothing.
        """
        log.debug("raising '%s' in %s" % (event, self.do_trace()))

        if event not in self.events:
            return

        to_be_deleted = []

        for function in self.events[event]:
            if event in self.self_destruct and function in self.self_destruct[event]:
                to_be_deleted.append(function)

            ret = function(*args, **kwargs)
            if ret:
               break

        for function in to_be_deleted:
            self.events[event].remove(function)
            self.self_destruct[event].remove(function)

            if not self.self_destruct[event]:
                del self.self_destruct[event]

        return ret

    def do_trace(self):
        """
        Prints out the trace for an event. Helpful for debugging.
        """

        # Trace is expensive so only do it when we need it
        if log.level > logging.DEBUG:
            return ''

        trace = traceback.extract_stack()[::-1]
        for t in trace:
            if os.path.basename(t[0]) in [ 'events.py', 'Module.py', 'LocalModule.py' ]:
                continue

            return '{0}:{1}:{2}'.format(*t)
        return ''

# Creates the global event object.
events = Events()
