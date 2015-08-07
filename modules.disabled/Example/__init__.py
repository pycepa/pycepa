from core.Module import Module

class Example(Module):
    def module_load(self):
        self.register('an event', self.an_event)
        self.trigger('an event', 'ayy', 'lmao')

    def an_event(self, arg, arg2):
        pass
