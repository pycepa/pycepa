from core.Module import Module
import select

class Select(Module):
    """
        Events registered:
            booted - run on boot by start() in daemon.py
            quit - end the select loop

            fd_readable - register an fd as readable
            fd_unreadable - un-register fd from read list

            fd_writable - register an fd as writable
            fd_unwritable - un-register fd from write list

            fd_exceptional - register an fd as exceptional
            fd_unexceptional - un-register fd from exception list

        Events triggered:
            fd_%s_readable % object - an fd is readable
            fd_%s_writable % object - an fd is writable
            fd_%s_exceptional % object - an fd is exceptional
    """

    def module_load(self):
        self.running = True

        self.readable = []
        self.writable = []
        self.exceptional = []

        self.register('booted', self.booted)
        self.register('quit', self.quit)
        self.register('fd_readable', self.fd_readable)
        self.register('fd_unreadable', self.fd_unreadable)
        self.register('fd_writable', self.fd_writable)
        self.register('fd_unwritable', self.fd_unwritable)
        self.register('fd_exceptional', self.fd_exceptional)
        self.register('fd_unexceptional', self.fd_unexceptional)

    def booted(self):
        while self.running:
            r, w, x = select.select(self.readable, self.writable, self.exceptional)

            for readable in r:
                self.trigger('fd_%s_readable' % readable, readable)

            for writable in w:
                self.trigger('fd_%s_writable' % writable, writable)

            for exceptional in x:
                self.trigger('fd_%s_exceptional' % exceptional, exceptional)

    def quit(self):
        self.running = False

    def fd_readable(self, fd):
        if not fd in self.readable:
            self.readable.append(fd)

    def fd_unreadable(self, fd):
        if fd in self.readable:
            self.readable.remove(fd)

    def fd_writable(self, fd):
        if not fd in self.writable:
            self.writable.append(fd)

    def fd_unwritable(self, fd):
        if fd in self.writable:
            self.writable.remove(fd)

    def fd_exceptional(self, fd):
        if not fd in self.exceptional:
            self.exceptional.append(fd)

    def fd_unexceptional(self, fd):
        if fd in self.exceptional:
            self.exceptional.remove(fd)
