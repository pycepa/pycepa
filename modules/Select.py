from core.Module import Module
import select
import logging
log = logging.getLogger(__name__)

class Select(Module):
    def module_load(self):
        """
            Events registered:
                booted                    - run on boot by start() in daemon.py
                quit                      - end the select loop
                fd_readable <object>      - register an fd as readable
                fd_unreadable <object>    - un-register fd from read list
                fd_writable <object>      - register an fd as writable
                fd_unwritable <object>    - un-register fd from write list
                fd_exceptional <object>   - register an fd as exceptional
                fd_unexceptional <object> - un-register fd from exception list
        """
        self.running = True

        self.register('booted', self.booted)
        self.register('quit', self.quit)
        self.register('fd_readable', self.fd_readable)
        self.register('fd_unreadable', self.fd_unreadable)
        self.register('fd_writable', self.fd_writable)
        self.register('fd_unwritable', self.fd_unwritable)
        self.register('fd_exceptional', self.fd_exceptional)
        self.register('fd_unexceptional', self.fd_unexceptional)

        self.fds = {}
        self.poll = select.poll()

    def booted(self):
        """
        Main I/O loop of the application.
        
        Events raised:
            * fd_<object>_readable <object>    - fd is readable.
            * fd_<object>_writable <object>    - fd is writable.
            * fd_<object>_exceptional <object> - fd is exceptional.
        """
        while self.running:
            events = self.poll.poll()

            event_strings = {
                select.POLLIN: 'fd_%s_readable',
                select.POLLOUT: 'fd_%s_writable',
                select.POLLPRI: 'fd_%s_exceptional',
            }

            if not events:
                continue

            for event in events:
                fd = self.fds[event[0]]['fd']
                self.trigger(event_strings[event[1]] % fd, fd)

    def quit(self):
        """
        Ends the I/O loop.
        """
        self.running = False

    def init_fd(self, fd, event, add=True):
        """
        Manages the poll file descriptor events.
        """
        fno = fd.fileno()

        if fno not in self.fds:
            if not add:
                return

            self.fds[fno] = {}
            self.fds[fno] = { 'fd': fd, 'events': 0 }

        if add:
            self.fds[fno]['events'] |= event
        elif self.fds[fno]['events'] & event:
            self.fds[fno]['events'] ^= event

        if self.fds[fno]['events'] == 0:
            del self.fds[fno]
            self.poll.unregister(fno)
        else:
            self.poll.register(fno, self.fds[fno]['events'])

    def fd_readable(self, fd):
        """
        Marks an fd readable.
        """
        self.init_fd(fd, select.POLLIN)

    def fd_unreadable(self, fd):
        """
        Marks an fd unreadable.
        """
        self.init_fd(fd, select.POLLIN, add=False)

    def fd_writable(self, fd):
        """
        Marks an fd writable.
        """
        self.init_fd(fd, select.POLLOUT)

    def fd_unwritable(self, fd):
        """
        Marks an fd unwritable.
        """
        self.init_fd(fd, select.POLLOUT, add=False)

    def fd_exceptional(self, fd):
        """
        Marks an fd exceptional.
        """
        self.init_fd(fd, select.POLLPRI)

    def fd_unexceptional(self, fd):
        """
        Marks an fd unexceptional.
        """
        self.init_fd(fd, select.POLLPRI, add=False)
