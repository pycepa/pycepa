from core.Module import Module
import socket

import logging
log = logging.getLogger(__name__)

class ListenRandom(Module):
    def module_load(self):
        self.buffers = {}

        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        sock.listen(5)

        log.info('listener: %s' % str(sock.getsockname()))

        self.trigger_avail('fd_readable', sock)
        self.register('fd_%s_readable' % sock, self.readable)

    def readable(self, sock):
        client, addr = sock.accept()
        print addr
        self.buffers[client] = ""

        self.trigger('fd_readable', client)
        self.register('fd_%s_readable' % client, self.client_readable)
        self.register('fd_%s_writable' % client, self.client_writable)

    def client_readable(self, client):
        data = client.recv(65535)
        if not data:
            self.trigger('fd_unreadable', client)
            self.trigger('fd_unwritable', client)
            self.unregister('fd_%s_readable' % client, self.client_readable)
            self.unregister('fd_%s_writable' % client, self.client_writable)
            del self.buffers[client]
            return

        self.buffers[client] += data
        self.trigger('fd_writable', client)

    def client_writable(self, client):
        num_bytes = client.send(self.buffers[client])
        self.buffers[client] = self.buffers[client][num_bytes:]

        if not self.buffers[client]:
            self.trigger('fd_unwritable', self.client_writable)
