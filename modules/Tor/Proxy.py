from core.Module import Module
from modules.Tor.Circuit import circuit
from modules.Tor.TorConnection import TorConnection

import random
import logging
log = logging.getLogger(__name__)

class Proxy(Module):
    """
    Tor proxy handler. Handles creation of tor connections.
    """
    def module_load(self):
        """
        Events registered:
            * tor_init_directory_stream <stream_id> - create a directory stream
        """
        self.register('tor_init_stream', self.get_stream)
        self.connections_pending = {}
        self.connections = []
        self.streams = []

    def get_stream(self, stream_id):
        """
        Events registered:
            * tor_<or_name>_proxy_initialized <or_name> - indicates that the OR connection
                                                          is ready for use.
            * tor_<or_name>_init_stream <stream_id>     - initialize a stream, will create
                                                          circuits as necessary.
        """
        if not self.connections and not self.connections_pending:
            OR = circuit[0]['name']
            self.register('tor_%s_proxy_initialized' % OR, self.proxy_initialized)
            TorConnection(circuit[0])
            self.connections_pending[OR] = [ stream_id ]
        elif self.connections:
            OR = random.choice(self.connections)
            self.trigger('tor_%s_init_stream' % OR, stream_id)
        else:
            OR = random.choice(self.connections_pending.keys())
            self.connections_pending[OR].append(stream_id)

    def proxy_initialized(self, name):
        """
        Proxy is initialized, so we begin creating a stream.

        Events raised:
            * tor_<or_name>_init_stream <stream_id> - initialize a stream, will create
                                                      circuits as necessary.
        """
        if name not in self.connections_pending:
            return

        self.connections.append(name)

        for stream in self.connections_pending[name]:
            self.trigger('tor_%s_init_stream' % name, stream)

        del self.connections_pending[name]
