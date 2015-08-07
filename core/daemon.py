import logging
import logging.config

log = logging.getLogger(__name__)

import os
import signal
import sys
import traceback

from core.events import events
from core.module_driver import modules

pid_file = 'data/pid'

def check_pid(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True

def read_pid():
    return int(open(pid_file).read().rstrip())

def write_pid():
    try:
        dirs = os.path.split(pid_file)[0]
        os.makedirs(dirs)
    except:
        pass

    open(pid_file, 'w').write(str(os.getpid()))

def start(daemon=True):
    log.info('starting server..')

    try:
        if check_pid(read_pid()):
            log.critical('process already started!')
            return
    except:
        pass

    try:
        modules.load_all()
    except Exception as e:
        log.critical('server boot failed: %s' % e)
        traceback.print_exc()
        return

    log.info('server successfully started.')

    if daemon:
        if os.fork(): quit()
        if os.fork(): quit()

        write_pid()

        os.setsid()

        sys.stdout = open('/dev/null', 'w')
        sys.stderr = open('data/errors', 'w')
        sys.stdin  = open('/dev/null')

    events.trigger('booted')

def stop():
    log.info('stopping server.')

    try:
        pid = read_pid()
    except Exception as e:
        log.critical('could not read PID file: %s' % e)
        return

    try:
        os.kill(pid, signal.SIGTERM)
    except Exception as e:
        log.critical('could not stop server: %s' % e)
        return

    os.remove(pid_file)

def restart():
    log.info('restarting server.')

    stop()
    start()

def reload():
    log.info('reloading server.')

    try:
        pid = read_pid()
    except Exception as e:
        log.critical('could not read PID file: %s' % e)
        return

    try:
        os.kill(pid, signal.SIGHUP)
    except Exception as e:
        log.critical('could not reload server: %s' % e)
