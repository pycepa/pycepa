from core.Module import Module
import logging
log = logging.getLogger(__name__)

class Test(Module):
    """
    Tests various Tor features.
    """
    dependencies = [ 'HTTPClient', 'Tor' ]

    def module_load(self):
        log.info('requesting http://google.com/')

        def chunk(chunk):
            log.info('got chunk http://google.com/: ' + chunk)

        def done():
            log.info('http get to http://google.com/ request completed.')
            self.directory_test()

        request = self.trigger('http_get', 'http://74.125.136.101/')
        request.register_local('data', chunk)
        request.register_local('done', done)


    def directory_test(self):
        log.info('requesting http://directory/')

        def chunk(chunk):
            log.info('got chunk http://directory/: ' + chunk)

        def done():
            log.info('http get to http://directory/ request completed.')

        request = self.trigger('http_get', 'http://google.com/', directory=True)
        request.register_local('data', chunk)
        request.register_local('done', done)
