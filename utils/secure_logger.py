import logging

class SecureLogger:
    def __init__(self, name, level=logging.INFO):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(level)
        # It's assumed that basicConfig is already done at the application entry point
        # or handlers are added elsewhere. If not, a default handler could be added here.
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)

    def _log(self, level, msg, *args, **kwargs):
        # Use exc_info=True if 'exc_info' is in kwargs and is True
        # Or if an exception object is passed as an arg
        exc_info = kwargs.pop('exc_info', False)
        if not exc_info and any(isinstance(arg, Exception) for arg in args):
            exc_info = True
        
        # The logging module itself handles parameter substitution securely.
        # We just need to ensure the message and args are passed correctly.
        self._logger.log(level, msg, *args, exc_info=exc_info, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self._log(logging.DEBUG, msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self._log(logging.INFO, msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self._log(logging.WARNING, msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self._log(logging.ERROR, msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self._log(logging.CRITICAL, msg, *args, **kwargs)
        
    def exception(self, msg, *args, **kwargs):
        kwargs['exc_info'] = True
        self._log(logging.ERROR, msg, *args, **kwargs)

    def setLevel(self, level):
        self._logger.setLevel(level)
