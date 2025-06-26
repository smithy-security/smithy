import logging

from pythonjsonlogger.json import JsonFormatter


log = logging.getLogger()
log.setLevel(logging.INFO)

handler = logging.StreamHandler()
formatter = JsonFormatter("{message}{asctime}{exc_info}", style="{")
handler.setFormatter(formatter)

log.addHandler(handler)
