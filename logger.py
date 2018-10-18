import logging

logging.basicConfig(
        format='[%(levelname)s] %(asctime)s - %(filename)s - %(funcName)s() - %(message)s',
        level=logging.DEBUG
    )

log = logging.getLogger()