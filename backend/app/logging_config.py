import logging

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"


def configure_logging(level: str) -> None:
    """Send application logs to the root handler without raising third-party verbosity."""
    logging.basicConfig(format=LOG_FORMAT)
    logging.getLogger("app").setLevel(level)
