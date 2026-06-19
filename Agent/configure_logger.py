import os
import logging
from logging.handlers import RotatingFileHandler


def configure_logger(script_name, process_id):
    # Keep one logger per Agent script. Using this module's __name__ would make
    # every caller share the same logger and duplicate handlers.
    logger = logging.getLogger(script_name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    # Create rotating file handler for the logger
    # max_bytes = 15 * 1024 * 1024  # 15 MB
    max_bytes = 10 * 1024 # 5KB to test the rotation
    backup_count = 30 # up to 30 old log files
    #file_handler = logging.FileHandler('ccm-agent.log')
    file_handler = RotatingFileHandler('ccm-agent.log', mode='a', maxBytes=max_bytes, backupCount=backup_count)
    file_handler.setLevel(logging.INFO)

    # Create formatter of the log file
    #formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(funcName)s: %(message)s')
    # script_name = os.path.basename(__file__)
    # ccm_agent_id = 22524368
    formatter = logging.Formatter(f'%(asctime)s - {script_name} - [{process_id}] - %(levelname)s: %(message)s ')
    file_handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(file_handler)
    return logger

def close_logger(logger):
    """Ensure the logger is properly closed when the script finishes."""
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)
