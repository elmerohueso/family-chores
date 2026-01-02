# Gunicorn configuration hooks for starting background services
# This file defines an `on_starting(server)` callback that Gunicorn will
# call in the master process before spawning workers. We use it to start
# the single `job_timer` background thread so it runs once globally.

import traceback
import os

# Number of gunicorn workers
workers = 4

# Bind address
bind = '0.0.0.0:8000'

# gunicorn log files
LOG_DIR = '/data/syslogs'
os.makedirs(LOG_DIR, exist_ok=True)
accesslog = os.path.join(LOG_DIR, 'requests.log')
errorlog = os.path.join(LOG_DIR, 'worker.log')


def on_starting(server):
    """Called just before the master process is initialized. Runs db initialization and job timer startup.
    """
    try:
        # Import lazily to avoid circular import problems during Gunicorn
        from app import gunicorn_on_starting, logger
        gunicorn_on_starting()
        try:
            logger.info("Gunicorn on_starting completed successfully")
        except Exception:
            # If logger is not available for any reason, fall back to server log
            server.log.info("Gunicorn on_starting completed successfully")
    except Exception as e:
        # Ensure any start errors are recorded so deployers can diagnose
        try:
            server.log.error("Gunicorn on_starting failed: %s", e)
            server.log.debug(traceback.format_exc())
        except Exception:
            pass
