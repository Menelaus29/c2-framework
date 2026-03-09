import sys
import traceback
from common.logger import get_logger
from agent.environment_checks import check_lab_environment
from agent.beacon import BeaconLoop

logger = get_logger('agent')

if __name__ == '__main__':
    try:
        check_lab_environment()
        BeaconLoop().run()
    except SystemExit:
        # check_lab_environment and TERMINATE signal both call sys.exit() — let them through
        raise
    except Exception as e:
        logger.error('catastrophic failure — agent exiting', extra={
            'reason':    str(e),
            'traceback': traceback.format_exc(),
        })
        sys.exit(1)