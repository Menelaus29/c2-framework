from agent.environment_checks import check_lab_environment
from agent.beacon import BeaconLoop

if __name__ == '__main__':
    check_lab_environment()
    BeaconLoop().run()