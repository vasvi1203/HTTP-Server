import sys, os, signal

if __name__ == '__main__':
    filename = open(sys.argv[1], "r")
    pids = filename.readlines()
    for pid in pids:
        pid = int(pid.strip('\n'))

        try:
            # terminating process
            os.kill(pid, signal.SIGKILL)
            print("Process successfully terminated")

        except:
            print("No such process running")
