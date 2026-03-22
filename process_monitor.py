import psutil

def get_running_processes():
    processes = []

    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe']):
        try:
            info = {
                "pid": proc.info['pid'],
                "ppid": proc.info['ppid'],
                "name": proc.info['name'],
                "path": proc.info['exe']
            }
            processes.append(info)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return processes
