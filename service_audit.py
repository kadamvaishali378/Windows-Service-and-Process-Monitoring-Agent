import wmi

def get_services():

    c = wmi.WMI()
    services = []

    for s in c.Win32_Service():
        info = {
            "name": s.Name,
            "display": s.DisplayName,
            "state": s.State,
            "start_mode": s.StartMode,
            "path": s.PathName
        }
        services.append(info)

    return services
