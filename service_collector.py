import subprocess

def collect_services():
    services = []

    try:
        # Run Windows command to list services
        output = subprocess.check_output("sc query type= service state= all", shell=True, text=True)

        lines = output.splitlines()

        for line in lines:
            line = line.strip()
            if line.startswith("SERVICE_NAME"):
                name = line.split(":")[1].strip()
                services.append(name)

    except Exception as e:
        print("Error collecting services:", e)

    return services
