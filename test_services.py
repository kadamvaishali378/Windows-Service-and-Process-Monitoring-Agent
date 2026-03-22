from service_collector import collect_services

services = collect_services()

print("Total services found:", len(services))

for s in services[:10]:
    print(s)
    