"""
Baseline Generator
------------------
Creates a whitelist of currently running processes.
Run this once on a clean system to generate baseline_processes.txt
"""

from process_monitor import get_running_processes


def generate_baseline(filename="baseline_processes.txt"):
    print("Collecting processes for baseline...\n")

    processes = get_running_processes()

    # Extract unique process names
    names = sorted({
        (p.get("name") or "").lower()
        for p in processes
        if p.get("name")
    })

    with open(filename, "w", encoding="utf-8") as f:
        for name in names:
            f.write(name + "\n")

    print(f"Baseline created with {len(names)} processes.")
    print(f"Saved to {filename}")


if __name__ == "__main__":
    generate_baseline()
