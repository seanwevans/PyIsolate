import subprocess
import sys

result = subprocess.run(
    [
        sys.executable,
        "-m",
        "coverage",
        "run",
        "-m",
        "pytest",
    ]
)
if result.returncode != 0:
    sys.exit(result.returncode)
subprocess.run([sys.executable, "-m", "coverage", "xml"], check=False)
subprocess.run([sys.executable, "-m", "coverage", "report"], check=False)
subprocess.run(["coverage-badge", "-o", "coverage.svg", "-f"], check=False)
