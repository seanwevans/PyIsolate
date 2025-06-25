"""Demonstrate Prometheus metrics collection."""

import time
import pyisolate as iso

# Start supervisor with metrics HTTP server on port 8000
sup = iso.Supervisor(metrics_port=8000)

sb = sup.spawn("metrics-demo")

sb.exec("post('metric example')")
print("Sandbox result:", sb.recv())

# Update metrics once before exiting
sup.metrics.export()
print("Metrics available at http://localhost:8000/metrics")

# Keep process alive briefly so the server stays up
time.sleep(1)

sb.close()
