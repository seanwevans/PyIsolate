import pyisolate as iso

sandbox = iso.spawn("echo")

code = """
post("Hello from sandbox")
"""

sandbox.exec(code)
print("Result:", sandbox.recv())

sandbox.close()
