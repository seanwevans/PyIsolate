def add(a, b):
    return a + b


def stage_one(x):
    return x + 1


def stage_two(x):
    return x * 2


def slow_identity(x):
    import time

    time.sleep(0.05)
    return x
