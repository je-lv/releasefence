# Offline installation

ReleaseFence has no runtime dependencies, so a machine with no network access needs only
Python 3.11 or later and the wheel file.

## From the release wheel

Copy `releasefence-0.1.0-py3-none-any.whl` from the GitHub release to the machine, then:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --no-index --no-deps releasefence-0.1.0-py3-none-any.whl
.venv/bin/releasefence --version
```

Or skip installing entirely: a wheel is a ZIP of pure Python, so this runs it in place:

```sh
PYTHONPATH=releasefence-0.1.0-py3-none-any.whl python3 -m releasefence scan path/to/release
```

## Building the wheel yourself without an index

Building needs `setuptools>=77` and `wheel` already installed in the build environment.
They are build tools only; the installed package does not use them.

```sh
python3 -m pip wheel --no-index --no-deps --no-build-isolation . --wheel-dir dist
```

`invalid command 'bdist_wheel'` means `wheel` is missing from the build environment, not
that ReleaseFence failed.
