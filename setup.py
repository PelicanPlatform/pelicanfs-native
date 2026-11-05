# The project is configured in pyproject.toml; this shim exists only to
# pass cffi_modules, which setuptools' declarative config cannot express.
from setuptools import setup

setup(cffi_modules=["build_ffi.py:ffibuilder"])
