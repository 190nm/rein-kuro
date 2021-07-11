# build.py

from typing import Any, Dict
from distutils.core import Extension
from distutils.errors import CCompilerError, DistutilsExecError, DistutilsPlatformError
from distutils.command.build_ext import build_ext

# from setuptools import Extension, find_packages, setup,
from pathlib import Path

kuro_dir = Path(__file__).resolve().parent.joinpath("ReinKuro")
clibs_dir = kuro_dir.joinpath("_clibs")
kuro_ext_config = dict(
    include_dirs=[str(clibs_dir.joinpath("kuro"))],
    sources=[str(clibs_dir.joinpath("kuro/kuro.c")), str(clibs_dir.joinpath("kuromodule.c"))],
)

ext_modules = [Extension("reinkuro._clibs.kuro", **kuro_ext_config)]


class BuildFailed(Exception):
    pass


class ExtBuilder(build_ext):
    def run(self):
        try:
            build_ext.run(self)
        except (DistutilsPlatformError, FileNotFoundError):
            print("Could not compile C extension.")

    def build_extension(self, ext):
        try:
            build_ext.build_extension(self, ext)
        except (CCompilerError, DistutilsExecError, DistutilsPlatformError, ValueError):
            print("Could not compile C extension.")


def build(setup_kwargs: Dict[str, Any]) -> None:
    setup_kwargs.update(
        {
            "ext_modules": ext_modules,
            "cmdclass": {"build_ext": ExtBuilder},
            "zip_safe": False,
        }
    )
