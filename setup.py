# -*- coding: utf-8 -*-
from pathlib import Path
from setuptools import Extension, find_packages, setup
from build import build

kuro_dir = Path(__file__).resolve().parent.joinpath("reinkuro")

clibs_dir = kuro_dir.joinpath("_clibs")

kuro_ext_config = dict(
    include_dirs=[str(clibs_dir.joinpath("kuro"))],
    sources=[
        str(clibs_dir.joinpath("kuro/kuro.c")),
        str(clibs_dir.joinpath("kuromodule.c")),
    ],
)

ext_modules = [Extension("reinkuro._clibs.kuro", **kuro_ext_config)]

packages = find_packages(exclude=["tests", "*.tests", "*.tests.*"])


package_data = {"": ["*"], "reinkuro._clibs": ["kuro/*"]}

install_requires = ["pycryptodome>=3.10.1,<4.0.0", "rich>=10.5.0,<11.0.0", "protobuf>=3.17.3,<4.0.0"]

setup_kwargs = {
    "name": "reinkuro",
    "version": "0.2.1",
    "description": "Tools for working with Nier Reincarnation.",
    "long_description": None,
    "author": "Bivi",
    "author_email": "190nano@gmail.com",
    "maintainer": None,
    "maintainer_email": None,
    "url": None,
    "packages": packages,
    "package_data": package_data,
    "install_requires": install_requires,
    "python_requires": ">=3.8,<4.0",
    "ext_modules": ext_modules,
    "entry_points": {
        "console_scripts": ["reinkuro = reinkuro.octo:main"],
    },
}

build(setup_kwargs)

setup(**setup_kwargs)
