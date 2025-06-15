#!/usr/bin/env python
import logging
import os
from importlib import util
from os import path

import setuptools
from setuptools import setup

# read the contents of your README file
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

logger = logging.getLogger(__name__)
spec = util.spec_from_file_location(
    "airiam.version", os.path.join("airiam", "version.py")
)
# noinspection PyUnresolvedReferences
mod = util.module_from_spec(spec)
spec.loader.exec_module(mod)  # type: ignore
version = mod.version  # type: ignore

setup(
    extras_require={
        "dev": [
            "Cerberus>=1.3.4",
            "coverage>=7.0.0",
            "coverage-badge>=1.1.0",
            "moto>=4.2.0",
            "pytest>=8.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "ruff>=0.1.0"
        ]
    },
    install_requires=[
        "boto3>=1.34.0",
        "colorama>=0.4.6",
        "python-terraform>=0.10.1",
        "requests>=2.31.0",
        "termcolor>=2.3.0"
    ],
    license="Apache License 2.0",
    name="airiam",
    version=version,
    description="Least privilege AWS IAM Terraformer",
    author="bridgecrew",
    author_email="meet@bridgecrew.io",
    url="https://github.com/bridgecrewio/AirIAM",
    packages=setuptools.find_packages(exclude=["tests*"]),
    scripts=["bin/airiam","bin/airiam.cmd"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    python_requires=">=3.8",
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: Software Development :: Build Tools',
        'Topic :: System :: Systems Administration'
    ]
)
