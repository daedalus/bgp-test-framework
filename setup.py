#!/usr/bin/env python3
"""
BGPv4 Adversarial Test Framework
A comprehensive testing framework for BGPv4 implementations based on RFC 4271
"""

from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="bgp-test-framework",
    version="1.0.0",
    description="BGPv4 Adversarial Test Framework based on RFC 4271",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/bgp-test-framework",
    author="BGP Security Research",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
    keywords="bgp network security testing protocol",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "pyyaml>=5.4",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "mypy>=0.900",
        ],
    },
    entry_points={
        "console_scripts": [
            "bgp-test=bgp_test_framework.cli:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/example/bgp-test-framework/issues",
        "Source": "https://github.com/example/bgp-test-framework",
        "Documentation": "https://github.com/example/bgp-test-framework#readme",
    },
)
