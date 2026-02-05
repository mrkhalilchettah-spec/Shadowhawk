"""
ShadowHawk Platform - Setup Configuration

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="shadowhawk",
    version="1.0.0",
    author="ShadowHawk Platform Team",
    author_email="team@shadowhawk.example.com",
    description="Enterprise-Grade Cyber Security Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shadowhawk/platform",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "shadowhawk=shadowhawk.api.main:main",
        ],
    },
)
