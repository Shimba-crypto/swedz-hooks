"""
setup.py for swedz-hooks
"""

from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="swedz-hooks",
    version="1.0.0",
    author="swedz-hooks contributors",
    description=(
        "Windows process memory manipulation and hooking library — "
        "pattern scanning, pointer chains, INT3 breakpoints, and more."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/swedz-hooks",
    packages=find_packages(exclude=["examples", "tests", "tests.*"]),
    python_requires=">=3.7",
    install_requires=[
        "pymem>=1.9",
        "psutil>=5.9",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers",
        "Topic :: System :: Operating System Kernels :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
    ],
    keywords=[
        "windows", "memory", "hacking", "hooking", "breakpoint",
        "pattern-scan", "pymem", "cheat", "reverse-engineering",
    ],
)
