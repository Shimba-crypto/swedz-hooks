from setuptools import setup, find_packages

setup(
    name="swedz-hooks",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["pymem", "psutil"],
    author="Shimba-crypto",
    description="Process hooking and memory tools",
)