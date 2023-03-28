
from setuptools import find_packages, setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="pwncli",
    version="1.5",
    author="roderick chan",
    author_email="ch22166@163.com",
    description="pwncli, do pwn quickly.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    install_requires=["click", "pwntools"],
    entry_points="""
        [console_scripts]
        pwncli=pwncli.cli:cli
    """,
    url="https://github.com/RoderickChan/pwncli",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License"
    ],
)