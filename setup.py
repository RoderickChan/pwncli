
from setuptools import setup, find_packages

setup(
    name="pwncli",
    version="1.2",
    author="roderick chan",
    author_email="ch22166@163.com",
    description="pwncli, do pwn quickly.",
    long_description="pwncli is a tool for pwner, let you pwn quickly and more effeciently.",
    packages=find_packages(),
    include_package_data=True,
    install_requires=["click", "pwntools", "ropper", "lief", "ROPgadget"],
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