
from setuptools import setup, find_packages

setup(
    name="pwncli",
    version="1.0",
    author="roderick chan",
    author_email="ch22166@163.com",
    packages=find_packages(),
    include_package_data=True,
    install_requires=["click", "pwntools"],
    entry_points="""
        [console_scripts]
        pwncli=pwncli.cli:cli
    """,
)