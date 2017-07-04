# import os
# import sys
from setuptools import setup
# from ctypes.util import find_library

# if not find_library("erasurecode"):
#     print("Missing 'liberasurecode' please install with:")
#     print("\tDebian/Ubuntu: apt-get install liberasurecode-dev")
#     print("\tMac: brew install liberasurecode")
#     sys.exit(os.EX_USAGE)

setup(
    name="sodium11",
    version="0.9.2",
    py_modules=['sodium11'],
    install_requires=[
        "six>=1.10.0",
        "PyNaCl>=1.1.2",
        "pyyaml>=3.12",
        "click>=6.7",
        "tqdm>=4.11.2",
        "colorama>=0.3.7",
        "pycryptodomex>=3.4.5",
    ],
    tests_require=[
        "pytest>=3.1.2"
    ],
    entry_points={
        'console_scripts': [
            'sodium11=sodium11:cli'
        ],
    }
)
