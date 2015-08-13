from setuptools import find_packages, setup

setup(
    name='ByteSpinner',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'click >= 4.1',
        'pycrypto >= 2.6'
    ],
    entry_points='''
        [console_scripts]
        bytespinner=ByteSpinner.cli:cli
    ''',
)
