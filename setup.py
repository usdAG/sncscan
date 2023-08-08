from setuptools import setup

setup(
    name='sncscan',
    version='0.9',
    packages=[''],
    url='https://github.com/usdAG/sncscan',
    license='GPLv3',
    author='Jonas Wamsler, Nicolas Schickert',
    author_email='jonas.wamser@usd.de',
    description='sncscan: Tool for analyzing SAP SNC Communication Security.',
    install_requires=[
        'pysap @ git+https://github.com/usdAG/pysap_sncscan.git#egg=main-sncscan']
)
