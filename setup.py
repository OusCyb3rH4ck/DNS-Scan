from setuptools import setup, find_packages

setup(
    name='dns-scan',
    version='0.1.4',
    description='A tool to get all DNS subdomains passively',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='OusCyb3rH4ck',
    author_email='OusCyb3rH4ck@proton.me',
    url='https://github.com/OusCyb3rH4ck/DNS-Scan',
    packages=find_packages(),
    install_requires=[
        'requests',
        'colorama',
        'tabulate',
        'pwn',
        'pwntools',
    ],
    entry_points={
        'console_scripts': [
            'dns-scan = dns_scan.main:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX :: Linux',
    ],
    python_requires='>=3.6',
)
