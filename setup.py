from setuptools import setup
from setuptools import find_packages
import cveguess

setup(
    name='cveguess',
    version=cveguess.__version__,
    description='CVE exploit guesser',
    url='https://github.com/mtnalonso/cveguess',
    author='Martin Alonso Vilar',
    author_email='mtnalonso@protonmail.com',
    license='GNU General Public License v3 (GPLv3)',
    packages=find_packages(),
    zip_safe=False,
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        'requests',
        'rich',
        'beautifulsoup4',
    ]
)

