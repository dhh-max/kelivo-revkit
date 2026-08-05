#!/usr/bin/env python3
"""APK Reverse Engineering Engine v2 - Setup"""
from setuptools import setup, find_packages

setup(
    name='apk-reverse-engine',
    version='2.0.0',
    description='全功能 APK 逆向工具集 - 解包/分析/反编译/修补/重打包/签名 一站式工具',
    author='Kelivo RevKit',
    packages=find_packages(),
    include_package_data=True,
    python_requires='>=3.8',
    install_requires=[
        'rich>=13.0.0',
    ],
    entry_points={
        'console_scripts': [
            'reng=apk_reverse_engine.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Reverse Engineering',
    ],
)