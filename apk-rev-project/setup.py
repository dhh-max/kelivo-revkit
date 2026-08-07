#!/usr/bin/env python3
"""APK Reverse Engineering Engine v2 - Setup"""
from setuptools import setup, find_packages
setup(
    name='apk-reverse-engine',
    version='2.2.0',
    description='全功能 APK 逆向工具集 - 解包/分析/反编译/修补/重打包/签名 一站式工具',
    long_description='''APK Reverse Engineering Engine v2
全功能 APK 逆向工程工具集，涵盖：
- APK 解包/打包/签名/对齐
- DEX/ELF 解析分析
- Manifest 解析与编辑 - 二进制 AXML 直接解析与修改
- 混淆/加固/SDK/隐私检测
- 线索串联/核心类定位/字符串分析
- 资源混淆检测/网络端点提取
- Smali 补丁/原生补丁/资源补丁
- 多语言支持(i18n)
- 基础工具：APK 文件操作(删除/添加/更新/搜索)
- 基础工具：Manifest 二进制操作(查找/删除/替换组件与属性)
- 签名证书指纹提取：直接解析 v2/v3 Signing Block 提取证书 SHA-256(纯标准库)
''',
    long_description_content_type='text/plain',
    author='Kelivo RevKit',
    packages=find_packages(),
    include_package_data=True,
    python_requires='>=3.8',
    install_requires=[
        'rich>=13.0.0',
        'pycryptodome>=3.0',
    ],
    extras_require={
        'full': [
            'androguard>=3.4',
            'pyaxmlparser>=0.3.3',
            'pyelftools>=0.29',
        ],
        'decompile': [
            'jadx>=0.0.1',
            'androguard>=3.4',
        ],
    },
    entry_points={
        'console_scripts': [
            'reng=apk_reverse_engine.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Software Development :: Reverse Engineering',
        'Topic :: Security',
    ],
    keywords='apk reverse-engineering android dex smali analysis security',
)