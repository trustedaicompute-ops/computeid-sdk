from setuptools import setup, find_packages

setup(
    name="computeid-sdk",
    version="1.0.0",
    description="Cryptographic identity for AI compute infrastructure and agentic AI systems",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="ComputeID",
    author_email="hello@compute-id.com",
    url="https://github.com/trustedaicompute-ops/computeid-sdk",
    py_modules=["computeid"],
    install_requires=["requests>=2.28.0"],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    keywords="gpu identity certificates quantum-safe ai agents security cryptography",
)
