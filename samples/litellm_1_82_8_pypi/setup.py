from setuptools import setup, find_packages

setup(
    name="litellm",
    version="1.82.8",
    packages=find_packages(),
    install_requires=["openai", "tiktoken"],
)
