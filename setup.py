import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="amazon-pay-v2",
    version="0.0.1",
    author="Hatraco GmbH",
    author_email="webdev@hatraco.de",
    description="A simple amazon pay api implementation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.hatraco-shop.de/onlineshop/amazon_pay",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Apache v2",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
    install_requires=[
        'requests',
        'cryptography',
    ]
)
