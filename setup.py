from importlib.metadata import entry_points
import setuptools

setuptools.setup(
    name='scanner',
    version='1.0.0',
    author='spacetimed',
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts' : ['scanner=scanner.__main__:main']
    },
)