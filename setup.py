from setuptools import setup, find_packages

from auth_token.version import get_version

setup(
    name='django-auth-token',
    version=get_version(),
    description="Django authorization via tokens.",
    keywords='django, authorization',
    author='Lubos Matl',
    author_email='matllubos@gmail.com',
    url='https://github.com/druids/django-auth-token',
    license='BSD',
    package_dir={'auth_token': 'auth_token'},
    include_package_data=True,
    packages=find_packages(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP',
    ],
    install_requires=[
        'django>=1.11',
    ],
    zip_safe=False
)
