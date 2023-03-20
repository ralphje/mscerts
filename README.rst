mscerts
=======

This package provides easy access to the Root Certificate Authorities present in
the Microsoft Trusted Root Program. It is a fork of Kenneth Reitz's
`certifi <https://pypi.org/project/certifi/>`_ project, which provides access
to Mozilla's collection of Root Certificates.

**Warning:** Microsoft's CA Program allows granular CA deprecation, which is not
properly supported by certificate bundle files. This means that using this
bundle may result in improper trust being applied, e.g. trusting certificates
that are not actually trusted in their current use.

It is therefore **highly recommended** to use `certifi` instead for almost all
needs, except in cases where the Microsoft store is specifically required, such
as in the `signify <https://pypi.org/project/signify/>`_ project.

Installation
------------
``mscerts`` is available on PyPI. Simply install it with ``pip``::

    $ pip install mscerts

Usage
-----
To reference the installed certificate authority (CA) bundle, you can use the
built-in function::

    >>> import mscerts

    >>> mscerts.where()
    '/usr/local/lib/python3.7/site-packages/mscerts/cacert.pem'

Or from the command line::

    $ python -m mscerts
    /usr/local/lib/python3.7/site-packages/mscerts/cacert.pem


Addition/Removal of Certificates
--------------------------------
This package is simply a mirror of the Microsoft store, and does not support
any addition/removal or other modification of the CA trust store content.
The sole provider of certificates in this store is Microsoft. See
https://aka.ms/RootCert for more information.
