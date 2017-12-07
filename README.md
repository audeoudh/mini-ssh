ssh_mini
========

A minimal python SSH client.


Utilization
-----------

The main CLI entry point is the `__main__.py` file. One can launch it by typing

    $ python __main__.py user@host

Its utilization is copied from the standard `ssh` command, but of course, not
all its options are supported.

If the package is installed somewhere (_i.e._ if PYTHONPATH contains this
package), one can also run this project by typing

    $ python -m Mini_SSH


Architecture
------------

* Interaction
  * `__main__.py`, main entry point for CLI usage.
* Core
  * `ssh_engine.py`, the SSH core. Handles incoming messages and their dispatch
    to the services.
* Abstraction
  * `fields.py`, abstraction of the SSH data structures. Based on the
    [section 5 of RFC 4251](https://tools.ietf.org/html/rfc4251#section-5).
  * `messages.py`, abstraction of the main SSH messages. The specific messages
    (_e.g._ elliptic-curve messages) are not defined there.
  * `transport.py`, a SSH equivalent to the TCP `sockets` of python stdlib.
    Handles the TCP socket itself and the main packet parsing (it send and
    receive SSH messages). It does not handle the key exchange mechanism, but
    uses the keys to encrypt/decrypt and check/produce MACs.
* Supported security algorithms
  * `asym_algos.py`, a description of asymmetric algorithms
  * `cipher_algos.py`, a standardization of supported ciphering algorithms
  * `hash_algos.py`, a standardization of hashing algorithms
  * `mac_algos.py`, a standardization of MAC algorithms
