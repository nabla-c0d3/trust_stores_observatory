Trust Stores Observatory
------------------------


[![Build Status](https://travis-ci.org/nabla-c0d3/trust_stores_observatory.svg?branch=master)](https://travis-ci.org/nabla-c0d3/trust_stores_observatory)

The Trust Stores Observatory monitors the content of the major platforms' root certificate stores. 

More specifically, it provides the following features:

* An easy way to download the most up-to-date root certificate stores, via a permanent link: [https://nabla-c0d3.github.io/trust_stores_observatory/trust_stores_as_pem.tar.gz](https://nabla-c0d3.github.io/trust_stores_observatory/trust_stores_as_pem.tar.gz).
* The ability to record any changes made to the root stores, by committing such changes to Git. This way we can keep the history of the root stores and for example keep track of when a new root certificate was added.
* The ability to review and compare the content of the different root stores, by storing the content of each store in a YAML file.

### Supported trust stores

* Apple iOS and macOS
* Google Android Open Source Project
* Microsoft Windows
* Mozilla NSS
* Oracle Java
* OpenJDK

Each trust store is checked for changes once a week.

### More information

The following blog post provides additional information about this project: [https://nabla-c0d3.github.io/blog/2018/01/16/trust-stores-observatory/](https://nabla-c0d3.github.io/blog/2018/01/16/trust-stores-observatory/).
