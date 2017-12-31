Trust Stores Observatory
------------------------

The Trust Stores Observatory monitors the content of the major platforms' root certificate stores. 

More specifically, it provides the following features:

* An easy way to download the most up-to-date trust stores, via a permanent link: https://nabla-c0d3.github.io/trust_stores_observatory/trust_stores_as_pem.tar.gz .
* The ability to keep track of any change made to the trust stores, by committing such changes to Git. This allows keeping the history of the root certificate stores, and detecting any changes made to them (such as the addition of a new root certificate).
* The ability to review and compare the content of the different trust stores. The content of each trust store is stored in a YAML file in _./trust_stores_.

### Supported trust stores

* Apple iOS and macOS
* Google Android Open Source Project
* Microsoft Windows
* Mozilla NSS

Each trust store is checked for changes once a week.

