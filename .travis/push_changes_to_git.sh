#! /bin/bash
# To be run as the deploy step in Travis CI: push all changes to the master branch
cd ./export
tar -zcf trust_stores_as_pem.tar.gz *
mv trust_stores_as_pem.tar.gz ../docs
cd ..

# Switch to SSH Git remote
git remote set-url origin git@github.com:nabla-c0d3/trust_stores_observatory.git
git checkout master

# Commit any changes to the trust stores
git commit -am 'Automated update of the trust stores [ci skip]'
git push
