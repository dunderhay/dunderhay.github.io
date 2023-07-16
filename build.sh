#!/bin/bash

# remove old site content
rm -rf ./docs

# build the site again
hugo --destination docs --buildFuture

# remove public folder as not required. should be ignored by .gitignore anyway
rm -rf ./public
