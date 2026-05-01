#!/bin/bash

mv reconcli.py reconcli
sudo mv reconcli /usr/local/bin/
sudo chmod +x /usr/local/bin/reconcli

rm -f reconcli.pyc

echo "reconcli installed successfully!"