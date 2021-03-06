#!/usr/bin/env python

# Execute with
# $ python webvulnscan/__main__.py (2.6+)
# $ python -m webvulnscan          (2.7+)

import sys

if __package__ is None and not hasattr(sys, "frozen"):
    # direct call of __main__.py
    import os.path
    path = os.path.realpath(os.path.abspath(__file__))
    sys.path.append(os.path.dirname(os.path.dirname(path)))

import webvulnscan

if __name__ == '__main__':
    webvulnscan.main()
