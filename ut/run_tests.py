#!/usr/bin/env python3.exe

import subprocess
import sys
import os

if __name__ == "__main__":
    for (dir, _, files) in os.walk(os.curdir):
        for file in files:
            print(file)
