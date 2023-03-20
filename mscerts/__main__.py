import argparse

from mscerts import contents, where

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--contents", action="store_true")
parser.add_argument("-s", "--stl", action="store_true")
args = parser.parse_args()

if args.contents:
    print(contents())
else:
    print(where())
