import argparse
import os
from sys import exit
from scanner.main import Scanner

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-f', '--file', type=os.path.abspath, help='relative file name')
    group.add_argument('-H', '--hash', type=str, help='hash')
    args = parser.parse_args()

    if args.file is not None:
        Scanner(args.file, which='file')

    elif args.hash is not None:
        Scanner(args.hash, which='hash')

    exit()

if __name__ == '__main__':
    main()