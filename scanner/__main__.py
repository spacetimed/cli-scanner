import argparse
import os
from scanlib.main import Scanner

parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file', type=os.path.abspath, help='relative file name', required=True)
args = parser.parse_args()

Scanner(args.file)