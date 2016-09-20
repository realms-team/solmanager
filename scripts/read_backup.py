### This script reads the backup file created by the solmanager and output the
### read objects as json.

#============================ imports =========================================

import sys
import os
import argparse
import json

if __name__ == "__main__":
    here = sys.path[0]
    sys.path.insert(0, os.path.join(here, '..','..', 'sol'))

from solobjectlib import Sol

sol = Sol.Sol()
parser = argparse.ArgumentParser()

#============================ args ============================================

inputfile = '../solmanager.backup'
outputfile = 'solmanager.backup.json'

parser.add_argument("-i", help="input file [../solmanager.backup]", type=str)
parser.add_argument("-o", help="output file [solmanager.backup.json]", type=str)
parser.add_argument("-t", help="filter SOL type (decimal type id)", type=int)

args = parser.parse_args()
if args.i is not None:
    inputfile = args.i
if args.o is not None:
    outputfile = args.o

#============================ main ============================================

# read the file

obj_list = sol.loadFromFile(inputfile)

# write the output

with open(outputfile, 'w') as out:
    for obj in obj_list:
        if args.t is not None:
            if obj["type"] == args.t:
                out.write(json.dumps(obj)+"\n")
        else:
            out.write(json.dumps(obj)+"\n")
