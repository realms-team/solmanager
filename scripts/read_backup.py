### This script reads the backup file created by the solmanager and output the
### read objects as json.

#============================ imports =========================================

import sys
import os
import argparse
import json
import time

if __name__ == "__main__":
    here = sys.path[0]
    sys.path.insert(0, os.path.join(here, '..','..', 'sol'))

from solobjectlib import Sol, SolDefines

sol = Sol.Sol()
parser = argparse.ArgumentParser()

#============================ args ============================================

inputfile = '../solmanager.backup'
outputfile = 'solmanager.backup.json'

parser.add_argument("-i", help="input file [../solmanager.backup]", type=str)
parser.add_argument("-o", help="output file [solmanager.backup.out]", type=str)
parser.add_argument("-f", help="output format [json|csv]", type=str, default="json")
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

for obj in obj_list:
    # skip if type is filtered
    if args.t is not None:
        if obj["type"] != args.t:
            continue

    # format object
    str_type = SolDefines.solTypeToTypeName(SolDefines, obj["type"])
    if args.f == "json":
        obj_formated = json.dumps(obj)
    else:
        obj_formated = " | ".join([
            time.strftime("%a %d %b %Y %H:%M:%S UTC", time.localtime(obj["timestamp"])),
            obj["mac"]
        ]) + " | " + " | ".join([str(val) for val in obj["value"].values()])

    # write object
    outfile = "backup/" + str_type + "." + args.f
    if not os.path.isfile(outfile) and args.f == "csv":
        with open(outfile, 'w') as out:
            out.write(" | ".join(["timestamp", "mac"]) + " | " +
                      " | ".join([str(val) for val in obj["value"]]) + "\n")
    with open(outfile, 'a') as out:
        out.write(obj_formated+"\n")


