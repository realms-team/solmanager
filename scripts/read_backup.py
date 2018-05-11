### This script reads the backup file created by the solmanager and output the
### read objects as json.

#============================ imports =========================================

import os
import argparse
import json
import time

from sensorobjectlibrary import Sol as sol, SolDefines

parser = argparse.ArgumentParser()

#============================ args ============================================

outputfile = 'solmanager.backup.json'

parser.add_argument("inputfile",
                    help="input file [../solmanager.backup]",
                    type=str)
parser.add_argument("-o", help="output file [solmanager.backup.json]", type=str)
parser.add_argument("-f", help="output format [json|csv]", type=str, default="json")
parser.add_argument("-t", help="filter SOL type (decimal type id)", type=int)

args = parser.parse_args()

if args.o is not None:
    outputfile = args.o

#============================ main ============================================

# read the file

obj_list = sol.loadFromFile(args.inputfile)

# write the output

for obj in obj_list:
    # skip if type is filtered
    if args.t is not None:
        if obj["type"] != args.t:
            continue

    # format object
    str_type = SolDefines.sol_type_to_type_name(obj["type"])
    if args.f == "json":
        obj_formated = json.dumps(obj)
    else:
        if type(obj['value']) == list:
            obj['value'] = obj['value'][0]
        obj_formated = "|".join([
            time.strftime("%a %d %b %Y %H:%M:%S UTC", time.localtime(obj["timestamp"])),
            obj["mac"]
        ]) + "|" + "|".join([str(val) for val in obj["value"].values()])

    # write object
    outfile = "backup/" + str_type + "." + args.f
    if not os.path.isfile(outfile) and args.f == "csv":
        with open(outfile, 'w') as out:
            out.write("|".join(["timestamp", "mac"]) + "|" +
                      "|".join([str(val) for val in obj["value"]]) + "\n")
    with open(outfile, 'a') as out:
        out.write(obj_formated+"\n")


