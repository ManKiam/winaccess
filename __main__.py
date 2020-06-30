import argparse
import sys

from . import *

log.info("UAC level: {}".format(uac_level()))
log.info("Build number: {}".format(build_number()))
log.info("Running elevated: {}".format(admin()))
log.info("Python version: {}.{}.{}\n".format(*sys.version_info))

scan_cmds = list(functions)

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--scan", nargs="+", required=False, help="Scan for either uac, persist or elevate method")
parser.add_argument("-u", "--use", nargs="+", required=False, help="Use either uac, persist or elevate method")
parser.add_argument("-i", "--id", nargs="+", required=False, help="Id of method")
parser.add_argument("-p", "--payload", nargs="+", required=False, help="Full path to payload, can include params")
parser.add_argument("-r", "--remove", action="store_true", required=False, help="Removes installed persistence")
parser.add_argument("-d", "--debug", action="store_true", required=False, help="debugging")
args = parser.parse_args()

if args.debug:
    logging.basicConfig(level=logging.DEBUG)

if args.scan:
    if not all([_ in scan_cmds for _ in args.scan]):
        parser.print_help()
        sys.exit(1)

    print(scanner(**{scan_cmds[_]: scan_cmds[_] in args.scan for _ in range(3)}))

if args.use and args.id:
    if not all([_ in scan_cmds for _ in args.use]) or not args.payload:
        parser.print_help()
        sys.exit(1)

    if scan_cmds[0] in args.use:
        print(run("uac", id=args.id[0], payload=args.payload))

    if scan_cmds[1] in args.use:
        print(run("persist", id=args.id[0], payload=args.payload, add=(False if args.remove else True)))

    if scan_cmds[2] in args.use:
        print(run("elevate", id=args.id[0], payload=args.payload))
