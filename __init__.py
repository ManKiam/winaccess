"""__init__"""

from .elevate import *
from .persist import *
from .uac import *

__version__ = 2.1

functions = {
    "uac": (
        uac1_info, uac2_info, uac3_info, uac4_info, uac5_info,
        uac6_info, uac7_info, uac8_info, uac9_info, uac10_info,
        uac11_info, uac12_info, uac13_info, uac14_info, uac15_info
    ),
    "persist": (
        persist1_info, persist2_info, persist3_info, persist4_info,
        persist5_info, persist6_info, persist7_info, persist8_info,
        persist9_info, persist10_info, persist11_info, persist12_info
    ),
    "elevate": (
        elevate1_info, elevate2_info, elevate3_info, elevate4_info,
        elevate5_info, elevate6_info, elevate7_info
    )
}


def scanner(uac, persist, elevate):
    log.debug(f"Comparing build number ({build_number()}) against 'Fixed In' build numbers")
    log.info(""" Id:    Type:           Compatible:     Description:\n ----   ------          -----------     -------------""")
    goods = {'uac': [], 'persist': [], 'elevate': []}
    for i in functions:
        if i == "uac" and not uac or i == "persist" and not persist or i == "elevate" and not elevate:
            continue
        for info in functions[i]:
            if int(info["Works From"]) <= int(build_number()) < int(info["Fixed In"]):
                log.info(f' {info["Id"]}\t{info["Type"]}\tYes\t\t{info["Description"]}')
                goods[i].append(info["Id"])
            else:
                log.info(f' {info["Id"]}\t{info["Type"]}\tNo\t\t{info["Description"]}')
    return goods


def run(types, id, payload, **kwargs):
    log.debug(f"Attempting to run method ({id}) configured with payload ({payload})")
    info = functions[types][int(id) - 1]
    if not int(info["Works From"]) <= int(build_number()) < int(info["Fixed In"]):
        log.error("Technique may not compatible with this system.")
    return globals()[info["Function Name"]](payload, **kwargs)
