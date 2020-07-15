import re

from cverooster.common.exception import CveIDInvalidFormattError


def parse_cve_id(cve_id):
    matched = re.match(r"^CVE-([0-9]{4})-([0-9]{4,})$", cve_id)
    if matched and len(matched.groups()) == 2:
        cve_year = int(matched.group(1))
        cve_number_str = matched.group(2)
        cve_number = int(cve_number_str.lstrip("0"))
        return cve_year, cve_number
    else:
        raise CveIDInvalidFormattError(cve_id)
