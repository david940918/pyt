"""This formatter outputs the issues as plain text."""
from ..vulnerabilities.vulnerability_helper import SanitisedVulnerability


def report(
    vulnerabilities,
    fileobj,
    print_sanitised,
):
    """
    Prints issues in text format.

    Args:
        vulnerabilities: list of vulnerabilities to report
        fileobj: The output file object, which may be sys.stdout
        print_sanitised: Print just unsanitised vulnerabilities or sanitised vulnerabilities as well
    """
    n_vulnerabilities = len(vulnerabilities)
    unsanitised_vulnerabilities = [v for v in vulnerabilities if not isinstance(v, SanitisedVulnerability)]
    n_unsanitised = len(unsanitised_vulnerabilities)
    n_sanitised = n_vulnerabilities - n_unsanitised
    heading = "{}개의 취약{}을 발견{}{}\n".format(
        '0' if n_unsanitised == 0 else n_unsanitised,
        '점' if n_unsanitised == 1 else '점들',
        " ({}개 추가로 정화시킴)".format(n_sanitised) if n_sanitised else "",
        ':' if n_vulnerabilities else '.',
    )
    vulnerabilities_to_print = vulnerabilities if print_sanitised else unsanitised_vulnerabilities
    with fileobj:
        fileobj.write(heading)

        for i, vulnerability in enumerate(vulnerabilities_to_print, start=1):
            fileobj.write('{}번 째 취약점:\n{}\n\n'.format(i, vulnerability))
