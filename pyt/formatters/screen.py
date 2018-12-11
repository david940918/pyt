"""This formatter outputs the issues as color-coded text."""
from ..vulnerabilities.vulnerability_helper import SanitisedVulnerability, UnknownVulnerability

RESET = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
DANGER = '\033[31m'
GOOD = '\033[32m'
HIGHLIGHT = '\033[45;1m'
RED_ON_WHITE = '\033[31m\033[107m'


def color(string, color_string):
    return color_string + str(string) + RESET


def report(
    vulnerabilities,
    fileobj,
    print_sanitised,
):
    """
    Prints issues in color-coded text format.

    Args:
        vulnerabilities: list of vulnerabilities to report
        fileobj: The output file object, which may be sys.stdout
    """
    n_vulnerabilities = len(vulnerabilities)
    unsanitised_vulnerabilities = [v for v in vulnerabilities if not isinstance(v, SanitisedVulnerability)]
    n_unsanitised = len(unsanitised_vulnerabilities)
    n_sanitised = n_vulnerabilities - n_unsanitised
    heading = "{}개의 취약{}을 발견{}.\n".format(
        '0' if n_unsanitised == 0 else n_unsanitised,
        '점' if n_unsanitised == 1 else '점들',
        " (plus {} sanitised)".format(n_sanitised) if n_sanitised else "",
    )
    vulnerabilities_to_print = vulnerabilities if print_sanitised else unsanitised_vulnerabilities
    with fileobj:
        for i, vulnerability in enumerate(vulnerabilities_to_print, start=1):
            fileobj.write(vulnerability_to_str(i, vulnerability))

        if n_unsanitised == 0:
            fileobj.write(color(heading, GOOD))
        else:
            fileobj.write(color(heading, DANGER))


def vulnerability_to_str(i, vulnerability):
    lines = []
    lines.append(color('취약점 {}'.format(i), UNDERLINE))
    lines.append('파일: {}'.format(color(vulnerability.source.path, BOLD)))
    lines.append(
        '사용자가 {}번 째 라인에, "{}"를 입력하였다:'.format(
            vulnerability.source.line_number,
            color(vulnerability.source_trigger_word, HIGHLIGHT),
        )
    )
    lines.append('\t{}'.format(color(vulnerability.source.label, RED_ON_WHITE)))
    if vulnerability.reassignment_nodes:
        previous_path = None
        lines.append('재할당:')
        for node in vulnerability.reassignment_nodes:
            if node.path != previous_path:
                lines.append('\t파일: {}'.format(node.path))
                previous_path = node.path
            label = node.label
            if (
                isinstance(vulnerability, SanitisedVulnerability) and
                node.label == vulnerability.sanitiser.label
            ):
                label = color(label, GOOD)
            lines.append(
                '\t  {}번 째 줄:\t{}'.format(
                    node.line_number,
                    label,
                )
            )
    if vulnerability.source.path != vulnerability.sink.path:
        lines.append('파일: {}'.format(color(vulnerability.sink.path, BOLD)))
    lines.append(
        'Reaches line {}, sink "{}"'.format(
            vulnerability.sink.line_number,
            color(vulnerability.sink_trigger_word, HIGHLIGHT),
        )
    )
    lines.append('\t{}'.format(
        color(vulnerability.sink.label, RED_ON_WHITE)
    ))
    if isinstance(vulnerability, SanitisedVulnerability):
        lines.append(
            '이 취약점은 {}{}. {} 이용'.format(
                color('잠재적으로 ', BOLD) if not vulnerability.confident else '',
                color('정화되었다', GOOD),
                color(vulnerability.sanitiser.label, BOLD),
            )
        )
    elif isinstance(vulnerability, UnknownVulnerability):
        lines.append(
            '이 취약점은 "{}" 때문에 알려지지 않았다.'.format(
                color(vulnerability.unknown_assignment.label, BOLD),
            )
        )
    return '\n'.join(lines) + '\n\n'
