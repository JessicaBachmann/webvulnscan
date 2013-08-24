import collections

LogEntry = collections.namedtuple(
    'LogEntry', ['level', 'target', 'group', 'message'])

_LEVEL_I18N = {
    u'warn': u'Warning',
    u'vuln': u'Vulnerability',
    u'info': u'Info',
}
LEVELS = (u'info', u'warn', u'vuln')


def entry_str(entry):
    return '%s: %s %s %s' % (
        _LEVEL_I18N[entry.level], entry.target, entry.group, entry.message)


class AbortProcessing(Exception):
    """ Stop searching now. """


class Log(object):
    def __init__(self, abort=False, verbosity=u'warn'):
        self.abort = abort
        self.entries = []
        self.verbosity = verbosity

    def __call__(self, level, target, group, message):
        assert level in LEVELS
        if LEVELS.index(level) < LEVELS.index(self.verbosity):
            return  # Ignore this log entry

        entry = LogEntry(level, target, group, message)
        self.entries.append(entry)
        if self.abort:
            raise AbortProcessing()

    def print_report(self, summarize=True):
        summary = collections.defaultdict(set)
        for e in self.entries:
            summary[(e.level, e.group, e.message)].add(e)

        for k, sum_entries in sorted(summary.items()):
            level, group, message = k
            if summarize and len(sum_entries) > 3:
                print(entry_str(sorted(sum_entries)[0]) +
                      ' (and %d similar)' % (len(sum_entries)-1))
            else:
                for e in sorted(sum_entries):
                    print(entry_str(e))

__all__ = ['AbortProcessing', 'Log']
