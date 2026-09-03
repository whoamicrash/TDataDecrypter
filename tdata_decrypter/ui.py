class Options:
    def __init__(self):
        self.sort_media = True
        self.merge_videos = True
        self.clean_texts = True
        self.raw_dump = True
        self.keep_staging = False


class ConsoleUI:

    def __init__(self):
        self.cancelled = False

    def log(self, msg, level='info'):
        prefix = {'ok': '[+]', 'warn': '[!]', 'err': '[X]'}.get(level, '[i]')
        print(f'{prefix} {msg}', flush=True)

    def progress(self, frac, note=''):
        pass

    def stage(self, name):
        print(f'\n=== {name} ===', flush=True)
