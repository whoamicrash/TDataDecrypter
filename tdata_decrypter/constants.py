import os

APP_TITLE = 'TDataDecrypter'

CFG_PATH = os.path.join(os.path.expanduser('~'), '.tdatadecrypter.json')

MASK32 = 0xFFFFFFFF

M32 = 0xFFFFFFFF

K_PART_SIZE = 128 * 1024

K_IN_SLICE = 8 * 1024 * 1024

MAX_SLICE_GAP = 64

MAX_SLICES_PER_FILE = 4096

MAX_MERGE_BYTES = 4 * 1024 ** 3

GOOD_BOXES = {b'ftyp', b'moov', b'mdat', b'moof', b'sidx', b'free', b'skip',
              b'wide', b'uuid', b'styp', b'ssix', b'prft', b'emsg', b'mfra', b'pdin'}


TAG_PREFIX = {1: 'image', 2: 'sticker', 3: 'voice', 4: 'round', 5: 'gif'}

TAG_NAMES = {0: 'generic', 1: 'image', 2: 'sticker', 3: 'voice_message',
             4: 'video_message', 5: 'animation'}


KEY_KINDS = ((0xFFFFFFFFFFFFFF00, 0x0000000000000100, 'document'),
             (0xFFFFFFFFFFFFFF00, 0x0000000000000200, 'document_thumb'),
             (0xFFFFFFFFFFFFFF00, 0x0000000000000300, 'album_thumb'),
             (0x0000FF0000000000, 0x0000010000000000, 'document_chunk'),
             (0x000000FF00000000, 0x0000000100000000, 'photo_chunk'),
             (0xFFFFFF0000000000, 0x0000020000000000, 'web_document'),
             (0xFFFFFF0000000000, 0x0000030000000000, 'url'),
             (0xFFFFFF0000000000, 0x0000040000000000, 'geo_point'))


LSK_SUBFILES = {0x09: 'user_settings', 0x0A: 'hashtags_bots', 0x0F: 'saved_gifs',
                 0x11: 'trusted_peers', 0x12: 'faved_stickers', 0x13: 'export_settings',
                 0x18: 'search_suggestions', 0x1C: 'media_playback', 0x1E: 'prefs'}


PEER_VERSION_TAG = 0x77FFFFFFFFFFFFFF

MODERN_IMAGE_TAG = -(2 ** 31)

PARTIAL_MIN_JPEG = 8000

MIN_JPEG = 600
