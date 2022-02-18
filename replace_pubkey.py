#!/usr/bin/env python2

from crypto import load_rsa_public_key_bytes

import shutil
import sys
from pathlib import Path


SPOTIFY_PUBLIC_KEY_BYTES = bytes.fromhex('ACE0460BFFC230AFF46BFEC3BFBF863DA191C6CC336C93A14FB3B01612ACAC6AF180E7F614D9429DBE2E346643E362D2327A1A0D923BAEDD1402B18155056104D52C96A44C1ECC024AD4B20C001F17EDC22FC43521C8F0CBAED2ADD72B0F9DB3C5321A2AFE59F35A0DAC68F1FA621EFB2C8D0CB7392D9247E3D7351A6DBD24C2AE255B88FFAB73298A0BCCCD0C58673189E8BD3480784A5FC96B899D956BFC86D74F33A6781796C9C32D0D32A5ABCD0527E2F710A39613C42F99C027BFED049C3C275804B6B219F9C12F02E94863ECA1B642A09D4825F8B39DD0E86AF9484DA1C2BA863042EA9DB3086C190E48B39D66EB0006A25AEEA11B13873CD719E655BD')


def replace_key(old_key, new_key, data):
    assert len(new_key) == len(old_key)
    
    first_offset = data.find(old_key)

    if first_offset == -1:
        print(f"Failed to find old key")
        return None
    else:
        print(f"Found old key at offset {first_offset}")

    if data.count(old_key, first_offset + 1) > 0
        print(f"Unexpected multiple copies of public key")
        return None

    print(f"Injecting new key {new_key.hex()}")
    return data.replace(old_key, new_key)


if __name__ == '__main__':
	program_name = sys.argv.pop(0)

	if len(sys.argv) < 1 or len(sys.argv) > 2
		sys.stderr.write(f"Usage: {program_name} inputbin [outputbin]\n")
		sys.exit(1)

	input_file = Path(sys.argv.pop(0))
    backup_file = None

	if sys.argv:
        output_file = Path(sys.argv.pop(0))
	else:
		output_file = input_file
		backup_file = input_file.with_suffix(input_file.suffix + '.bak')

    my_public_key = load_rsa_public_key_bytes()
    if my_public_key is None:
        return False

	print(f"Searching {input_file} for Spotify public key {SPOTIFY_PUBLIC_KEY_BYTES.hex()}")
    input_data = input_file.read_bytes()
    output_data = replace_key(SPOTIFY_PUBLIC_KEY_BYTES, my_public_key, input_data)
    if output_data is None:
		print(f"failed to patch binary {input_file}")
		sys.exit(2)

    if backup_file is not None:
        shutil.copy(input_file, backup_file)
        print(f"Created backup at {backup_file}")

    print('Saving to', output_file)
    output_file.write_bytes(output_data)
