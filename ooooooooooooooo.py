import os, sys
import re

r = re.compile(rb'<RSAKeyValue>(.*?)</RSAKeyValue>', re.DOTALL)

def main(metadata_path: str) -> None:
    f = open(metadata_path, 'rb+')
    data = f.read()
    matches = [i for i in r.finditer(data)]

    if len(matches) < 1:
        print('No RSA key found')
        sys.exit(1)

    print(f'Found {len(matches)} RSA key(s)')
    for i, match in enumerate(matches):
        key = match.group().decode().replace("\n", "").replace("\r", "").replace(" ", "")
        print(f'\n{i} - RSAKey at {match.start()}: {key}')
        
    #Let the user select the key that they want to replace
    key_to_replace = input(f'Which key do you want to replace? (0-{len(matches)-1}) ')

    k = matches[int(key_to_replace)]
    k_str = k.group().decode()
    k_max_len = len(k_str)

    print(f'Replacing: {k_str}')
    replacement = b''

    if "\r\n" in matches[int(key_to_replace)].group().decode():
        print('Selected key is a multiline key. Replacement key needs to be read from a file.')
        answer = input('Do you want to save the key for editing? (y/n): ')
        if answer == 'y':
            with open("key.txt", "wb") as ky:
                ky.write(k.group())
            print('Key saved to key.txt')

        rep_key_name = input('Please enter the path for the replacement key (syntax of the key needs to be same): ')
        with open(rep_key_name, 'rb') as rep_key_file:
            replacement = rep_key_file.read()
    else:
        #Let the user enter the replacement key
        new_key = input(f'Enter the new key (must be {k_max_len} characters!): ')
        replacement = new_key.encode()

    if (len(replacement) != k_max_len):
        print(f'Key must be {k_max_len} characters long!')
        sys.exit(1)

    #Replace the key
    f.seek(k.start())
    f.write(replacement)
    f.close()

    print('Key replaced! Please recrypt the metadata before using it.')

if __name__ == '__main__':

    if len(sys.argv) != 2:
        print('Genshin RSA Key Extractor & Modifier')
        print('Usage: {} <decrypted-metadata>'.format(sys.argv[0]))
        sys.exit(1)

    metadata = sys.argv[1]
    if os.path.isfile(metadata):
        main(metadata)
    else:
        print(f'Cannot find {metadata}, please check your path.')
        sys.exit(1)
