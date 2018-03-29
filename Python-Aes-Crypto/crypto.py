import pyAesCrypt
import os
import sys
import getpass
from colorama import init, Fore

BUFFER_SIZE = 64 * 1024


def show_help():
    print('Encryption usage:')
    print('\tpython crypto.py --encrypt [PATH] [[OPTIONAL] KEY_FILE]')
    print()
    print('\tKEY_FILE - if specified AES256 key will be generated and saved to that file')
    print('\totherwise script will ask about user key to encrypt data.')
    print()
    print()
    print('Decryption usage:')
    print('\tpython crypto.py --decrypt [PATH [[OPTIONAL] KEY_FILE]')
    print()
    print('\tKEY_FILE - if specified AES256 key will be loaded from that file')
    print('\totherwise script will ask about user key to decrypt data.')
    sys.stdout.flush()


def show_argv_error():
    print('Too few arguments were specified. See crypto --help')
    sys.stdout.flush()


def run_crypto(crypto_action, path, key_file):
    if crypto_action == '--encrypt':
        key = os.urandom(256) if key_file else read_key() 
        save_key(key_file, key)
        encrypt(path, key)
    elif crypto_action == '--decrypt':
        key = load_key(key_file) if key_file else read_key()
        decrypt(path, key)
    else:
        show_help()


def read_key():
    if sys.stdin.isatty():
        return str.encode(getpass.getpass('Key: '))
    else:
        print('Key: ', end='', flush=True)
        return str.encode(sys.stdin.readline().rstrip())


def load_key(key_path):
    with open(key_path, 'rb') as key_file:
        return key_file.read()


def save_key(key_path, key):
    if key_path:
        with open(key_path, 'wb') as key_file:
            key_file.write(key)


def encrypt(path, key):
    if os.path.isdir(os.path.abspath(path)):
        encrypt_dir(path, key)
    elif os.path.isfile(os.path.abspath(path)):
        encrypt_file(path, key)


def decrypt(path, key):
    if os.path.isdir(os.path.abspath(path)):
        decrypt_dir(path, key)
    elif os.path.isfile(os.path.abspath(path)):
        decrypt_file(path, key)


def encrypt_dir(path, encrypt_key):
    for root, dirs, files in os.walk(path):
        for file in files:
            encrypt_file(os.path.abspath(os.path.join(root, file)), encrypt_key)


def encrypt_file(path, encrypt_key):
    try:
        print_coloured('[   ENCRYPTING   ]: ' + path, Fore.YELLOW)
        enc_path = path + '.enc'
        pyAesCrypt.encryptFile(path, enc_path, str(encrypt_key), BUFFER_SIZE)
        os.remove(path)
        os.rename(enc_path, path)
        print_coloured('[   ENCRYPTED    ]', Fore.GREEN)
    except Exception as e:
        print_coloured('[   EXCEPTION    ]', Fore.RED)
        print_coloured(e, Fore.RED)


def decrypt_dir(path, decrypt_key):
    for root, dirs, files in os.walk(path):
        for file in files:
            decrypt_file(os.path.abspath(os.path.join(root, file)), decrypt_key)


def decrypt_file(path, decrypt_key):
    try:
        print_coloured('[   DECRYPTING   ]: ' + path, Fore.YELLOW)
        dec_path = path + '.dec'
        pyAesCrypt.decryptFile(path, dec_path, str(decrypt_key), BUFFER_SIZE)
        os.remove(path)
        os.rename(dec_path, path)
        print_coloured('[   DECRYPTED    ]', Fore.GREEN)
    except Exception as e:
        print_coloured('[   EXCEPTION    ]', Fore.RED)
        print_coloured(e, Fore.RED)


def print_coloured(text, color):
    print(color + text, flush=True)


def main():
    if '--help' in sys.argv:
        show_help()
    elif len(sys.argv) < 2:
        show_argv_error()
    else:
        key_file = sys.argv[3] if len(sys.argv) > 3 else None
        run_crypto(crypto_action=sys.argv[1], path=sys.argv[2], key_file=key_file)


if __name__ == '__main__':
    init(convert=False, strip=False)
    main()
    exit(0)
