import pyAesCrypt
import os
import sys
import getpass
from colorama import init, Fore

BUFFER_SIZE = 64 * 1024


def show_help():
    print('Encryption usage:')
    print('\tpython crypto.py --encrypt [PATH]')
    print()
    print('Decryption usage:')
    print('\tpython crypto.py --decrypt [PATH]')
    sys.stdout.flush()


def show_argv_error():
    print('Too few arguments were specified. See crypto --help')
    sys.stdout.flush()


def run_crypto(crypto_action, path):
    key = read_key()
    if os.path.isdir(os.path.abspath(path)):
        if crypto_action == '--encrypt':
            encrypt_dir(path, key)
        elif crypto_action == '--decrypt':
            decrypt_dir(path, key)
        else:
            show_help()
    else:
        if crypto_action == '--encrypt':
            encrypt_file(path, key)
        elif crypto_action == '--decrypt':
            decrypt_file(path, key)
        else:
            show_help()


def read_key():
    if sys.stdin.isatty():
        return getpass.getpass('Key: ')
    else:
        print('Key: ', end='', flush=True)
        return sys.stdin.readline().rstrip()


def encrypt_dir(path, encrypt_key):
    for root, dirs, files in os.walk(path):
        for file in files:
            encrypt_file(os.path.abspath(os.path.join(root, file)), encrypt_key)


def encrypt_file(path, encrypt_key):
    try:
        print_coloured('[   ENCRYPTING   ]: ' + path, Fore.YELLOW)
        pyAesCrypt.encryptFile(path, path + '.enc', encrypt_key, BUFFER_SIZE)
        os.remove(path)
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
        pyAesCrypt.decryptFile(path, os.path.splitext(path)[0], decrypt_key, BUFFER_SIZE)
        os.remove(path)
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
        run_crypto(sys.argv[1], sys.argv[2])


if __name__ == '__main__':
    init(convert=False, strip=False)
    main()
    exit(0)
