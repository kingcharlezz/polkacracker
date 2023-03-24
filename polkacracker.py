# Author: philsmd
# Date: July 2021
# License: public domain, credits go to philsmd and hashcat



# Note: NaCl uses XSalsa20 and Poly1305 for decrypting the data.
# Key derivation is done by scrypt (32768, 8, 1)



# only tested with version 3 of a PolkaWallet test wallet



from base64 import b64decode
import sys
import struct
import scrypt # py-scrypt (or use hashlib.scrypt or passlib.hash.scrypt)
from nacl.secret import SecretBox # install PyNaCl
import multiprocessing



#
# Constants
#



SCRYPT_DEFAULT_N = 32768 # 1 << 15 (2^15)
SCRYPT_DEFAULT_P =     1
SCRYPT_DEFAULT_R =     8






#
# what needs to be encoded






ENCODED = "xxx";


# Start


def decrypt_chunk(raw_data, salt, nonce, encrypted, chunk_size, password_list):
    """
    Decrypts a chunk of the encrypted data using a list of passwords.
    """
    for password in password_list:
        key = scrypt.hash(password.strip(), salt, N=SCRYPT_DEFAULT_N, r=SCRYPT_DEFAULT_R, p=SCRYPT_DEFAULT_P, buflen=32)
        box = SecretBox(key)
        try:
            box.decrypt(encrypted, nonce)
            return password.strip()
        except:
            pass
    return None


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("ERROR: Please specify the dict file within the command line", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], 'r') as fp:
        password_list = fp.readlines()

    raw_data = b64decode(ENCODED)

    salt = raw_data[0:32]

    scrypt_n = struct.unpack("<I", raw_data[32:36])[0]
    scrypt_p = struct.unpack("<I", raw_data[36:40])[0]
    scrypt_r = struct.unpack("<I", raw_data[40:44])[0]

    if scrypt_n != SCRYPT_DEFAULT_N:
        print("ERROR: Scrypt N value not valid", file=sys.stderr)
        sys.exit(1)

    if scrypt_p != SCRYPT_DEFAULT_P:
        print("ERROR: Scrypt P value not valid", file=sys.stderr)
        sys.exit(1)

    if scrypt_r != SCRYPT_DEFAULT_R:
        print("ERROR: Scrypt R value not valid", file=sys.stderr)
        sys.exit(1)

    offset = 32 + (3 * 4) # 32 byte salt + 3 numbers (N, p, r)

    nonce = raw_data[offset + 0:offset + 24]
    encrypted = raw_data[offset + 24:]

    num_processes = multiprocessing.cpu_count()
    chunk_size = len(password_list) // num_processes

    processes = []

    for i in range(num_processes):
        start_index = i * chunk_size
        end_index = start_index + chunk_size

        if i == num_processes - 1:
            end_index = len(password_list)

        chunk_password_list = password_list[start
