# PASSWORD DICTIONARY ATTACK

import hashlib
import os


# FILE STORED TO LIST
word_list = []  # WORD LIST
hash_list = []  # HASH LIST


# ALL FILE PLACED IN THE LISTS DIRECTORY
# FOR DYNAMIC FILE ENTRY
# FILE NAME SHOULD BE INPUTED


# password_cracking/lists/W9193504_OSEI_AVAILLO.txt
# password_cracking/lists/wordlist.txt


hash_file = input('PASWORD HASH FILE NAME IN TXT FORMAT: ')
word_file = input('WORD LIST FILE NAME IN TXT FORMAT: ')


hash_file_path = os.path.abspath("./password_cracking/lists/" + hash_file)
word_list_file_path = os.path.abspath("./password_cracking/lists/" + word_file)
md5result_list_path = os.path.abspath(
    "./password_cracking/result/mds_result.txt")
sha256result_list_path = os.path.abspath(
    "./password_cracking/result/sha256_result.txt")
sha224result_list_path = os.path.abspath(
    "./password_cracking/result/sha224_result.txt")


# EXTRACT HASH BY LINE
# STORE HASH IN LIST

try:
    with open(hash_file_path, "r") as hashes:
        hash_extract = hashes.readlines()
        for line in hash_extract:
            line_obj = {'salt': line.split(':')[0].strip(), 'hash': line.split(':')[
                1].strip()}  # SPLIT THE SALT FROM HASH
            hash_list.append(line_obj)

# EXTRACT WORDLIST
# STORE WORD IN LIST

    with open(word_list_file_path, "r") as words:
        word_extract = words.readlines()
        for lines in word_extract:
            word_list.append(lines.strip())  # strip all trails to return word

    # CHECK THE HASHING TYPE
    for obj in hash_list:
        for word in word_list:

            raw_to_be_hashed = (word + obj['salt']).encode('utf-8')

            # CHECK FOR MD5 HASH

            check_md5 = hashlib.md5(raw_to_be_hashed.strip()).hexdigest()

            if check_md5 == obj['hash']:

                # WRITE RESULT IN FILE
                with open(md5result_list_path, "a") as md5_result:
                    md5_result.write(
                        f"WORD->{word} MD5 HASH->{check_md5} HASH IN FILE->{obj['hash']} SALT->{obj['salt']} \n")

                # CHECK FOR SHA224

            check_sha224 = hashlib.sha224(raw_to_be_hashed.strip()).hexdigest()

            if check_sha224 == obj['hash']:
                print(word, check_sha224, obj['hash'])

                # WRITE RESULT IN FILE
                with open(sha224result_list_path, "a") as sha224_result:

                    sha224_result.write(
                        f"WORD->{word}  SHA224 HASH->{check_sha224} HASH IN FILE->{obj['hash']} SALT->{obj['salt']} \n")

                # CHECK FOR SHA256

            check_sha256 = hashlib.sha256(raw_to_be_hashed.strip()).hexdigest()
            if check_sha256 == obj['hash']:
                hash_list.remove(obj)  # remove the found hash to reduce search

                with open(sha256result_list_path, "a") as sha256_result:

                    sha256_result.write(
                        f"WORD -> {word} SHA256 HASH->{check_sha256} HASH IN FILE->{obj['hash']} SALT->{obj['salt']} \n")

    print('NO MATCH')
    exit()
except Exception as e:
    print(f'THIS ERROR OCCURED->>> {e}')
