#!/usr/bin/python
"""
  decrypts and downloads a file from Sftp Site
"""
from tempfile import mkdtemp
from Crypto.Cipher import AES
from glob import glob
import gnupg
import hashlib
import os
import re
import tarfile
import struct
import argparse
import shutil
import getpass


def parse():
    """ pass arguments to the script """
    parser = argparse.ArgumentParser(description="retrieve and decrypt files from sftpsite")
    parser.add_argument('-f', '--file-name', help='File name to decrypt (full path)', required=True)

    return parser.parse_args()


def decrypt_file(aesfile, encfile, gpgfile, outfname, passphrase):
    """ Decrypt file """
    gpg = gnupg.GPG(gnupghome='{0}/.gnupg'.format(os.environ['HOME']))
    # decrypt gpg file
    with open(gpgfile, 'rb') as gpg_in_file:
        gpg.decrypt_file(gpg_in_file, passphrase=passphrase, output=aesfile)
    os.remove(gpgfile)
    # check if the gpg decrypted file was created
    if not os.path.exists(aesfile):
        return

    # read aes key file
    with open(aes_file, 'rb') as aes_in_file:
        aes_key = aes_in_file.read()

    chunksize = 24*1024

    with open(encfile, 'rb') as in_file:
        origsize = struct.unpack('<Q', in_file.read(struct.calcsize('Q')))[0]
        iv = in_file.read(16)
        decryptor = AES.new(aes_key, AES.MODE_CBC, iv)
        with open(outfname, 'wb') as out_file:
            while True:
                chunk = in_file.read(chunksize)
                if len(chunk) == 0:
                    break
                out_file.write(decryptor.decrypt(chunk))
            out_file.truncate(origsize)
    for remove_file in aes_file, encfile:
        os.remove(remove_file)


def check_gpg():
    """ Decrypt file """
    gpg = gnupg.GPG(gnupghome='{0}/.gnupg'.format(os.environ['HOME']))
    all_public_keys = gpg.list_keys()
    all_public_keys_names = []
    for public_key in all_public_keys:
        key_uid = public_key['uids'][0]
        all_public_keys_names.append(key_uid)
    if not any(public_key_name.startswith('encryptonator') for public_key_name in all_public_keys_names):
        print 'Could not find any rsa key for {}'.format(os.environ['USER'])
        print 'Please run this tool with the same user used for the backup'
        quit(1)


def extract_tar(tar_file, tar_dir):
    """ extract 'tar_file' to 'tar_dir' """
    tar = tarfile.open(tar_file)
    tar.extractall(path=tar_dir)
    tar.close()


def check_md5(md5_file):
    """ return the md5 of a file """
    md5hash = hashlib.md5()
    with open(md5_file, "rb") as l:
        for chunk in iter(lambda: l.read(4096), b""):
            md5hash.update(chunk)
    return md5hash.hexdigest()


if __name__ == "__main__":

    check_gpg()
    ARGS = parse()
    file_name = ARGS.file_name
    pass_phrase = getpass.getpass(prompt='Insert your passphrase: ')

    base_dir = os.path.dirname(ARGS.file_name)
    if not base_dir:
        print 'Error: please provide the full path of file_name'
        quit(1)

    base_file = os.path.basename(ARGS.file_name)
    tmp_dir = mkdtemp(prefix=base_file + '-', dir=base_dir)
    # extract files to a tmp dir
    try:
        extract_tar(file_name, tmp_dir)
    except Exception, e:
        print'Error while unpacking {0}: {1}'.format(file_name, e)
        quit(1)

    enc_file = glob('{0}/*.enc'.format(tmp_dir))[0]
    gpg_file = glob('{0}/*.gpg'.format(tmp_dir))[0]
    aes_file = re.sub(r'.aes.gpg$', '.aes', gpg_file)
    out_file_name = re.sub(r'.enc$', '', enc_file)

    for checksum in [gpg_file, enc_file]:
        f = open('{}.md5'.format(checksum))
        if check_md5(checksum) != f.readline().split()[0]:
            print 'MD5 mismatch for {}'.format(checksum)
            quit(1)
    # start decrypting
    try:
        decrypt_file(aes_file, enc_file, gpg_file, out_file_name, pass_phrase)
    except Exception, e:
        print'Error while decrypting: {0}'.format(e)

    if not os.path.exists(out_file_name):
        if not os.path.exists(aes_file):
            print 'Failed to decrypt GPG file {}: wrong passphrase?'.format(gpg_file)
        else:
            print 'Something went wrong while decrypting {0}'.format(file_name)
    else:
        out_file_base_name = os.path.basename(out_file_name)
        decrypted_file = os.path.join(base_dir, out_file_base_name)
        print 'File succesfully decrypted as {}'.format(decrypted_file)
        os.rename(out_file_name, decrypted_file)
        os.remove(file_name)

    shutil.rmtree(tmp_dir)
