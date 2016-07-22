#!/usr/bin/python
"""
  rsyncs a file to the encryptonator platform
"""
from Crypto.Cipher import AES
import os
import tarfile
import hashlib
import argparse
import commands
import time
import gnupg
import struct
import rsa


def parse():
    """ parse script options """

    parser = argparse.ArgumentParser(
        formatter_class=lambda prog:
        argparse.RawDescriptionHelpFormatter(prog, max_help_position=36))

    parser.add_argument('-f', '--file', dest='src_file', help='File name to sync')
    parser.add_argument('-d', '--dir', dest='src_dir', help='Sync files in this directory')
    parser.add_argument('-t', '--time', dest='time', help='Only sync files that were changed in the specified number of hours')
    parser.add_argument('-p', '--platform', dest='platform', required=True, help='Platform to sync for')
    parser.add_argument('-i', '--identity', dest='identity', default='encryptonator_id_rsa', help='SSH identity file')
    parser.add_argument('-e', '--encryptonator', dest='encryptonator', default='encryptonator.ecg.so', help='Encryptonator server')
    parser.add_argument('-c', '--crypt', help='Encrypt before sending', action='store_true')

    arguments = parser.parse_args()
    if arguments.src_file and arguments.src_dir:
        parser.error('Please specify either a file or a directory, not both')
        quit(1)
    elif not arguments.src_file and not arguments.src_dir:
        parser.error('Please specify either a file or a directory')
        quit(1)

    return arguments


def encrypt(file_path):
    """ encrypt a file """

    out_filename = '{}.enc'.format(file_path)

    # create random aes key, encrypt it using gpg with a
    # specific rsa 2048 key and store it
    gpg = gnupg.GPG(gnupghome='{0}/.gnupg'.format(os.environ['HOME']))
    all_public_keys = gpg.list_keys()
    all_public_keys_names = []
    for public_key in all_public_keys:
        key_uid = public_key['uids'][0]
        all_public_keys_names.append(key_uid)
    if not any(public_key_name.startswith('encryptonator') for public_key_name in all_public_keys_names):
        print 'ENC: No rsa key found. Stopping encryption.'
        print 'Please run generate_encryptonate_gpg_keys.py to create the GPG key'
        quit(1)

    aes_key = str(rsa.randnum.read_random_bits(256))
    aes_key_file_name = '{}.aes'.format(file_path)
    gpg_aes_key_file_name = '{}.gpg'.format(aes_key_file_name)
    # temporarily store the encrypted aes key
    with open(aes_key_file_name, 'wb') as aes_key_file:
        aes_key_file.write(aes_key)
    # encrypt the aes key file. gpg recipient name is equal to 'encryptonator'
    with open(gpg_aes_key_file_name, 'wb') as gpg_file, open(aes_key_file_name, 'rb') as aes_file:
        gpg.encrypt_file(aes_file, recipients='encryptonator', output=gpg_aes_key_file_name)
    # remove the temporary aes file
    os.remove(aes_key_file_name)

    # create the md5sum of the enrypted aes key and store it
    gpg_aes_key_file_md5 = get_md5sum(gpg_aes_key_file_name)
    gpg_aes_file_md5 = gpg_aes_key_file_name + '.md5'
    sftpsite_md5_file_format = gpg_aes_key_file_md5 + '  ' + os.path.basename(gpg_aes_key_file_name)
    with open(gpg_aes_file_md5, 'wb') as md5_out:
        md5_out.write(sftpsite_md5_file_format)
    print 'ENC: Stored AES key in {}'.format(os.path.basename(gpg_aes_key_file_name))

    # encrypt the input file using the generated aes key, taken from:
    # http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
    iv = rsa.randnum.read_random_bits(128)
    mode = AES.MODE_CBC
    encryptor = AES.new(aes_key, mode, iv)

    filesize = os.path.getsize(file_path)
    chunksize = 64*1024

    with open(file_path, 'rb') as in_file, open(out_filename, 'wb') as out_file:
        out_file.write(struct.pack('<Q', filesize))
        out_file.write(iv)
        while True:
            chunk = in_file.read(chunksize)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                chunk += ' ' * (16 - len(chunk) % 16)
            out_file.write(encryptor.encrypt(chunk))

    # create the md5sum of the encrypted file and store it
    out_filename_md5 = get_md5sum(out_filename)
    out_file_md5 = out_filename + '.md5'
    sftpsite_md5_file_format = out_filename_md5 + '  ' + os.path.basename(out_filename)
    with open(out_file_md5, 'wb') as md5_out:
        md5_out.write(sftpsite_md5_file_format)
    print 'Finished encrypting {}'.format(os.path.basename(file_path))

    # pack the files together and remove original
    file_path_tar = '{}.encrypted.tar'.format(file_path)
    out_filename_md5 = '{}.md5'.format(out_filename)
    gpg_aes_key_file_name_md5 = '{}.md5'.format(gpg_aes_key_file_name)
    create_tar(file_path_tar,
               out_filename,
               out_filename_md5,
               gpg_aes_key_file_name,
               gpg_aes_key_file_name_md5)


def get_md5sum(md5_file):
    """ return the md5 of a file """
    md5hash = hashlib.md5()
    with open(md5_file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5hash.update(chunk)
    return md5hash.hexdigest()


def create_tar(dst_file, *src_files):
    """ add files to tar archive """
    os.chdir(os.path.dirname(dst_file))
    tar = tarfile.open(dst_file, 'w')
    for src_file in src_files:
        tar.add(os.path.basename(src_file))
        os.remove(src_file)
    tar.close()


def rsync_file(src_file, platform, enc_user, identity, enc_server, crypt):
    """ start rsync """
    if crypt:
        encrypt(src_file)
        tar_file = '{}.encrypted.tar'.format(src_file)
    else:
        tar_file = src_file

    ssh_id = '{0}/.ssh/{1}'.format(os.environ['HOME'], identity)

    rsync_cmd = "/usr/bin/rsync -avx -e 'ssh -i {0}' {1} {2}@{3}::{4}/".format(ssh_id, tar_file, enc_user, enc_server, platform)
    rsync_output = commands.getstatusoutput(rsync_cmd)

    if crypt:
        try:
            os.remove(tar_file)
        except OSError:
            pass

    if rsync_output[0] != 0:
        print 'Something broke while rsyncing: {0}'.format(rsync_output[1])
        quit(1)


if __name__ == "__main__":

    args = parse()
    platform_user = '{0}_encryptonator'.format(args.platform)

    if args.src_file:
        if os.path.isfile(args.src_file):
            if rsync_file(args.src_file, args.platform, platform_user,
                          args.identity, args.encryptonator, args.crypt):
                print "Sync completed for {0}".format(args.src_file)
                quit(0)
        else:
            print "{0} is not a file".format(args.src_file)
            quit(1)
    elif args.src_dir:
        if not os.path.exists(args.src_dir):
            print "{0} does not exist".format(args.src_dir)
            quit(1)
        for sync_file in os.listdir(args.src_dir):
            sync_file = '{0}/{1}'.format(args.src_dir, sync_file)
            if os.path.isfile(sync_file):
                if args.time:
                    change_time = args.time
                    now_epoch = time.time()
                    ctime_epoch = os.path.getctime(sync_file)
                    time_difference = (now_epoch - ctime_epoch)/60/60
                    if int(time_difference) < int(change_time):
                        if rsync_file(sync_file, args.platform, platform_user,
                                      args.identity, args.encryptonator, args.crypt):
                            print "Sync completed for {0}".format(sync_file)
                else:
                    if rsync_file(sync_file, args.platform, platform_user,
                                  args.identity, args.encryptonator, args.crypt):
                        print "Sync completed for {0}".format(sync_file)
        quit(0)
