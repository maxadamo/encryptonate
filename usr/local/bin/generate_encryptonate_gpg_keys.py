#!/usr/bin/python
"""
  Generate encryptonator GPG key
"""
import subprocess
import getpass
import gnupg
import apt
import os


if __name__ == "__main__":

    isvirtual = subprocess.check_output('/usr/bin/facter -p is_virtual',
                                        shell=True).replace('\n', '')

    if isvirtual == 'true':
        cache = apt.Cache()
        if not cache['haveged'].is_installed:
            print 'Please install the package "haveged" and run its daemon\n'
            print 'This is a virtual server, which does not meet the necessary'
            print 'entropy condition to generate the GPG keys.\n'
            print 'NOTE: the package can be removed once the key has been generated'
            os.sys.exit(1)

    try:
        gpg = gnupg.GPG(gnupghome='{0}/.gnupg'.format(os.environ['HOME']))
        pass_phrase_1 = getpass.getpass(prompt='Please enter a passphrase: ')
        pass_phrase_2 = getpass.getpass(prompt='Enter the passphrase again: ')
        if pass_phrase_1 != pass_phrase_2:
            print "The passphrase does not match"
            quit(1)
        key_input = gpg.gen_key_input(
            key_type='RSA',
            key_length='2048',
            name_real='encryptonator',
            name_email='email@domain.com',
            expire_date='4y',
            passphrase=pass_phrase_2)
        key_data = gpg.gen_key(key_input)
        import_key = gpg.import_keys(str(key_data))
    except Exception, e:
        print 'Failed to generate key: {0}'.format(e)
