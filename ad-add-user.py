#!/usr/bin/python

import ldap
from ldap.controls import SimplePagedResultsControl
import sys
import os
import ldap.modlist as modlist
import pprint
import argparse
import yaml

class AD:
    def __init__(self):
        # global vars 
        self.me             = None
        self.user           = None # username to be created
        self.domain         = None # domain name for the new user account
        self.employee_num   = None # number of employee ID
        self.firstname      = None # Firstname
        self.lastname       = None # Lastname
        self.passwd         = 'Clave11..22' # Password

        self.ldap_user      = None # account with adminitrator privileges on the Active Directory
        self.ldap_pass      = None 
        self.ldap_base_dn   = None
        self.ldap_server    = None # host for the Active Directory
        self.ldap_domain    = None # domain name (example.com)

        # call main
        self.main()

    def getparams(self):
        parser = argparse.ArgumentParser(prog='ad-add-user', description='Creates Active directory Accounts', 
            epilog='Usage: ad-add-user --user <user> -f <name> -l <lastname> -d <domain>')

        parser.add_argument('-u', '--user', dest='user', help='User to be created on Active Directory', required=True, type=str)
        parser.add_argument('-e', '--employee-num', dest='employee_num', help='Number of employee expedient', required=True, type=str)
        parser.add_argument('-f', '--firstname', dest='firstname', help='First Name', required=True, type=str)
        parser.add_argument('-l', '--lastname', dest='lastname', help='Last Name', required=True, type=str)
        parser.add_argument('-d', '--domain', dest='domain', help='Domain Name', required=True, type=str)

        args = parser.parse_args()

        self.me             = os.path.dirname(os.path.realpath(__file__)) # directory where I'm running
        self.user           = args.user
        self.firstname      = args.firstname
        self.lastname       = args.lastname
        self.employee_num   = args.employee_num
        self.domain         = args.domain

        self.getconfig()

    def getconfig(self):
        try:
            with open("%s/ad-add-user.yaml" %self.me, "r") as config_file:
                config = yaml.load(config_file)
            config_file.closed

            self.ldap_user      = config['ad']['admin_user']
            self.ldap_pass      = config['ad']['admin_pass']
            self.ldap_base_dn   = config['ad']['base_dn']
            self.ldap_server    = config['ad']['server']
            self.ldap_domain    = config['ad']['domain']
            self.ldap_cert      = config['ad']['cert']
        except Exception as e:
            print e

    def ldap_connect(self):
        try:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            self.ldap_client = ldap.initialize("ldaps://%s:636" %self.ldap_server)
            self.ldap_client.set_option(ldap.OPT_REFERRALS, 0)
            self.ldap_client.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            self.ldap_client.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
            self.ldap_client.set_option(ldap.OPT_X_TLS_DEMAND, True )
            self.ldap_client.set_option(ldap.OPT_DEBUG_LEVEL, 255 )
            self.ldap_client.set_option(ldap.OPT_X_TLS_CACERTFILE,"%s" %(self.ldap_cert))
            self.ldap_client.simple_bind_s("%s@%s" %(self.ldap_user, self.ldap_domain), "%s" %self.ldap_pass)
        except ldap.LDAPError, error_message:
          print "Error connecting to LDAP server: %s" % error_message
          return False

    def ldap_user_exists(self, username):
        """ return 0 if user doesn't exists """
        try:
            user_results = self.ldap_client.search_s(self.ldap_base_dn, ldap.SCOPE_SUBTREE,'(userPrincipalName=%s*)' %self.user,['*'])
            if len(user_results)>0:
                return 1
            return 0
        except ldap.LDAPError, error_message:
            print "Error finding username: %s" % error_message
            return False

    def ldap_add_user(self):
        # Lets build our user: Disabled to start (514)
        user_dn = 'cn=' + self.firstname + ' ' + self.lastname + ',' + self.ldap_base_dn
        user_attrs = {}
        user_attrs['objectClass'] = ['top', 'person', 'organizationalPerson', 'user']
        user_attrs['cn'] = [ self.firstname + ' ' + self.lastname ]
        user_attrs['userPrincipalName'] = [self.user + '@' + self.domain]
        user_attrs['sAMAccountName'] = [self.user]
        user_attrs['givenName'] = [self.firstname]
        user_attrs['sn'] = [self.lastname]
        user_attrs['displayName'] = [self.firstname + ' ' + self.lastname]
        user_attrs['userAccountControl'] = ['514']
        user_attrs['mail'] = [self.user + '@' + self.domain]
        user_attrs['employeeID'] = [str(self.employee_num)]
        user_ldif = modlist.addModlist(user_attrs)

        # Prep the password
        unicode_pass = unicode('\"' + self.passwd + '\"', 'iso-8859-1')
        password_value = unicode_pass.encode('utf-16-le')
        add_pass = [(ldap.MOD_REPLACE, 'unicodePwd', [password_value])]
        # 512 will set user account to enabled
        mod_acct = [(ldap.MOD_REPLACE, 'userAccountControl', '512')]
        # New group membership
        add_member = [(ldap.MOD_ADD, 'member', user_dn)]
        # Replace the primary group ID
        #mod_pgid = [(ldap.MOD_REPLACE, 'primaryGroupID', GROUP_TOKEN)]
        mod_pgid = [(ldap.MOD_REPLACE, 'primaryGroupID', 'Usuarios')]
        # Delete the Domain Users group membership
        del_member = [(ldap.MOD_DELETE, 'member', user_dn)]

        # Add the new user account
        try:
            print "creating user account..."
            self.ldap_client.add_s(user_dn, user_ldif)
        except ldap.LDAPError, error_message:
          print "Error adding new user: %s" % error_message
          return False

        # Add the password
        try:
            print "adding password..."
            self.ldap_client.modify_s(user_dn, add_pass)
        except ldap.LDAPError, error_message:
          print "Error setting password: %s" % error_message
          return False

    def main(self):
        self.getparams()                        # get command line params
        self.ldap_connect()                     # connect to ldap server
        if self.ldap_user_exists(self.user):    # check user 
            print "user account %s already exists" %self.user
        else:
            print "user account %s doesn't exists" %self.user
            self.ldap_add_user()


if __name__ == "__main__":
    ad = AD()
