#!/usr/bin/python

import ldap
from ldap.controls import SimplePagedResultsControl
import sys
import os
import ldap.modlist as modlist
import pprint
import argparse
import yaml
import string
import random

class AD:
    def __init__(self):
        # global vars 
        self.debug          = 0
        self.me             = None # set the path of this running script
        self.displayname    = None # 
        self.user           = None # username to be created/updated
        self.user_dn        = None # CN=John Doe,OU=Developers,OU=Users,OU=My Company,DC=example,DC=com
        self.domain         = None # domain name for the new user account
        self.employee_num   = None # number of employee ID
        self.firstname      = None # Firstname
        self.lastname       = None # Lastname
        self.mobile         = None # mobile phone number
        self.mail           = None
        self.passwd         = None # Password
        self.action         = 'create' # create/update
        self.groups         = []

        self.ldap_user      = None # account with adminitrator privileges on the Active Directory
        self.ldap_pass      = None 
        self.ldap_base_dn   = None
        self.ldap_server    = None # host for the Active Directory
        self.ldap_domain    = None # domain name (example.com)

        # call main
        self.main()

    def getparams(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--debug', dest='debug', help='Debug mode on', action='store_true', required=False)
        
        subparsers = parser.add_subparsers(help='commands')

        # create
        create_parser = subparsers.add_parser('create', help='Create a new Active Directory Account')
        create_parser.add_argument('-u','--user', action='store', metavar='<username>', help='User to be created on Active Directory', required=True, type=str)
        create_parser.add_argument('-f','--firstname', action='store', dest='firstname', help='Person Firstname', required=True)
        create_parser.add_argument('-l','--lastname', action='store', dest='lastname', help='Person Lastname', required=True, type=str)
        create_parser.add_argument('--displayname', action='store', dest='displayname', help='ie: Joe The Fantastic Doe', required=True, type=str)
        create_parser.add_argument('-m','--mail', action='store', dest='mail', help='E-Mail account', required=True, type=str)
        create_parser.add_argument('-p','--password', action='store', dest='passwd', help='Password for the user account', required=False, type=str)
        create_parser.add_argument('-g','--group', action='append', dest='groups', 
            help='Group where the user belongs. ie: -g "CN=Domain Guests,CN=Users,DC=example,DC=com"', required=False)
        create_parser.add_argument('--mobile', action='store', dest='mobile', help='Mobile Phone', required=False)

        # update
        update_parser = subparsers.add_parser('update', help='Updates an Active Directory Account')
        update_parser.add_argument('-u','--user', action='store', help='User to be updated on Active Directory', required=True, type=str)
        update_parser.add_argument('-p','--password', action='store', dest='passwd', help='Password for the user account', required=False, type=str)
        update_parser.add_argument('-f','--firstname', action='store', dest='firstname', help='Person Firstname', required=False)
        update_parser.add_argument('-l','--lastname', action='store', dest='lastname', help='Person Lastname', required=False, type=str)
        update_parser.add_argument('--displayname', action='store', dest='displayname', help='ie: Joe The Fantastic Doe', required=False, type=str)
        update_parser.add_argument('-m','--mail', action='store', dest='mail', help='E-Mail account', required=False, type=str)
        update_parser.add_argument('-g','--group', action='append', dest='groups', 
            help='Group where the user belongs. ie: -g "CN=Domain Guests,CN=Users,DC=example,DC=com"', required=False)
        update_parser.add_argument('--mobile', action='store', dest='mobile', help='Mobile Phone', required=False)

        args = parser.parse_args()

        if "update" in sys.argv[1] or "update" in sys.argv[2]: self.action = 'update' 
        if args.debug: self.debug=1 

        if self.debug: print parser.parse_args()

        try:
            self.me   = os.path.dirname(os.path.realpath(__file__)) # directory where I'm running
            self.user = args.user
            if args.firstname: self.firstname = args.firstname
            if args.lastname: self.lastname = args.lastname
            if args.mail: self.mail = args.mail
            if args.passwd: self.passwd = args.passwd
            if args.groups: self.groups = args.groups
            if args.mobile: self.mobile = args.mobile
            if args.displayname: self.displayname = args.displayname
        except Exception as e:
            print e
            pass

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

    def ldap_close(self):
        self.ldap_client.unbind_s()
        return True

    def ldap_user_exists(self, username):
        """ return 0 if user doesn't exists """
        try:
            user_results = self.ldap_client.search_s(self.ldap_base_dn, ldap.SCOPE_SUBTREE,'(userPrincipalName=%s*)' %self.user,['*'])
            if len(user_results)>0:
                self.user_dn = user_results[0][0]
                if self.debug: print "+ user [%s] exists user_dn[%s]" %(self.user,self.user_dn)
                return 1
            if self.debug: print "+ user [%s] not found" %(self.user)
            return 0
        except ldap.LDAPError, error_message:
            print "Error finding username: %s" % error_message
            return False
            sys.exit(0)

    def ldap_add_user(self):
        # this will create the username under the tree for the (self.ldap_base_dn) configured on ad-add-user.yaml
        user_dn = 'cn=' + self.firstname + ' ' + self.lastname + ',' + self.ldap_base_dn
        
        user_attrs = {}
        user_attrs['objectClass']           = ['top', 'person', 'organizationalPerson', 'user']
        user_attrs['cn']                    = [self.firstname + ' ' + self.lastname]
        user_attrs['userPrincipalName']     = [self.user + '@' + self.ldap_domain] # username@active.directory.domain.com
        user_attrs['sAMAccountName']        = [self.user] # john.doe
        user_attrs['givenName']             = [self.firstname] # John
        user_attrs['sn']                    = [self.lastname] # Doe
        user_attrs['displayName']           = [self.displayname] # self.displayname
        user_attrs['userAccountControl']    = ['514'] # account disabled
        user_attrs['mail']                  = [self.mail] # john.doe@example.com
        user_ldif = modlist.addModlist(user_attrs)

        # New group membership
        add_member = [(ldap.MOD_ADD, 'member', user_dn)]

        # Add the new user account
        try:
            if self.debug: print "+ creating user account [%s]" %self.user
            self.ldap_client.add_s(user_dn, user_ldif)
        except ldap.LDAPError, error_message:
          print "Error adding new user: %s" % error_message
          return False

        self.ldap_set_password(user_dn) # setting password
        self.ldap_add_user_to_group(groups=self.groups, user_dn=user_dn) # adding groups
        self.ldap_account_status(status='enable', user_dn=user_dn) # enable the user account
        self.ldap_set_primarygroup(user_dn=user_dn) # set primary group

        print "account created!"

    def ldap_set_password(self, user_dn):
        new_password = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(10)) \
            if self.passwd==None else self.passwd 

        unicode_pass = unicode('\"' + new_password + '\"', 'iso-8859-1')
        password_value = unicode_pass.encode('utf-16-le')
        add_pass = [(ldap.MOD_REPLACE, 'unicodePwd', [password_value])]

        try:
            if self.debug: print "+ setting password [%s] for account [%s]" %(new_password,self.user)
            self.ldap_client.modify_s(user_dn, add_pass)
            return True
        except ldap.LDAPError, error_message:
            print "Error setting password: %s" % error_message
            return False

    def ldap_set_primarygroup(self, user_dn=None, group_id=513):
        try:
            if self.debug: print "+ setting primaryGroupID to %s" %group_id
            mod_primarygroupid = [(ldap.MOD_REPLACE, 'primaryGroupID', "%s" %group_id)]
            self.ldap_client.modify_s(user_dn, mod_primarygroupid)
        except ldap.LDAPError, error_message:
            print "Error changing user's primary group: %s" % error_message
            return False

    def ldap_account_status(self, status='enable', user_dn=None):
        """ set/modify the account status to enabled (512) | disabled (514) """
        try:
            st = 512 if status.lower()=='enable' or status.lower()=='enabled' else 514 
            if self.debug: "+ setting account status to [%s] %s" %(st,status)
#            mod_acct = [(ldap.MOD_REPLACE, 'userAccountControl', '512')]
            mod_acct = [(ldap.MOD_REPLACE, 'userAccountControl', str(st))]
            self.ldap_client.modify_s(user_dn, mod_acct)
        except ldap.LDAPError, error_message:
            print "Error enabling user: %s" % error_message
            return False

    def ldap_add_user_to_group(self, groups=[], user_dn=None):
        err_flag = 0
        for group in groups:
            if self.debug: 
                print "ldap_add_user_to_group(): trying to add user [%s] to group [%s]" %(self.user, group)
                print "ldap_add_user_to_group(): [debug info] user_dn: %s" %user_dn
                print "ldap_add_user_to_group(): [debug info] self.user_dn: %s" %self.user_dn

                add_member = [(ldap.MOD_ADD, 'member', user_dn)]

                try:
                    self.ldap_client.modify_s(group, add_member)
                    if self.debug: print "ldap_add_user_to_group(): user [%s] to group [%s] successfully" %(self.user, group)
                except ldap.LDAPError, error_message:
                    print "ldap_add_user_to_group(): Error adding user to group: %s" % error_message
                    err_flag = 1
                    pass

        return False if err_flag==1 else True

    def ldap_update_field(self, user_dn=None, field=None, value=None):
        try:
            if self.debug: print "+ updating field [%s]=%s" %(field, value)
            update_field = [(ldap.MOD_REPLACE, str(field), str(value))]
            self.ldap_client.modify_s(user_dn, update_field)
        except ldap.LDAPError, error_message:
            print "ldap_update_field(): Error changing user's primary group: %s" % error_message
            return False

    def main(self):
        self.getparams()    # get command line params
        self.ldap_connect() # connect to ldap server

        if self.action=='create':
            if not self.ldap_user_exists(self.user):
                self.ldap_add_user()

        if self.action=='update':
            if self.ldap_user_exists(self.user):
                # update groups if needed
                if len(self.groups)>0:
                    self.ldap_add_user_to_group(user_dn=self.user_dn, groups=self.groups)

                # change password
                if self.passwd:
                    self.ldap_set_password(user_dn=self.user_dn)

                # update firstname
                if self.firstname:
                    self.ldap_update_field(user_dn=self.user_dn, field='givenName', value=self.firstname)

                # update lastname
                if self.firstname:
                    self.ldap_update_field(user_dn=self.user_dn, field='sn', value=self.lastname)

                # update displayname
                if self.displayname:
                    self.ldap_update_field(user_dn=self.user_dn, field='displayName', value=self.displayname)
                
                # update mail
                if self.mail:
                    self.ldap_update_field(user_dn=self.user_dn, field='mail', value=self.mail)
                
        self.ldap_close()



if __name__ == "__main__":
    ad = AD()
