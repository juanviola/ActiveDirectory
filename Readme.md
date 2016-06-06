# Adding users to Active Directory with Python from linux

## Requirements
- python-ldap
- python-yaml

## Downloading the AD certificate
1. Open your web browser on and paste this http://your-active-directory-server/certsrv/certcarc.asp
2. Select your CA certificate
3. Click on "Download CA certificate"
4. Open the certificate and export it as the-name-you-want.pem

## Configuration file ad-add-user.yaml 
```
ad:
  admin_user: administrator
  admin_pass: my_password
  base_dn: 'OU=Users,OU=My Company,dc=example,dc=com'
  server: 'ad01.example.com'
  domain: 'example.com'
  cert: the-name-you-want.pem
```

## Example Adding new user
```
ad-add-user.py create -u john.doe --displayname "John Awesome Doe" \
	-m john.doe@example.com --mobile "15-5555-4444" \ 
	-f John -l Doe -p "MyPass11.22" \
	-g 'CN=Domain Guests,OU=Users,DC=example,DC=com' \
	-g 'CN=Domain Admins,OU=Users,DC=example,DC=com' \
```

## Example updating user
```
./ad-add-user.py update -u john.doe \
	-g 'CN=Domain Guests,OU=Users,DC=example,DC=com' \
	-g 'CN=Domain Admins,OU=Users,DC=example,DC=com' 
```
