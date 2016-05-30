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