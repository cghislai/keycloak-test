# keycloak-test
Testing keycloak

Just a test bed to try some keycloak features and application integrations.

## beid authenticator spi

 - Extends the keycloak 'X509/Validate username' provider.
 - Uses the same config model, but with other meanings:
   - If a 'user attribute' parameter is provided, the subject DN serial number (belgian national number) will be
     used to match an user against that field
   - If no 'user attribute' parameter is provider, the last name and first given name will be used to match an user
   - CRL/OCSP options should behave the same way as the original provider
   - All other options are ignored 

