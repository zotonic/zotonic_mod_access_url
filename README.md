mod_access_url
==============

Zotonic module for giving access to urls by signing the url with user credentials.

**This module needs Zotonic 1.0 or newer**

URLs are signed using a user specific secret. This secret is stored in the `identity` table.
Accessing a signed url gives access to that *single request* using all the access permissions of the signing user.
Only that single url will be accessible, any other url or request will use the credentials of the requesting user.

URLs signed by this module look like this:

    https://example.com/en/page/20652?z_access_url=true&z_access_url_token=jRM4PvTUU65aExNCisCG&z_access_url_nonce=MHbsQAUPdTS1U3oTgO8B&z_access_url_sig=IQ00Vrmn1D0JGjKegKeP%2FfCoS%2F40XI%2BC2xrqO4xPP%2FA%3D

In the template it can be created by adding the `z_access_url` argument:

    {% url page id=20652 z_access_url %}

The `z_access_url` argument is picked up by `mod_access_url` which then signs the generated url with the `z_access_url_nonce`, `z_access_url_token` and `z_access_url_sig` arguments. Note that there must be an authenticated user to be able to sign an url.
