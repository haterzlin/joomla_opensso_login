Joomla plugin for OpenSSO authentication
----------------------------------------

FEATURES
--------
* Login in OpenSSO and use sso token cookie to login to joomla application
* Login in Joomla verifing username and password in OpenSSO and create sso token cookie to login to other OpenSSO connected apps
* When session at OpenSSO is destroyed, you can work in Joomla app
* Logout destroys sso token cookie
* Saves password to Joomla DB after successful login, so it's possible to login when OpenSSO is down
* Your sso token cookie is verified after 15 minutes and activity in joompla app, so session at OpenSSO is refreshed and you can use your sso token cookie to log to other application

PACKAGING
---------
zip all modules and then create archive which contains:

language - direcotory with language files
lib_openssoplugin.zip
pkg_ssologin.xml - xml file
plg_authentication_openssologin.zip
plg_system_openssosso.zip
plg_user_savepasswd.zip

INSTALLATION
------------
1. Install package through joomla plugin menu
2. Configure authentication plugin
3. Enable all new plugins
4. Set authentication modules priority as is your wish
