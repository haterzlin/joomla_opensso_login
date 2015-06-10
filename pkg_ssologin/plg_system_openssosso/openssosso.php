<?php
// no direct access
defined( '_JEXEC' ) or die( 'Restricted access' );
 
jimport( 'joomla.plugin.plugin' );
jimport( 'openssoplugin.base.functions' );
 
/**
 * OpenSSO system plugin
 */
class plgSystemOpenssosso extends plgSystemOpenSSOPlugin
{
/**
* Constructor.
*
* @access protected
* @param object $subject The object to observe
* @param array   $config  An array that holds the plugin configuration
* @since 1.0
*/
 
    function onAfterInitialise() {
        /* zjistime, jestli je  uzivatel prihlaseny a pokud ne, zkusime udelat SSO */
        $user = JFactory::getUser();
        //$plugin = JPluginHelper::getPlugin('authentication', 'openssologin');
        //$params = new JRegistry($plugin->params);
        //echo print_r($this->params->get("sso_token_cookie_name"));
        //error_log("onAfterInitialise");
        if ($user->guest) {
            //error_log("user is guest, cookie ".$params->get('sso_token_cookie_name')." = ".$_COOKIE[$params->get('sso_token_cookie_name')]);
            if (isSet($_COOKIE[$this->params->get('sso_token_cookie_name')])) {
                //error_log("SSO token cookie is set");
                if ($this->verify_SSO_token()) {
                    //login user
                    //error_log("SSO token is verified");
                    // get username from OpenSSO
                    $this->SSO_get_attrs();
                    $uid = $this->attrs_get_attr_value($this->params->get('sso_username_attribute_name'));
                    // see if its in db
                    $db =& JFactory::getDBO();
                    $query = $db->getQuery(true);
                    $query->select('id');
                    $query->from($db->quoteName('#__users'));
                    $query->where($db->quoteName('username')." = ".$db->quote($uid));
                    $db->setQuery( $query );
                    $result = $db->loadResult();
                    $row = $db->loadRow();
                    // login to user with that id
                    if (isset($result) && $result != False) {
                        $user->load($result);
                        //error_log("Single Sign On with OpenSSO to user ".$uid);
                    }
                }
            }
        }
        else {
            //error_log("user is not guest");
            // overeni, zda neni treba prodlouzit session na OpenSSO
        }
        if ($this->session->get('ssorefreshsessiontime') != 0 && $this->session->get('ssorefreshsessiontime') < time()) {
            if ($this->verify_SSO_token()) {
                $this->set_next_SSO_token_expiration_time();
            }
        }
        //error_log("next sso session update ". date('Y-m-d H:i', $this->session->get('ssorefreshsessiontime')));
       //error_log("onAfterInitialise end");
    }

    function onUserLogout() {
        $this->destroySSOsession();
    }

}
