<?php
/**
 * @version    $Id: ssologin.php 1 2015-05-15 $
 * @package    Joomla.SSOLogin
 * @subpackage Plugins
 * @license    GNU/GPL
 */
 
// Check to ensure this file is included in Joomla!
defined('_JEXEC') or die();
jimport('openssoplugin.base.functions'); 

/**
 * SSOLogin Authentication Plugin.  Based on the example.php plugin in the Joomla! Core installation
 *
 * @package    Joomla.SSOLogin
 * @subpackage Plugins
 * @license    GNU/GPL
 */
class plgAuthenticationOpenSSOLogin extends plgSystemOpenSSOPlugin
{
    /**
     *
     * @access    public
     * @param     array     $credentials    Array holding the user credentials ('username' and 'password')
     * @param     array     $options        Array of extra options
     * @param     object    $response       Authentication response object
     * @return    boolean
     * @since 1.5
     */

    function onUserAuthenticate( $credentials, $options, &$response ) {
        // on authenticate attempt, contact OpenSSO, get SSO token and get user attributes

        if ($this->get_new_SSO_token($credentials['username'], $credentials['password'])) {
            $response->status = JAuthentication::STATUS_SUCCESS;
            $response->username = $credentials['username'];
            $this->SSO_get_attrs();
            $response->email = $this->attrs_get_attr_value($this->params->get('sso_email_attribute_name'));
            $response->fullname = $this->attrs_get_attr_value($this->params->get('sso_fullname_attribute_name'));
            error_log("user ".$credentials['username']." logged in with ssologin plugin");
        }
        else {
	        $response->status = JAuthentication::STATUS_FAILURE;
	        $response->error_message = 'Invalid username and password';
	         error_log("user ".$credentials['username']." login error with ssologin plugin");
        }
    }
    
}
?>
