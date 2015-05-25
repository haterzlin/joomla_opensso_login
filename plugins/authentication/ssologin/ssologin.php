<?php
/**
 * @version    $Id: ssologin.php 1 2015-05-15 $
 * @package    Joomla.SSOLogin
 * @subpackage Plugins
 * @license    GNU/GPL
 */
 
// Check to ensure this file is included in Joomla!
defined('_JEXEC') or die();
 
/**
 * SSOLogin Authentication Plugin.  Based on the example.php plugin in the Joomla! Core installation
 *
 * @package    Joomla.SSOLogin
 * @subpackage Plugins
 * @license    GNU/GPL
 */
class plgAuthenticationSSOLogin extends JPlugin
{
    /**
     * This method should handle any authentication and report back to the subject
     * We authenticate to OpenSSO and then to JoomlaDB
     * Password is saved to Joomla DB after succesful authentication
     * User is created in DB if don't exists
     *
     * @access    public
     * @param     array     $credentials    Array holding the user credentials ('username' and 'password')
     * @param     array     $options        Array of extra options
     * @param     object    $response       Authentication response object
     * @return    boolean
     * @since 1.5
     */

    private $ssotoken = "";
    private $ssoatributtespage = "";

    function get_new_SSO_token($login, $password) {
        // connects to RESTful authentication service and creates new session
        $ssl = "";
        if ($this->params->get('sso_protocol') == "https") $ssl = "ssl://";
        $host = $this->params->get('sso_host');
        $port = $this->params->get('sso_port');
        $page = "/".$this->params->get('sso_deploy_path')."/identity/authenticate?username=".$login."&password=".$password."&".$this->params->get('sso_authentication_additional_parameters');
        $timeout = 5;
        //echo "Connection to ".$ssl."".$host.":".$port." and request for page ".$page;

        $fp = fsockopen($ssl."".$host, $port, $errno, $errstr, $timeout);
        if (!$fp) {
          error_log("Error conecting to OpenSSO: ".$errno.": ".$errstr);
          return False;
        } else {
            $out = "POST ".$page." HTTP/1.1\r\n";
            $out .= "Host: ".$host.":".$port."\r\n";
            $out .= "UserAgent: PHP SSOLogin Joomla plugin\r\n";
            $out .= "Connection: Close\r\n\r\n";

            $temp = "";
            fwrite($fp, $out);
            while (!feof($fp)) {
                $temp .= fgets($fp, 128);
            }
            fclose($fp);
            if (strpos($temp,"token.id=") === False ) {
                error_log("sso login error ".$login." no token.id in returned page: ".$temp);
                return False;
            }
            else {
                $lines = explode("\n",$temp);
                foreach ($lines as $value) {
                    $explode = explode("=",$value);
                    if ($explode[0] == "token.id") {
                        array_shift($explode);
                        $value = implode("=",$explode);
                        $this->ssotoken = $value;
                        return True;
                    }
                }
                error_log("sso login error ". $login. " ---".$temp."---");
                return False;
            }
        }
    }

    function SSO_get_attrs() {
        //connect to OpenSSO server with ssotoken and return attributes of users to ssoattributespage
        //$token_id = cookieEncode($token_id);
        $token_id = $this->ssotoken;
        $url = $this->params->get('sso_protocol')."://".$this->params->get('sso_host')."/".$this->params->get('sso_deploy_path')."/identity/attributes";
        $opts = array( 'http' => array( 'method' => 'GET', 'header' => "Cookie: ".$this->params->get('sso_token_cookie_name')."=".$token_id."\r\n" ));
        $context = stream_context_create($opts);
        $this->ssoattributespage = file_get_contents($url, false, $context);
    }

    function attrs_get_attr_value($attr_name) {
      // return attribute value from ssoattributepage
      $lines = explode("\n",$this->ssoattributespage);
      $next = False;
      foreach ($lines as $value) {
        if ($next) {
          $explode = explode("=",$value);
          return $explode[1];
        }
        if ($value == "userdetails.attribute.name=".$attr_name) {
          $next = True;
        }
      }
      return "";
    }

    function onUserAuthenticate( $credentials, $options, &$response ) {
        // on authenticate attempt, contact OpenSSO, get SSO token and get user attributes
        if ($this->get_new_SSO_token($credentials['username'], $credentials['password'])) {
            $response->status = JAuthentication::STATUS_SUCCESS;
            $response->username = $credentials['username'];
            $this->SSO_get_attrs();
            $response->email = $this->attrs_get_attr_value($this->params->get('sso_email_attribute_name'));
            $response->fullname = $this->attrs_get_attr_value($this->params->get('sso_fullname_attribute_name'));
            //error_log("user ".$credentials['username']." logged in with ssologin plugin");
        }
        else {
	        $response->status = JAuthentication::STATUS_FAILURE;
	        $response->error_message = 'Invalid username and password';
	         error_log("user ".$credentials['username']." login error with ssologin plugin");
        }
    }
    
    function onUserAfterLogin() {
        // http://stackoverflow.com/questions/2727043/using-php-to-create-a-joomla-user-password
        $salt = JUserHelper::genRandomPassword(32);
        $crypt = JUserHelper::getCryptedPassword($_POST["password"] , $salt);
        $password = $crypt.':'.$salt;
        // Get a database object
        $user = JFactory::getUser();
        $db =& JFactory::getDBO();
        $query = $db->getQuery(true);
        $fields = array(
            $db->quoteName('password') . ' = "'.$password.'"'
        );
        $conditions = array(
            $db->quoteName('username') . ' = '.$user->username, 
        );
        $query->update($db->quoteName('#__users'))->set($fields)->where($conditions);
        $db->setQuery( $query );
        $result = $db->execute();
        //if ($result) error_log("plugin ssologin saved password of user ".$user->username." to joomla db");
        //else error_log("plugin ssologin failed to save password of user ".$user->username." to joomla db: ".mysql_error());
    }
}
?>
