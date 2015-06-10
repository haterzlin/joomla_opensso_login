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
class plgSystemOpenSSOPlugin extends JPlugin
{
    /**
     * basic functions used for communication with OpenSSO
     * ssotoken - store for current user token
     * ssoatributtespage - store for current user attributes
     */

    private $ssotoken = "";
    private $ssoatributtespage = "";

    public function __construct(& $subject, $config)
    {
        parent::__construct($subject, $config);
        $this->loadLanguage();
        $plugin = JPluginHelper::getPlugin('authentication', 'openssologin');
        $params = new JRegistry($plugin->params);
        $this->params = $params;
        $this->session = JFactory::getSession();
    }

    public function create_SSO_token_cookie() {
        if (! isset($_SERVER["HTTP_HOST"]))
            $domain = $_SERVER["SERVER_NAME"];
        else
            $domain = $_SERVER["HTTP_HOST"];
        $exploded_domain = explode(".", $domain);
        $domain = implode(".",array_slice($exploded_domain, -2));
        //error_log("domain is ".$domain." sso token is ".$this->ssotoken);
        $result = setrawcookie($this->params->get('sso_token_cookie_name'), $this->ssotoken, time() + 60*60*10, "/", $domain, True, True);
        return $result;
    }
    
    public function set_next_SSO_token_expiration_time() {
        $this->session->set('ssorefreshsessiontime', time() + $this->params->get('sso_session_update_interval'));
    }

    public function reset_SSO_token_expiration_time() {
        $this->session->set('ssorefreshsessiontime', 0);
    }

    function get_new_SSO_token($login, $password) {
        // connects to RESTful authentication service and creates new session
        $ssl = "";
        if ($this->params->get('sso_protocol') == "https") $ssl = "ssl://"; // is config included?
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
                        //error_log("saved ssotoken: ".$this->ssotoken);
                        $this->create_SSO_token_cookie();
                        $this->set_next_SSO_token_expiration_time();
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

    function verify_SSO_token() {
        /* Verify SSO token value at OpenSSO and returns true or false */
        $url = $this->params->get('sso_protocol')."://".$this->params->get('sso_host')."/".$this->params->get('sso_deploy_path')."/identity/isTokenValid";
        $opts = array( 'http' => array( 'method' => 'GET', 'header' => "Cookie: ".$this->params->get('sso_token_cookie_name')."=".$_COOKIE[$this->params->get('sso_token_cookie_name')]."\r\n" ));
        $context = stream_context_create($opts);
        $file_contents = @file_get_contents($url, false, $context); //@ will make errors disappear
        if (strpos($file_contents,"boolean=true") === False ) {
            //error_log(date("Y-m-d H:i:s")." ".$_SESSION["uid"]." ".$token_id." invalid, REST page content: ".$file_contents, 3, "/app/iwa1_ws/logs/token_verify.log");
            return False;
        }
        else {
            //error_log(date("Y-m-d H:i:s")." ".$_SESSION["uid"]." ".$token_id." ok\n", 3, "/app/iwa1_ws/logs/token_verify.log");
            $this->ssotoken = $_COOKIE[$this->params->get('sso_token_cookie_name')];
            $this->set_next_SSO_token_expiration_time();
            return True;
        }
    }

    function destroySSOsession() {
        if (isset($_COOKIE[$this->params->get('sso_token_cookie_name')])) {
            $url = $this->params->get('sso_protocol')."://".$this->params->get('sso_host')."/".$this->params->get('sso_deploy_path')."/identity/logout?subjectid=".$_COOKIE[$this->params->get('sso_token_cookie_name')];
            $opts = array( 'http' => array( 'method' => 'POST'));
            $context = stream_context_create($opts);
            $result = file_get_contents($url, false, $context);
            if ($result) {
                //error_log("OpenSSO session destroyed succesfully");
                $this->reset_SSO_token_expiration_time();
            }
        }
    }


}
?>
