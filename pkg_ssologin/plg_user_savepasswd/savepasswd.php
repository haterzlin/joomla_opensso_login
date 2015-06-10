<?php
/**
 * @version    $Id: savepasswd.php 1 2015-05-15 $
 * @package    Joomla.SSOLogin
 * @subpackage Plugins
 * @license    GNU/GPL
 */
 
// Check to ensure this file is included in Joomla!
defined('_JEXEC') or die();
 
/**
 * SSOLogin User Plugin.  Based on the example.php plugin in the Joomla! Core installation
 *
 * @package    Joomla.SSOLogin
 * @subpackage Plugins
 * @license    GNU/GPL
 */
class plgUserSavePassword extends JPlugin
{
    /**
     * Password is saved to Joomla DB after succesful authentication
     *
     * @access    public
     * @return    boolean
     * @since 1.5
     */
    
    function onUserAfterLogin() {
        /* po uspesnem prihlaseni ulozime heslo */
        if (isSet($_POST["password"]) && $_POST["password"]!="") {
            // misto $_POST["password"] by melo byt 
            //$jinput = JFactory::getApplication()->input;
            //$password = $jinput->get('password', '', 'STRING');
            // http://stackoverflow.com/questions/2727043/using-php-to-create-a-joomla-user-password
            jimport('joomla.user.helper');
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
                $db->quoteName('username') . ' = "'.$user->username.'"', 
            );
            $query->update($db->quoteName('#__users'))->set($fields)->where($conditions);
            $db->setQuery( $query );
            $result = $db->execute();
            return $result;
        }
        return false;
    }

}
?>
