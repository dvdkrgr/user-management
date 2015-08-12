<?php

namespace webvimark\modules\UserManagement\models\forms;

use webvimark\helpers\LittleBigHelper;
use webvimark\modules\UserManagement\models\User;
use webvimark\modules\UserManagement\UserManagementModule;
use yii\base\Model;
use Yii;

class LoginForm extends Model {

  public $username;
  public $password;
  public $rememberMe = false;
  public $ldap_login = false;
  private $_user = false;

  /**
   * @inheritdoc
   */
  public function rules() {
    return [
      [['username', 'password'], 'required'],
      [['rememberMe', 'ldap_login'], 'boolean'],
      ['password', 'validatePassword'],
      ['username', 'validateIP'],
    ];
  }

  public function attributeLabels() {
    return [
      'username' => UserManagementModule::t('front', 'Login'),
      'password' => UserManagementModule::t('front', 'Password'),
      'rememberMe' => UserManagementModule::t('front', 'Remember me'),
      'ldap_login' => UserManagementModule::t('front', 'LDAP-Login'),
    ];
  }

  /**
   * Validates the password.
   * This method serves as the inline validation for password.
   */
  public function validatePassword() {
    if (!Yii::$app->getModule('user-management')->checkAttempts()) {
      $this->addError('password', UserManagementModule::t('front', 'Too many attempts'));

      return false;
    }

    if (!$this->hasErrors()) {
      $user = $this->getUser();
      if (!$user || !$user->validatePassword($this->password)) {
        $this->addError('password', UserManagementModule::t('front', 'Incorrect username or password.'));
      }
    }
  }

  /**
   * Check if user is binded to IP and compare it with his actual IP
   */
  public function validateIP() {
    $user = $this->getUser();

    if ($user AND $user->bind_to_ip) {
      $ips = explode(',', $user->bind_to_ip);

      $ips = array_map('trim', $ips);

      if (!in_array(LittleBigHelper::getRealIp(), $ips)) {
        $this->addError('password', UserManagementModule::t('front', "You could not login from this IP"));
      }
    }
  }

  /**
   * Logs in a user using the provided username and password.
   * @return boolean whether the user is logged in successfully
   */
  public function login() {

    //Get the user object
    $user = $this->getUser();
    //No user found? Return incorrect username or password error 
    if ($user == NULL) {
      $this->addError('password', UserManagementModule::t('front', 'Incorrect username or password.'));
      return false;
    }
    else {
      // If the found user is declared as an ldap user jump into this block
      if ($user->ldap_user) {

        // Get config parameters
        $ldap_servers = Yii::$app->user->ldapServer;
        $ldap_domains = Yii::$app->user->ldapDomain;

        // Variable to use and change later
        $ldap_connection_established = false;

        // Loop through every given ldap_server...
        foreach ($ldap_servers as $ldap_server) {

          // If the server name contains : split it and use port parameter
          // otherwise use the normal ldap_connect method
          if (strpos($ldap_server, ":") !== false) {
            $ldap_server_explode = explode(":", $ldap_server);
            $connect = ldap_connect("ldap://" . $ldap_server_explode[0], $ldap_server_explode[1]);
          }
          else {
            $connect = ldap_connect("ldap://" . $ldap_server);
          }

          // Set LDAP options for the connection
          ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, 3);
          ldap_set_option($connect, LDAP_OPT_REFERRALS, 0);

          // ...and also loop through every ldap_domain
          foreach ($ldap_domains as $ldap_domain) {
            // Set auth user and auth password for the connection
            // domain slashes were only added if length is over zero 
            // to prevent errors on empty domains
            $auth_user = '';
            if (strlen($ldap_domain) > 0) {
              $auth_user = $ldap_domain . "\\";
            }
            $auth_user .= $this->username;
            $auth_pass = $this->password;

            // Able to connect to the server with the credentials? 
            // Set variable to true and break the inner foreach loop
            if (($bind = @ldap_bind($connect, $auth_user, $auth_pass))) {
              $ldap_connection_established = true;
              break;
            }
          }
          // There was a working ldap connection established? Close the 
          // connection and break the outer foreach loop
          if ($ldap_connection_established) {
            ldap_close($connect);
            break;
          }
        }

        // No connection to the LDAP server with the domain name? 
        // Close existing LDAP connection and return an error
        if (!$ldap_connection_established) {
          $this->addError('password', UserManagementModule::t('front', 'Incorrect username or password.'));
          ldap_close($connect);
          return false;
        }
        else {
          // Correct connection? Login as the given user
          return Yii::$app->user->login($user, $this->rememberMe ? Yii::$app->user->cookieLifetime : 0);
        }
      }
      else {
        // No ldap user? Verify and login or return false
        if ($this->validate()) {
          return Yii::$app->user->login($user, $this->rememberMe ? Yii::$app->user->cookieLifetime : 0);
        }
        else {
          return false;
        }
      }
    }
  }

  /**
   * Finds user by [[username]]
   * @return User|null
   */
  public function getUser() {
    if ($this->_user === false) {
      $this->_user = User::findByUsername($this->username);
    }

    return $this->_user;
  }

}
