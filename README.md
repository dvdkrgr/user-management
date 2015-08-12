!!! THIS IS NOT THE ORIGINAL webvimark/module-user-management PACKAGE !!!


This package is modified like the following:

It is possible to set the boolean attribute ldap_user for an user object ($user->ldap_user = true)
A user declared as an ldap user will not be authenticated to the local database, instead it will be
checked against the directory.

If the the login is successful the user will be logged in as the user that is given in the local database.

You can set multiple LDAP servers and multiple LDAP domains inside the config file:

    'user' => [
      'class' => 'webvimark\modules\UserManagement\components\UserConfig',
      'ldapServer' => ['10.11.12.13','1.2.3.4','99.99.99.99'],
      'ldapDomain' => ['YOURDOMAIN','ANOTHERDOMAIN'],
     ]

The login procedure will try out every server/domain combination with the given credentials.
If you want to use a server port just declare the LDAP server like 12.13.14.16:9999

Example usage of this plugin:

You have local users inside the database with passwords (non ldap users). Additionally to this you want to bind an active directory to 
your application.

In this case you could create a Yii2 command controller that is going to run monthly/weekly/daily/hourly (whatever you want) and 
synchronizes the ldap users into yout database like the this:


$security = new \yii\base\Security();
$new_user = new \webvimark\modules\UserManagement\models\User;
$new_user->id = NULL;
$new_user->username = "newuser";
$new_user->password = md5($security->generateRandomString());
$new_user->email = "newuser@example.com";
$new_user->email_confirmed = true;
$new_user->ldap_user = true;
$new_user->save();


Notice: I'm using $security->generateRandomString inside md5() method to generate a random strong password inside the local database.
It is just necessary to create this user to have an user object on the webpage that is controlled by our ldap user. 


!!! END OF THE MODIFICATION NOTICE !!!



User management module for Yii 2
=====

Perks
---

* User management
* RBAC (roles, permissions and stuff) with web interface
* Registration, authorization, password recovery and so on
* Visit log
* Optimised (zero DB queries during usual user workflow)
* Nice widgets like GhostMenu or GhostHtml::a where elements are visible only if user has access to route where they point


Installation
------------

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```
composer require --prefer-dist webvimark/module-user-management "*"
```

or add

```
"webvimark/module-user-management": "*"
```

to the require section of your `composer.json` file.

Configuration
---

1) In your config/web.php

```php

'components'=>[
	'user' => [
		'class' => 'webvimark\modules\UserManagement\components\UserConfig',

		// Comment this if you don't want to record user logins
		'on afterLogin' => function($event) {
				\webvimark\modules\UserManagement\models\UserVisitLog::newVisitor($event->identity->id);
			}
	],
],

'modules'=>[
	'user-management' => [
		'class' => 'webvimark\modules\UserManagement\UserManagementModule',

		// Here you can set your handler to change layout for any controller or action
		// Tip: you can use this event in any module
		'on beforeAction'=>function(yii\base\ActionEvent $event) {
				if ( $event->action->uniqueId == 'user-management/auth/login' )
				{
					$event->action->controller->layout = 'loginLayout.php';
				};
			},
	],
],

```

To learn about events check:

* http://www.yiiframework.com/doc-2.0/guide-concept-events.html
* http://www.yiiframework.com/doc-2.0/guide-concept-configurations.html#configuration-format

Layout handler example in *AuthHelper::layoutHandler()*

To see full list of options check *UserManagementModule* file


2) In your config/console.php (this is needed for migrations and working with console)

```php

'modules'=>[
	'user-management' => [
		'class' => 'webvimark\modules\UserManagement\UserManagementModule',
	],
],

```

3) Run migrations

```php

./yii migrate --migrationPath=vendor/webvimark/module-user-management/migrations/

```

4) In you base controller

```php

public function behaviors()
{
	return [
		'ghost-access'=> [
			'class' => 'webvimark\modules\UserManagement\components\GhostAccessControl',
		],
	];
}

```

Where you can go
-----

```php

<?php
use webvimark\modules\UserManagement\components\GhostMenu;
use webvimark\modules\UserManagement\UserManagementModule;

echo GhostMenu::widget([
	'encodeLabels'=>false,
	'activateParents'=>true,
	'items' => [
		[
			'label' => 'Backend routes',
			'items'=>UserManagementModule::menuItems()
		],
		[
			'label' => 'Frontend routes',
			'items'=>[
				['label'=>'Login', 'url'=>['/user-management/auth/login']],
				['label'=>'Logout', 'url'=>['/user-management/auth/logout']],
				['label'=>'Registration', 'url'=>['/user-management/auth/registration']],
				['label'=>'Change own password', 'url'=>['/user-management/auth/change-own-password']],
				['label'=>'Password recovery', 'url'=>['/user-management/auth/password-recovery']],
				['label'=>'E-mail confirmation', 'url'=>['/user-management/auth/confirm-email']],
			],
		],
	],
]);
?>

```

First steps
---

From the menu above at first you'll se only 2 element: "Login" and "Logout" because you have no permission to visit other urls
and to render menu we using **GhostMenu::widget()**. It's render only element that active user can visit.

Also same functionality has **GhostNav::widget()** and **GhostHtml:a()**

1) Login as superadmin/superadmin

2) Go to "Permissions" and play there

3) Go to "Roles" and play there

4) Go to "User" and play there

5) Relax


Usage
---

You controllers may have two properties that will make whole controller or selected action accessible to everyone

```php
public $freeAccess = true;

```

Or

```php
public $freeAccessActions = ['first-action', 'another-action'];

```

Here are list of the useful helpers. For detailed explanation look in the corresponding functions.

```php

User::hasRole($roles, $superAdminAllowed = true)
User::hasPermission($permission, $superAdminAllowed = true)
User::canRoute($route, $superAdminAllowed = true)

User::assignRole($userId, $roleName)
User::revokeRole($userId, $roleName)

User::getCurrentUser($fromSingleton = true)

```

Role, Permission and Route all have following methods

```php

Role::create($name, $description = null, $groupCode = null, $ruleName = null, $data = null)
Role::addChildren($parentName, $childrenNames, $throwException = false)
Role::removeChildren($parentName, $childrenNames)

```


Events
------

Events can be handled via config file like following

```php

'modules'=>[
	'user-management' => [
		'class' => 'webvimark\modules\UserManagement\UserManagementModule',
		'on afterRegistration' => function(UserAuthEvent $event) {
			// Here you can do your own stuff like assign roles, send emails and so on
		},
	],
],

```

List of supported events can be found in *UserAuthEvent* class

FAQ
---

**Question**: I want users to register and login with they e-mails! Mmmmm... And they should confirm it too!

**Answer**: See configuration properties *$useEmailAsLogin* and *$emailConfirmationRequired*

**Question**: I want to have profile for user with avatar, birthday and stuff. What should I do ?

**Answer**: Profiles are to project-specific, so you'll have to implement them yourself (but you can find example here - https://github.com/webvimark/user-management/wiki/Profile-and-custom-registration). Here is how to do it without modifying this module

1) Create table and model for profile, that have user_id (connect with "user" table)

2) Check AuthController::actionRegistration() how it works (*you can skip this part*)

3) Define your layout for registration. Check example in *AuthHelper::layoutHandler()*. Now use theming to change registraion.php file

4) Define your own UserManagementModule::$registrationFormClass. In this class you can do whatever you want like validating custom forms and saving profiles

5) Create your controller where user can view profiles


