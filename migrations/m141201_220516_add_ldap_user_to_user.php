<?php

use yii\db\Migration;

class m141201_220516_add_ldap_user_to_user extends Migration
{
	public function safeUp()
	{
		$this->addColumn(Yii::$app->getModule('user-management')->user_table, 'ldap_user', 'tinyint(1) not null default 0');
		Yii::$app->cache->flush();

	}

	public function safeDown()
	{
		$this->dropColumn(Yii::$app->getModule('user-management')->user_table, 'ldap_user');
		Yii::$app->cache->flush();
	}
}
