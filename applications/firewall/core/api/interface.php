<?php
	namespace App\Firewall\Core;

	interface Api_Interface
	{
		public function isValid($returnInvalidAttributes = false);

		public function sleep();

		public function wakeup(array $datas);
	}