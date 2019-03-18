<?php
	namespace App\Firewall\Core;

	use ArrayObject;

	interface Api_Rule_Interface
	{
		public function isValid($returnInvalidAttributes = false);

		public function sleep();

		public function wakeup(array $datas, ArrayObject $objects = null);
	}