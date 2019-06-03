<?php
	namespace App\Firewall\Core;

	interface Api_Interface
	{
		public function check();
		public function isValid($returnInvalidAttributes = false);

		public function toArray();
		public function toObject();
		
		public function __isset($name);
		public function __get($name);
		public function __toString();

		public function sleep();

		public function wakeup(array $datas);
	}