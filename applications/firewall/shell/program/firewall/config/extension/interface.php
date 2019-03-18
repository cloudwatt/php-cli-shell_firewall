<?php
	namespace App\Firewall;

	interface Shell_Program_Firewall_Config_Extension_Interface 
	{
		public function load($filename);

		public function save($filename, array $configs);

		public function import($filename);
	}