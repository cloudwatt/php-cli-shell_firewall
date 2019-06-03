<?php
	namespace App\Firewall;

	interface Shell_Program_Firewall_Config_Extension_Interface 
	{
		/**
		  * @param string $filename File to load
		  * @param string $prefix Rule name prefix
		  * @param string $suffix Rule name suffix
		  * @return bool|int Number of rules loaded
		  * @throw App\Firewall\Exception|Core\Exception\Message
		  */
		public function load($filename, $prefix = null, $suffix = null);

		/**
		  * @param string $filename File target
		  * @param array $configs Configurations to save
		  * @return bool
		  * @throw App\Firewall\Exception|Core\Exception\Message
		  */
		public function save($filename, array $configs);

		/**
		  * @param string $filename File to import
		  * @param string $prefix Rule name prefix
		  * @param string $suffix Rule name suffix
		  * @return bool|int Number of rules imported
		  * @throw App\Firewall\Exception|Core\Exception\Message
		  */
		public function import($filename, $prefix = null, $suffix = null);

		/**
		  * @param string $filename File target
		  * @param array $configs Configurations to export
		  * @return bool
		  * @throw App\Firewall\Exception|Core\Exception\Message
		  */
		public function export($filename, array $configs);
	}