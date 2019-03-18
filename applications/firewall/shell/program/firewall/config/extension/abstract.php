<?php
	namespace App\Firewall;

	use ArrayObject;

	use Cli as Cli;

	abstract class Shell_Program_Firewall_Config_Extension_Abstract implements Shell_Program_Firewall_Config_Extension_Interface
	{
		/**
		  * @var Cli\Terminal\Main
		  */
		protected $_TERMINAL;

		/**
		  * @var Cli\Shell\Main
		  */
		protected $_SHELL;

		/**
		  * @var ArrayObject
		  */
		protected $_objects;


		public function __construct(Cli\Shell\Main $SHELL, ArrayObject $objects)
		{
			$this->_SHELL = $SHELL;
			$this->_TERMINAL = $SHELL->terminal;

			$this->_objects = $objects;
		}
	}