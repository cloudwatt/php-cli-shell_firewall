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

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Object_Site
		  */
		protected $_siteFwProgram = null;

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Object_Address
		  */
		protected $_addressFwProgram = null;

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Object_Rule
		  */
		protected $_ruleFwProgram = null;


		public function __construct(Cli\Shell\Main $SHELL, ArrayObject $objects,
			Shell_Program_Firewall_Object_Site $siteFwProgram, Shell_Program_Firewall_Object_Address $addressFwProgram, Shell_Program_Firewall_Object_Rule $ruleFwProgram)
		{
			$this->_SHELL = $SHELL;
			$this->_TERMINAL = $SHELL->terminal;

			$this->_objects = $objects;

			$this->_siteFwProgram = $siteFwProgram;
			$this->_addressFwProgram = $addressFwProgram;
			$this->_ruleFwProgram = $ruleFwProgram;
		}
	}