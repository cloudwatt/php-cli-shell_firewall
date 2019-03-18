<?php
	namespace App\Firewall;

	use ArrayObject;

	use Core as C;

	use Cli as Cli;

	abstract class Shell_Program_Firewall_Config_Helper_Abstract
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
		  * @var Core\Config
		  */
		protected $_CONFIG;

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Config
		  */
		protected $_ORCHESTRATOR;

		/**
		  * @var ArrayObject
		  */
		protected $_objects;


		public function __construct(Cli\Shell\Main $SHELL, Shell_Program_Firewall_Config $ORCHESTRATOR, ArrayObject $objects)
		{
			$this->_SHELL = $SHELL;
			$this->_TERMINAL = $SHELL->terminal;
			$this->_CONFIG = $SHELL->config;
			$this->_ORCHESTRATOR = $ORCHESTRATOR;

			$this->_objects = $objects;
		}
	}