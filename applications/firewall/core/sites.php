<?php
	namespace App\Firewall\Core;

	use Core as C;

	class Sites extends C\Items
	{
		protected static $_itemClassName = __NAMESPACE__ .'\Site';

		/**
		  * @var Core\Config
		  */
		protected $_CONFIG = null;


		public function __construct(C\Config $config)
		{
			$this->_CONFIG = $config;
			$config = $this->_CONFIG->FIREWALL->sites;

			parent::__construct($config);
		}

		public function getSiteKeys()
		{
			return $this->keys();
		}
	}