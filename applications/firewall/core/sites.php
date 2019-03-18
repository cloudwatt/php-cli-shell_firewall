<?php
	namespace App\Firewall\Core;

	use Core as C;

	class Sites extends C\Items
	{
		protected static $_itemClassName = __NAMESPACE__ .'\Site';


		public function __construct(C\Config $config)
		{
			parent::__construct($config, 'FIREWALL', 'sites');
		}

		public function getSiteKeys()
		{
			return $this->keys();
		}
	}