<?php
	namespace App\Firewall;

	use ArrayObject;

	use Cli as Cli;

	use App\Firewall\Core;

	class Shell_Program_Firewall_Object_Site extends Shell_Program_Firewall_Object_Abstract
	{
		const OBJECT_IDS = array(
			Core\Api_Site::OBJECT_TYPE
		);

		const OBJECT_KEYS = array(
			Core\Api_Site::OBJECT_TYPE => Core\Api_Site::OBJECT_KEY
		);

		const OBJECT_CLASSES = array(
			Core\Api_Site::OBJECT_TYPE => 'App\Firewall\Core\Api_Site'
		);

		const ALL_SITES = 'all';

		/**
		  * @var App\Firewall\Core\Sites
		  */
		protected $_fwSites;


		public function __construct(Cli\Shell\Main $SHELL, ArrayObject $objects, Core\Sites $fwSites)
		{
			parent::__construct($SHELL, $objects);

			$this->_fwSites = $fwSites;
		}

		protected function _getSite($type, $name)
		{
			return $this->_getObject($type, $name);
		}

		public function locate($type, $search, $strict = false)
		{
			return false;
		}

		public function create($type, array $args)
		{
			if($this->_typeIsAllowed($type))
			{
				if(isset($args[0]))
				{
					$name = $args[0];
					$availableSites = $this->_fwSites->getSiteKeys();

					if(mb_strtolower($name) !== self::ALL_SITES)
					{
						if(in_array($name, $availableSites, true)) {
							$sites = array($name);
						}
					}
					else {
						$sites = $availableSites;
					}

					if(isset($sites))
					{
						$status = false;

						$class = $this->_typeToClass($type);
						$currentSites = $this->_objects[$class::OBJECT_KEY];
						$missingSites = array_diff($sites, array_keys($currentSites));

						if(count($missingSites) > 0)
						{
							foreach($missingSites as $site)
							{
								$Core_Api_Site = new $class($site);
								$status = $Core_Api_Site->isValid();

								if($status) {
									$this->_objects[$class::OBJECT_KEY][$site] = $Core_Api_Site;
								}
								else{
									$objectName = ucfirst($Core_Api_Site::OBJECT_NAME);
									$this->_SHELL->error($objectName." '".$site."' invalide", 'orange');
									break;
								}
							}

							if($status) {
								$this->_SHELL->print("Site(s) activé(s)", 'green');
							}
						}
						else {
							$this->_SHELL->error("Site(s) déjà activé(s)", 'orange');
						}
					}
					else {
						$this->_SHELL->error("Le site '".$name."' n'existe pas", 'orange');
					}

					return true;
				}
			}

			return false;
		}

		public function modify($type, array $args)
		{
			return false;
		}

		public function rename($type, array $args)
		{
			return false;
		}

		public function remove($type, array $args)
		{
			if(isset($args[0]))
			{
				$name = $args[0];

				if(mb_strtolower($name) === self::ALL_SITES) {
					return $this->clear($type);
				}
				else
				{
					if(($Core_Api_Site = $this->_getSite($type, $name)) !== false) {
						$this->_unregister($Core_Api_Site);
						$objectName = ucfirst($Core_Api_Site::OBJECT_NAME);
						$this->_SHELL->print($objectName." '".$name."' supprimé", 'green');
					}
					else {
						$objectName = $this->typeToName($type, true);
						$this->_SHELL->print($objectName." '".$name."' introuvable", 'orange');
					}
				}

				return true;
			}

			return false;
		}

		public function filter($type, $filter)
		{
			return false;
		}

		public function format(Core\Api_Abstract $objectApi, array $listFields)
		{
			if($objectApi instanceof Core\Api_Site)
			{
				$site = $objectApi->toObject();

				// @todo tester sans $objectApi->toObject() --> iterator reference error, a debuguer
				foreach($site['zones'] as $key => &$zones)
				{
					foreach($zones as $IPv => &$item) {
						$item = sprintf($listFields['site']['zones']['format'], $key, $IPv, implode(', ', $item));
					}

					$zones = implode(PHP_EOL, $zones);
				}

				$site['zones'] = implode(PHP_EOL, $site['zones']);
				return $site;
			}
			else {
				throw new Exception("Object API must be an instance of Core\Api_Site", E_USER_ERROR);
			}
		}
	}