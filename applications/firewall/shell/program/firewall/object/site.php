<?php
	namespace App\Firewall;

	use ArrayObject;

	use Cli as Cli;

	use App\Firewall\Core;

	class Shell_Program_Firewall_Object_Site extends Shell_Program_Firewall_Object_Abstract
	{
		const OBJECT_NAME = 'site';

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
						$class = $this->_typeToClass($type);
						$objectName = ucfirst($class::OBJECT_NAME);

						$currentSites = $this->_objects[$class::OBJECT_KEY];
						$missingSites = array_diff($sites, array_keys($currentSites));

						if(count($missingSites) > 0)
						{
							foreach($missingSites as $site)
							{
								$Core_Api_Site = new $class($site, $site);
								$isValid = $Core_Api_Site->isValid();

								if($isValid) {
									$this->_register($Core_Api_Site);
									$this->_SHELL->error($objectName." '".$site."' activé", 'green');
								}
								else {
									$this->_SHELL->error($objectName." '".$site."' invalide", 'orange');
								}
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
					if(($Core_Api_Site = $this->getObject($type, $name)) !== false) {
						$this->_unregister($Core_Api_Site);
						$objectName = ucfirst($Core_Api_Site::OBJECT_NAME);
						$this->_SHELL->print($objectName." '".$name."' supprimé", 'green');
					}
					else {
						$objectName = $this->getName($type, true);
						$this->_SHELL->print($objectName." '".$name."' introuvable", 'orange');
					}
				}

				return true;
			}

			return false;
		}

		public function locate($type, $search, $strict = false)
		{
			return false;
		}

		public function filter($type, $filter, $strict = false)
		{
			return false;
		}

		protected function _format(Core\Api_Abstract $objectApi, array $listFields, $view, $return)
		{
			if($objectApi instanceof Core\Api_Site)
			{
				switch($return)
				{
					case self::RETURN_OBJECT:
					case self::RETURN_TABLE: {
						$site = $objectApi->toObject();
						break;
					}
					case self::RETURN_ARRAY: {
						$site = $objectApi->toArray();
						break;
					}
					default: {
						throw new Exception("Format return type '".$return."' is not valid", E_USER_ERROR);
					}
				}

				if($view === self::VIEW_EXTENSIVE)
				{
					// @todo tester sans $objectApi->toObject() --> iterator reference error, a debuguer
					foreach($site['zones'] as $key => &$zones)
					{
						foreach($zones as $IPv => &$item) {
							$item = sprintf($listFields['site']['zones']['format'], $key, $IPv, implode(', ', $item));
						}
						unset($item);

						$zones = implode(PHP_EOL, $zones);
					}
					unset($zones);

					$site['zones'] = implode(PHP_EOL, $site['zones']);
				}
				else {
					unset($site['zones']);
				}

				if($return === self::RETURN_TABLE)
				{
					// @todo a coder
					//return C\Tools::formatShellTable(array($table), false, false, '/');
					return $site;
				}
				else {
					return $site;
				}
			}
			else {
				throw new Exception("Object API must be an instance of Core\Api_Site", E_USER_ERROR);
			}
		}
	}