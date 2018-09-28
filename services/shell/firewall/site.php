<?php
	class Service_Shell_Firewall_Site
	{
		protected $_MAIN;
		protected $_Firewall_Sites;

		protected $_objects;


		public function __construct(Service_Abstract $MAIN, Firewall_Sites $Firewall_Sites, ArrayObject $objects)
		{
			$this->_MAIN = $MAIN;
			$this->_Firewall_Sites = $Firewall_Sites;

			$this->_objects = $objects;
		}

		public function create($class, array $args)
		{
			if(isset($args[0]))
			{
				$site = $args[0];
				$availableSites = $this->_Firewall_Sites->getSiteKeys();

				if(mb_strtolower($site) !== 'all')
				{
					if(in_array($site, $availableSites, true)) {
						$sites = array($site);
					}
				}
				else {
					$sites = $availableSites;
				}

				if(isset($sites))
				{
					$status = false;

					$_sites = array_keys($this->_objects[$class]);
					$siteToCreate = array_diff($sites, $_sites);

					foreach($siteToCreate as $site)
					{
						$objectApi = new $class($site);
						$status = $objectApi->isValid();

						if($status) {
							$this->_objects[$class][$site] = $objectApi;
						}
						else{
							$name = ucfirst($objectApi::OBJECT_NAME);
							$this->_MAIN->error($name." '".$site."' invalide", 'orange');
							break;
						}
					}

					if($status) {
						$this->_MAIN->print("Site(s) créé(s)", 'green');
					}
				}

				return true;
			}

			return false;
		}

		public function remove($class, array $args)
		{
			if(isset($args[0]))
			{
				$site = $args[0];
				$objectName = ucfirst($class::OBJECT_NAME);

				if(mb_strtolower($site) === 'all') {
					return $this->clear($class);
				}
				elseif(array_key_exists($site, $this->_objects[$class])) {
					unset($this->_objects[$class][$site]);
					$this->_MAIN->print($objectName." '".$site."' supprimé", 'green');
				}
				else {
					$objectName = ucfirst($class::OBJECT_NAME);
					$this->_MAIN->print($objectName." '".$site."' introuvable", 'orange');
				}

				return true;
			}

			return false;
		}

		public function clear($class)
		{
			$objects =& $this->_objects[$class];	// /!\ Important
			$objects = array();

			$objectName = ucfirst($class::OBJECT_NAME);
			$this->_MAIN->print($objectName." réinitialisé", 'green');
			return true;
		}

		public function format(Firewall_Api_Site $Firewall_Api_Site, array $listFields)
		{
			$site = $Firewall_Api_Site->toObject();

			// @todo tester sans $Firewall_Api_Site->toObject() --> iterator reference error, a debuguer
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
	}