<?php
	require_once(__DIR__ . '/abstract.php');
	require_once(__DIR__ . '/firewall/config.php');
	require_once(__DIR__ . '/firewall/site.php');
	require_once(__DIR__ . '/firewall/object.php');
	require_once(__DIR__ . '/firewall/rule.php');

	class Service_Shell_Firewall extends Service_Shell_Abstract
	{
		const SEARCH_FROM_CURRENT_CONTEXT = false;

		protected $_LIST_TITLES = array(
			'site' => 'SITES',
			'host' => 'HOSTS',
			'subnet' => 'SUBNETS',
			'network' => 'NETWORKS',
			'rule' => 'RULES',
		);

		protected $_LIST_FIELDS = array(
			'site' => array(
				'fields' => array('name', 'equipment'),
				'format' => "%s\t\t\t\t\t\t%s",
				'zones' => array(
					'fields' => array('zone', 'ipv', 'filter'),
					'format' => "\t- %s\t\t%s\t\t%s"
				),
			),
			'host' => array(
				'fields' => array('name', 'addressV4', 'addressV6'),
				'format' => "%s\t\t\t\t\t\t%s\t\t\t%s"
			),
			'subnet' => array(
				'fields' => array('name', 'subnetV4', 'subnetV6'),
				'format' => "%s\t\t\t\t\t\t%s\t\t\t%s"
			),
			'network' => array(
				'fields' => array('name', 'networkV4', 'networkV6'),
				'format' => "%s\t\t\t\t\t\t%s\t\t\t%s"
			),
			'rule' => array(
				'fields' => array('id', 'category', 'fullmesh', 'action', 'description'),
				'format' => "[%d]\t{%s}\t\tFullmesh: %s\t\tAction: %s\t\t(%s)",
				'sources' => array(
					'fields' => array('source'),
					'format' => "\t- %s\t\t\t\t%s\t\t\t%s"
				),
				'destinations' => array(
					'fields' => array('destination'),
					'format' => "\t- %s\t\t\t\t%s\t\t\t%s"
				),
				'protocols' => array(
					'fields' => array('protocol'),
					'format' => "\t- %s"
				)
			)
		);

		protected $_PRINT_TITLES = array(
			'site' => 'SITES',
			'host' => 'HOSTS',
			'subnet' => 'SUBNETS',
			'network' => 'NETWORKS',
			'rule' => 'RULES',
		);

		protected $_PRINT_FIELDS = array(
			'site' => array(
				'name' => 'Name: %s',
				'equipment' => 'Firewall: %s',
				'zones' => PHP_EOL.'Zones:'.PHP_EOL.'%s',
			),
			'host' => array(
				'name' => 'Name: %s',
				'addressV4' => 'Address IPv4: %s',
				'addressV6' => 'Address IPv6: %s',
			),
			'subnet' => array(
				'name' => 'Name: %s',
				'subnetV4' => 'Subnet V4: %s',
				'subnetV6' => 'Subnet V6: %s',
			),
			'network' => array(
				'name' => 'Name: %s',
				'networkV4' => 'Network V4: %s',
				'networkV6' => 'Network V6: %s',
			),
			'rule' => array(
				'id' => 'ID: %d',
				'category' => 'Type: %s',
				'fullmesh' => 'Fullmesh: %s',
				'description' => 'Description: %s',
				'action' => 'Action: %s',
				'sources' => PHP_EOL.'Sources:'.PHP_EOL.'%s',
				'destinations' => PHP_EOL.'Destinations:'.PHP_EOL.'%s',
				'protocols' => PHP_EOL.'Protocols:'.PHP_EOL.'%s'
			)
		);

		protected $_Firewall_Sites = null;

		protected $_Service_Shell_Firewall_Config;
		protected $_Service_Shell_Firewall_Site;
		protected $_Service_Shell_Firewall_Object;
		protected $_Service_Shell_Firewall_Rule;
		protected $_Service_Shell_Firewall_Ipam;

		protected $_sites = array();
		protected $_hosts = array();
		protected $_subnets = array();
		protected $_networks = array();
		protected $_rules = array();

		protected $_objects = null;
		protected $_firewalls = array();


		public function __construct(Service_Abstract $MAIN, SHELL $SHELL)
		{
			parent::__construct($MAIN, $SHELL);

			$this->_Firewall_Sites = new Firewall_Sites($this->_CONFIG);

			$this->_objects = new ArrayObject(array(
				'Firewall_Api_Site' => &$this->_sites,
				'Firewall_Api_Host' => &$this->_hosts,
				'Firewall_Api_Subnet' => &$this->_subnets,
				'Firewall_Api_Network' => &$this->_networks,
				'Firewall_Api_Rule' => &$this->_rules,
			), ArrayObject::ARRAY_AS_PROPS);

			$this->_Service_Shell_Firewall_Config = new Service_Shell_Firewall_Config($MAIN, $this->_objects);
			$this->_Service_Shell_Firewall_Site = new Service_Shell_Firewall_Site($MAIN, $this->_Firewall_Sites, $this->_objects);
			$this->_Service_Shell_Firewall_Object = new Service_Shell_Firewall_Object($MAIN, $SHELL, $this->_objects);
			$this->_Service_Shell_Firewall_Rule = new Service_Shell_Firewall_Rule($MAIN, $SHELL, $this->_objects);
			$this->_Service_Shell_Firewall_Ipam = new Service_Shell_Firewall_Ipam();
		}

		public function syncFirewall(FIREWALL $firewall)
		{
			$firewall->clearHosts()->addHosts($this->_hosts);
			$firewall->clearSubnets()->addSubnets($this->_subnets);
			$firewall->clearNetworks()->addNetworks($this->_networks);
			$firewall->clearRules()->addRules($this->_rules);
			return true;
		}

		public function syncFirewalls()
		{
			foreach($this->_sites as $site) {
				$Firewall_Site = $this->_Firewall_Sites->{$site->name};
				$firewall = new FIREWALL($Firewall_Site);
				$this->_firewalls[$site->name] = $firewall;
				$this->syncFirewall($firewall);
			}

			return true;
		}

		// --------------------------------------------------
		public function createSite(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Site->create('Firewall_Api_Site', $args);
			return $this->_setHasChanges($status);
		}

		public function createHost(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Object->create('Firewall_Api_Host', $args);
			return $this->_setHasChanges($status);
		}

		public function createSubnet(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Object->create('Firewall_Api_Subnet', $args);
			return $this->_setHasChanges($status);
		}

		public function createNetwork(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Object->create('Firewall_Api_Network', $args);
			return $this->_setHasChanges($status);
		}

		public function createRule(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Rule->create('Firewall_Api_Rule', $args);
			return $this->_setHasChanges($status);
		}

		public function modifyHost(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Object->modify('Firewall_Api_Host', $args);
			return $this->_setHasChanges($status);
		}

		public function modifySubnet(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Object->modify('Firewall_Api_Subnet', $args);
			return $this->_setHasChanges($status);
		}

		public function modifyNetwork(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Object->modify('Firewall_Api_Network', $args);
			return $this->_setHasChanges($status);
		}

		public function modifyRule(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Rule->modify('Firewall_Api_Rule', $args);
			return $this->_setHasChanges($status);
		}

		public function removeSite(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Site->remove('Firewall_Api_Site', $args);
			return $this->_setHasChanges($status);
		}

		public function removeHost(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Object->remove('Firewall_Api_Host', $args);
			return $this->_setHasChanges($status);
		}

		public function removeSubnet(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Object->remove('Firewall_Api_Subnet', $args);
			return $this->_setHasChanges($status);
		}

		public function removeNetwork(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Object->remove('Firewall_Api_Network', $args);
			return $this->_setHasChanges($status);
		}

		public function removeRule(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Rule->remove('Firewall_Api_Rule', $args);
			return $this->_setHasChanges($status);
		}

		public function clearAll()
		{
			$this->clearSites();
			$this->clearHosts();
			$this->clearSubnets();
			$this->clearNetworks();
			$this->clearRules();
			return true;
		}

		public function clearSites()
		{
			$status = $this->_Service_Shell_Firewall_Site->clear('Firewall_Api_Site');
			return $this->_setHasChanges($status);
		}

		public function clearHosts()
		{
			$status = $this->_Service_Shell_Firewall_Object->clear('Firewall_Api_Host');
			return $this->_setHasChanges($status);
		}

		public function clearSubnets()
		{
			$status = $this->_Service_Shell_Firewall_Object->clear('Firewall_Api_Subnet');
			return $this->_setHasChanges($status);
		}

		public function clearNetworks()
		{
			$status = $this->_Service_Shell_Firewall_Object->clear('Firewall_Api_Network');
			return $this->_setHasChanges($status);
		}

		public function clearRules()
		{
			$status = $this->_Service_Shell_Firewall_Rule->clear('Firewall_Api_Rule');
			return $this->_setHasChanges($status);
		}
		// --------------------------------------------------

		// --------------------------------------------------
		protected function _getObject($class, $id)
		{
			return $this->_Service_Shell_Firewall_Object->getObject($class, $id);
		}

		public function showSite(array $args)
		{
			return $this->_showObject('Firewall_Api_Site', $args);
		}

		public function showHost(array $args)
		{
			return $this->_showObject('Firewall_Api_Host', $args);
		}

		public function showSubnet(array $args)
		{
			return $this->_showObject('Firewall_Api_Subnet', $args);
		}

		public function showNetwork(array $args)
		{
			return $this->_showObject('Firewall_Api_Network', $args);
		}

		public function showRule(array $args)
		{
			return $this->_showObject('Firewall_Api_Rule', $args);
		}

		protected function _showObject($class, array $args)
		{
			if(isset($args[0]))
			{
				$id = $args[0];

				switch($class)
				{
					case 'Firewall_Api_Site':
						$objects = $this->_getSiteInfos($id);
						break;
					case 'Firewall_Api_Host':
						$objects = $this->_getHostInfos($id);
						break;
					case 'Firewall_Api_Subnet':
						$objects = $this->_getSubnetInfos($id);
						break;
					case 'Firewall_Api_Network':
						$objects = $this->_getNetworkInfos($id);
						break;
					case 'Firewall_Api_Rule':
						$objects = $this->_getRuleInfos($id);
						break;
					default:
						throw new Exception("Unknown class '".$class."'", E_USER_ERROR);
				}

				if(count($objects) > 0) {
					$this->_printInformations($class::OBJECT_TYPE, $objects);
				}
				else {
					$objectName = ucfirst($class::OBJECT_NAME);
					$this->_MAIN->error($objectName." '".$id."' introuvable", 'orange');
				}

				return true;
			}

			return false;
		}

		public function showConfig()
		{
			if($this->_Service_Shell_Firewall_Rule->isEditingRule()) {
				$editingRuleId = $this->_Service_Shell_Firewall_Rule->getEditingRuleId();
				$this->showRule(array($editingRuleId+1));
			}
			else {
				$this->printObjectsList();
			}

			return true;
		}

		protected function _getObjects($context = null)
		{
			$sites = array();

			foreach($this->_sites as $site) {
				$sites[] = $this->_Service_Shell_Firewall_Site->format($site, $this->_LIST_FIELDS);
			}

			$rules = array();

			foreach($this->_rules as $ruleId => $rule) {
				$rules[] = $this->_Service_Shell_Firewall_Rule->format($ruleId, $this->_LIST_FIELDS);
			}

			return array(
				'site' => $sites,
				'host' => $this->_hosts,
				'subnet' => $this->_subnets,
				'network' => $this->_networks,
				'rule' => $rules
			);
		}

		public function showSites()
		{
			return $this->_showObjectsInfos('Firewall_Api_Site');
		}

		public function showHosts()
		{
			return $this->_showObjectsInfos('Firewall_Api_Host');
		}

		public function showSubnets()
		{
			return $this->_showObjectsInfos('Firewall_Api_Subnet');
		}

		public function showNetworks()
		{
			return $this->_showObjectsInfos('Firewall_Api_Network');
		}

		public function showRules()
		{
			return $this->_showObjectsInfos('Firewall_Api_Rule');
		}

		protected function _showObjectsInfos($class)
		{
			$infos = array();
			$objects = $this->_objects[$class];

			switch($class)
			{
				case 'Firewall_Api_Site':
				{
					foreach($objects as $object) {
						$infos[] = $this->_Service_Shell_Firewall_Site->format($object, $this->_LIST_FIELDS);
					}
					break;
				}
				case 'Firewall_Api_Rule':
				{
					foreach($objects as $ruleId => $rule) {
						$infos[] = $this->_Service_Shell_Firewall_Rule->format($ruleId, $this->_LIST_FIELDS);
					}
					break;
				}
				default: {
					$infos = $objects;
				}
			}

			if(count($infos) === 0) {
				$this->_MAIN->error("Aucun ".$class::OBJECT_NAME." trouvé", 'orange');
			}

			$this->_printObjectsList(array($class::OBJECT_TYPE => $infos));
			return true;
		}
		// --------------------------------------------------

		// --------------------------------------------------
		public function printObjectInfos(array $args, $fromCurrentContext = true)
		{
			$cases = array(
				'site' => '_getSiteInfos',
				'host' => '_getHostInfos',
				'subnet' => '_getSubnetInfos',
				'network' => '_getNetworkInfos',
				'rule' => '_getRuleInfos'
			);

			$result = $this->_printObjectInfos($cases, $args, $fromCurrentContext);

			if($result !== false) {
				list($status, $type, $infos) = $result;
				return $status;
			}
			else {
				return false;
			}
		}

		public function printSearchObjects(array $args)
		{
			if(count($args) === 3)
			{
				$time1 = microtime(true);
				$objects = $this->_searchObjects($args[0], $args[1], $args[2]);
				$time2 = microtime(true);

				if($objects !== false)
				{
					$this->_MAIN->setLastCmdResult($objects);
					$this->_MAIN->print('RECHERCHE ('.round($time2-$time1).'s)', 'black', 'white', 'bold');

					if(!$this->_MAIN->isOneShotCall())
					{
						if(isset($objects['hosts']))
						{
							$counter = count($objects['hosts']);
							$this->_MAIN->EOL()->print('HOSTS ('.$counter.')', 'black', 'white');

							if($counter > 0)
							{
								// /!\ Object Firewall_Api_Host ou ArrayObject
								foreach($objects['hosts'] as $host)
								{
									$text1 = '['.$host->name.']';
									$text1 .= Tools::t($text1, "\t", 7, 0, 8);
									$text2 = $host->addressV4;
									$text2 .= Tools::t($text2, "\t", 4, 0, 8);
									$text3 = $host->addressV6;
									$this->_MAIN->print($text1.$text2.$text3, 'grey');
								}
							}
							else {
								$this->_MAIN->error('Aucun résultat', 'orange');
							}
						}

						if(isset($objects['subnets']))
						{
							$counter = count($objects['subnets']);
							$this->_MAIN->EOL()->print('SUBNETS ('.$counter.')', 'black', 'white');

							if($counter > 0)
							{
								// /!\ Object Firewall_Api_Subnet ou ArrayObject
								foreach($objects['subnets'] as $subnet)
								{
									$text1 = '['.$subnet->name.']';
									$text1 .= Tools::t($text1, "\t", 7, 0, 8);
									$text2 = $subnet->subnetV4;
									$text2 .= Tools::t($text2, "\t", 4, 0, 8);
									$text3 = $subnet->subnetV6;
									$this->_MAIN->print($text1.$text2.$text3, 'grey');
								}
							}
							else {
								$this->_MAIN->error('Aucun résultat', 'orange');
							}
						}

						if(isset($objects['networks']))
						{
							$counter = count($objects['networks']);
							$this->_MAIN->EOL()->print('NETWORKS ('.$counter.')', 'black', 'white');

							if($counter > 0)
							{
								foreach($objects['networks'] as $network)
								{
									$text1 = '['.$network->name.']';
									$text1 .= Tools::t($text1, "\t", 7, 0, 8);
									$text2 = $network->networkV4;
									$text2 .= Tools::t($text2, "\t", 4, 0, 8);
									$text3 = $network->networkV6;
									$this->_MAIN->print($text1.$text2.$text3, 'grey');
								}
							}
							else {
								$this->_MAIN->error('Aucun résultat', 'orange');
							}
						}

						if(isset($objects['rules']))
						{
							$counter = count($objects['rules']);
							$this->_MAIN->EOL()->print('RULES ('.$counter.')', 'black', 'white');

							if($counter > 0)
							{
								foreach($objects['rules'] as $rule)
								{
									$text1 = '['.$rule['id'].']';
									$text1 .= Tools::t($text1, "\t", 7, 0, 8);
									$text2 = '{'.$rule['category'].'}';
									$text2 .= Tools::t($text2, "\t", 4, 0, 8);
									$text3 = 'Fullmesh: '.$rule['fullmesh'].' | Action: '.$action.' ('.$rule['description'].')';
									$this->_MAIN->print($text1.$text2.$text3, 'grey');

									foreach(array('sources', 'destinations', 'protocols') as $attribute) {
										$this->_MAIN->print(ucfirst($attribute).':'.PHP_EOL.$rule[$attribute]);
									}
								}
							}
							else {
								$this->_MAIN->error('Aucun résultat', 'orange');
							}
						}

						$this->_MAIN->EOL();
					}
				}
				else {
					$this->_MAIN->error("Aucun résultat trouvé", 'orange');
				}

				return true;
			}

			return false;
		}

		protected function _searchObjects($context, $type, $search)
		{
			switch($type)
			{
				case 'host':
				{
					$hosts = $this->_getHostInfos($search, self::SEARCH_FROM_CURRENT_CONTEXT, $context);
					$ipamAddresses = $this->_Service_Shell_Firewall_Ipam->searchAddresses($search);
					return array('hosts' => array_merge($hosts, $ipamAddresses));
					break;
				}
				case 'subnet':
				{
					$subnets = $this->_getSubnetInfos($search, self::SEARCH_FROM_CURRENT_CONTEXT, $context);
					$ipamSubnets = $this->_Service_Shell_Firewall_Ipam->searchSubnets($search);
					return array('subnets' => array_merge($subnets, $ipamSubnets));
					break;
				}
				case 'network':
				{
					$networks = $this->_getNetworkInfos($search, self::SEARCH_FROM_CURRENT_CONTEXT, $context);
					return array('networks' => $networks);
					break;
				}
				case 'rule':
				{
					$rules = $this->_getRuleInfos($search, self::SEARCH_FROM_CURRENT_CONTEXT, $context);
					return array('rules' => $rules);
					break;
				}
				case 'all':
				{
					$hosts = $this->_searchObjects($context, 'host', $search);
					$subnets = $this->_searchObjects($context, 'subnet', $search);
					$networks = $this->_searchObjects($context, 'network', $search);
					$rules = $this->_searchObjects($context, 'rule', $search);
					return array_merge($hosts, $subnets, $networks, $rules);
					break;
				}
				default: {
					throw new Exception("Search item '".$type."' is unknow", E_USER_ERROR);
				}
			}
		}

		protected function _getSiteInfos($search, $fromCurrentContext = true, $context = null, $strict = false)
		{
			return $this->_getObjectInfos('Firewall_Api_Site', $search, $strict);
		}

		protected function _getHostInfos($search, $fromCurrentContext = true, $context = null, $strict = false)
		{
			return $this->_getObjectInfos('Firewall_Api_Host', $search, $strict);
		}

		protected function _getSubnetInfos($search, $fromCurrentContext = true, $context = null, $strict = false)
		{
			return $this->_getObjectInfos('Firewall_Api_Subnet', $search, $strict);
		}

		protected function _getNetworkInfos($search, $fromCurrentContext = true, $context = null, $strict = false)
		{
			return $this->_getObjectInfos('Firewall_Api_Network', $search, $strict);
		}

		// $strict for future use
		protected function _getRuleInfos($search, $fromCurrentContext = true, $context = null, $strict = false)
		{
			if(Tools::is('int&&>0', $search)) {
				return $this->_getObjectInfos('Firewall_Api_Rule', ((int) $search-1), true);
			}

			return array();
		}

		protected function _getObjectInfos($class, $search, $strict = false)
		{
			$result = array();
			$objects = $this->_objects[$class];

			foreach($objects as $id => $object)
			{
				// /!\ La recherche doit être sensible à la case !
				if($search === $id || ($strict === false && (preg_match("#^".preg_quote($search)."#", $object->name) || $object->match($search))))
				{
					switch($class)
					{
						case 'Firewall_Api_Site': {
							$object = $this->_Service_Shell_Firewall_Site->format($object, $this->_LIST_FIELDS);
							break;
						}
						case 'Firewall_Api_Rule': {
							$object = $this->_Service_Shell_Firewall_Rule->format($id, $this->_LIST_FIELDS);	// @todo passer $id --> $object
							break;
						}
						default: {
							$object = $object->toObject();
						}
					}

					if($object !== false) {
						$result[] = $object;
					}
				}
			}

			return $result;
		}
		// --------------------------------------------------

		// ---------------------- RULE ----------------------
		public function rule_fullmesh(array $args)
		{
			return $this->_Service_Shell_Firewall_Rule->fullmesh($args);
		}

		public function rule_action(array $args)
		{
			return $this->_Service_Shell_Firewall_Rule->action($args);
		}

		public function rule_source($type, array $args)
		{
			return $this->_Service_Shell_Firewall_Rule->source($type, $args);
		}

		public function rule_destination($type, array $args)
		{
			return $this->_Service_Shell_Firewall_Rule->destination($type, $args);
		}

		public function rule_protocol(array $args)
		{
			return $this->_Service_Shell_Firewall_Rule->protocol($args);
		}

		public function rule_description(array $args)
		{
			return $this->_Service_Shell_Firewall_Rule->description($args);
		}

		public function rule_check()
		{
			return $this->_Service_Shell_Firewall_Rule->check();
		}

		public function rule_reset($attribute)
		{
			return $this->_Service_Shell_Firewall_Rule->reset($attribute);
		}

		public function rule_exit()
		{
			return $this->_Service_Shell_Firewall_Rule->exit();
		}
		// --------------------------------------------------

		// --------------------- CONFIG ---------------------
		public function hasChanges()
		{
			return $this->_Service_Shell_Firewall_Config->hasChanges;
		}

		public function autoload()
		{
			$status = $this->_Service_Shell_Firewall_Config->autoload();

			if(!$status) {
				$this->clearAll();
			}

			return $status;
		}

		public function load(array $args)
		{
			$status = $this->_Service_Shell_Firewall_Config->load($args);

			if(!$status) {
				$this->clearSites();
				$this->clearRules();
			}

			return $status;
		}

		public function save(array $args)
		{
			return $this->_Service_Shell_Firewall_Config->save($args);
		}

		public function export($type, array $args)
		{
			$status = $this->syncFirewalls();

			if($status) {
				return $this->_Service_Shell_Firewall_Config->export($this->_firewalls, $type, $args);
			}
			else {
				$this->_MAIN->error("Une erreur s'est produite lors de la synchronisation des firewalls", 'orange');
				return false;
			}
		}

		protected function _setHasChanges($status)
		{
			if($status === true) {
				$this->_Service_Shell_Firewall_Config->hasChanges();
			}

			// /!\ Retourner le status! méthode magique
			return $status;
		}
		// --------------------------------------------------

		// ----------------- AutoCompletion -----------------
		// @todo recevoir en arg la cmd afin de voir si le user veut des host, subnets ou network
		// @todo si recherche locale retourne un résultat alors ne pas rechercher dans l'IPAM
		public function shellAutoC_srcDst($search)
		{
			if($this->_Service_Shell_Firewall_Rule->isEditingRule())
			{
				/**
				  * /!\ Pour eviter le double PHP_EOL (celui du MSG et de la touche ENTREE)
				  * penser à désactiver le message manuellement avec un lineUP
				  */
				$this->_MAIN->displayWaitingMsg(true, false, 'Searching in IPAM');

				// /!\ Ne pas rechercher sur ALL car il y a rules
				$hosts = $this->_searchObjects(null, 'host', $search);
				$subnets = $this->_searchObjects(null, 'subnet', $search);
				$networks = $this->_searchObjects(null, 'network', $search);

				// Utile car la désactivation doit s'effectuer avec un lineUP, voir message plus haut
				$this->_MAIN->deleteWaitingMsg(true);

				$items = array_merge($hosts['hosts'], $subnets['subnets'], $networks['networks']);

				foreach($items as &$item)
				{
					/**
					  * ['name'] est généré automatiquement
					  * Voir Firewall_Api_Abstract->toArray()
					  */
					$item = $item['name'];
				}
				unset($item);	// /!\ sécurité

				return $items;
			}
			else {
				return array();
			}
		}
		// --------------------------------------------------
	}