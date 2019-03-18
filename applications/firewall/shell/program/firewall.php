<?php
	namespace App\Firewall;

	use ArrayObject;

	use Core as C;
	use Core\Exception as E;

	use Cli as Cli;

	use Addon\Ipam;

	use App\Firewall\Core;

	class Shell_Program_Firewall extends Cli\Shell\Program\Program
	{
		const SEARCH_FROM_CURRENT_CONTEXT = false;
		const SHELL_AC__SRC_DST__MIN_SEARCH_LEN = 3;

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
				'format' => "%s\t\t\t\t\t\t\t\t%s\t\t\t%s"
			),
			'subnet' => array(
				'fields' => array('name', 'subnetV4', 'subnetV6'),
				'format' => "%s\t\t\t\t\t\t\t\t%s\t\t\t%s"
			),
			'network' => array(
				'fields' => array('name', 'networkV4', 'networkV6'),
				'format' => "%s\t\t\t\t\t\t\t\t%s\t\t\t%s"
			),
			'rule' => array(
				'fields' => array('id', 'category', 'fullmesh', 'state', 'action', 'description', 'date'),
				'format' => "[%d]\t{%s}\t\tFullmesh: %s\t\tStatus: %s\t\tAction: %s\t\t(%s)\t\t@%s",
				'sources' => array(
					'fields' => array('source'),
					'format' => "%s [%s] {%s}"
				),
				'destinations' => array(
					'fields' => array('destination'),
					'format' => "%s [%s] {%s}"
				),
				'protocols' => array(
					'fields' => array('protocol'),
					'format' => "%s"
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
				'date' => 'Date: %s',
				'category' => 'Type: %s',
				'fullmesh' => 'Fullmesh: %s',
				'description' => 'Description: %s',
				'state' => 'Status: %s',
				'action' => 'Action: %s',
				'acl' => PHP_EOL.'%s',
			)
		);

		/**
		  * @var App\Firewall\Core\Sites
		  */
		protected $_fwSites = null;

		/**
		  * @var array
		  */
		protected $_fwPrograms = array();

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Config
		  */
		protected $_configFwProgram;

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Object_Site
		  */
		protected $_siteFwProgram;

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Object_Address
		  */
		protected $_addressFwProgram;

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Object_Rule
		  */
		protected $_ruleFwProgram;

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Ipam
		  */
		protected $_ipamFwProgram;

		/**
		  * @var array
		  */
		protected $_sites = array();

		/**
		  * @var array
		  */
		protected $_hosts = array();

		/**
		  * @var array
		  */
		protected $_subnets = array();

		/**
		  * @var array
		  */
		protected $_networks = array();

		/**
		  * @var array
		  */
		protected $_rules = array();

		/**
		  * @var ArrayObject
		  */
		protected $_objects = null;

		/**
		  * @var array
		  */
		protected $_firewalls = array();


		public function __construct(Cli\Shell\Main $SHELL)
		{
			parent::__construct($SHELL);

			$this->_fwSites = new Core\Sites($this->_CONFIG);

			$this->_objects = new ArrayObject(array(
				Core\Api_Site::OBJECT_KEY => &$this->_sites,
				Core\Api_Host::OBJECT_KEY => &$this->_hosts,
				Core\Api_Subnet::OBJECT_KEY => &$this->_subnets,
				Core\Api_Network::OBJECT_KEY => &$this->_networks,
				Core\Api_Rule::OBJECT_KEY => &$this->_rules,
			), ArrayObject::ARRAY_AS_PROPS);

			$this->_ipamFwProgram = new Shell_Program_Firewall_Ipam();
			$this->_ruleFwProgram = new Shell_Program_Firewall_Object_Rule($SHELL, $this->_objects);
			$this->_addressFwProgram = new Shell_Program_Firewall_Object_Address($SHELL, $this->_objects);
			$this->_configFwProgram = new Shell_Program_Firewall_Config($SHELL, $this->_objects);
			$this->_siteFwProgram = new Shell_Program_Firewall_Object_Site($SHELL, $this->_objects, $this->_fwSites);

			$this->_fwPrograms = array(
				Core\Api_Site::OBJECT_TYPE => $this->_siteFwProgram,
				Core\Api_Host::OBJECT_TYPE => $this->_addressFwProgram,
				Core\Api_Subnet::OBJECT_TYPE => $this->_addressFwProgram,
				Core\Api_Network::OBJECT_TYPE => $this->_addressFwProgram,
				Core\Api_Rule::OBJECT_TYPE => $this->_ruleFwProgram,
			);
		}

		// FIREWALL
		// --------------------------------------------------
		public function syncFirewall(Core\Firewall $firewall)
		{
			$firewall->clearHosts()->addHosts($this->_hosts);
			$firewall->clearSubnets()->addSubnets($this->_subnets);
			$firewall->clearNetworks()->addNetworks($this->_networks);
			$firewall->clearRules()->addRules($this->_rules);
			return true;
		}

		public function syncFirewalls()
		{
			foreach($this->_sites as $siteApi) {
				$Core_Site = $this->_fwSites->{$siteApi->name};
				$firewall = new Core\Firewall($Core_Site);
				$this->_firewalls[$siteApi->name] = $firewall;
				$this->syncFirewall($firewall);
			}

			return true;
		}
		// --------------------------------------------------

		// OBJECT > CREATE
		// --------------------------------------------------
		public function createSite(array $args)
		{
			$status = $this->_siteFwProgram->create(Core\Api_Site::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function createHost(array $args)
		{
			$status = $this->_addressFwProgram->create(Core\Api_Host::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function createSubnet(array $args)
		{
			$status = $this->_addressFwProgram->create(Core\Api_Subnet::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function createNetwork(array $args)
		{
			$status = $this->_addressFwProgram->create(Core\Api_Network::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function createRule(array $args)
		{
			$status = $this->_ruleFwProgram->create(Core\Api_Rule::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function cloneRule(array $args)
		{
			$status = $this->_ruleFwProgram->clone(Core\Api_Rule::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}
		// --------------------------------------------------

		// OBJECT > MODIFY
		// --------------------------------------------------
		public function modifyHost(array $args)
		{
			$status = $this->_addressFwProgram->modify(Core\Api_Host::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function modifySubnet(array $args)
		{
			$status = $this->_addressFwProgram->modify(Core\Api_Subnet::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function modifyNetwork(array $args)
		{
			$status = $this->_addressFwProgram->modify(Core\Api_Network::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function modifyRule(array $args)
		{
			$status = $this->_ruleFwProgram->modify(Core\Api_Rule::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}
		// --------------------------------------------------

		// OBJECT > REFRESH
		// --------------------------------------------------
		public function refreshHost(array $args)
		{
			$status = $this->_addressFwProgram->refresh(Core\Api_Host::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function refreshSubnet(array $args)
		{
			$status = $this->_addressFwProgram->refresh(Core\Api_Subnet::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function refreshNetwork(array $args)
		{
			$status = $this->_addressFwProgram->refresh(Core\Api_Network::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function refreshHosts()
		{
			$status = $this->_addressFwProgram->refreshAll(Core\Api_Host::OBJECT_TYPE);
			return $this->_setHasChanges($status);
		}

		public function refreshSubnets()
		{
			$status = $this->_addressFwProgram->refreshAll(Core\Api_Subnet::OBJECT_TYPE);
			return $this->_setHasChanges($status);
		}

		public function refreshNetworks()
		{
			$status = $this->_addressFwProgram->refreshAll(Core\Api_Network::OBJECT_TYPE);
			return $this->_setHasChanges($status);
		}
		// --------------------------------------------------

		// OBJECT > REPLACE
		// --------------------------------------------------
		public function replace(array $args)
		{
			if(count($args) === 4) {
				list($badType, $badName, $newType, $newName) = $args;
				$status = $this->_ruleFwProgram->replace(Core\Api_Rule::OBJECT_TYPE, $badType, $badName, $newType, $newName);
				return $this->_setHasChanges($status);
			}
			else {
				return false;
			}
		}
		// --------------------------------------------------

		// OBJECT > RENAME
		// --------------------------------------------------
		public function renameHost(array $args)
		{
			$status = $this->_addressFwProgram->rename(Core\Api_Host::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function renameSubnet(array $args)
		{
			$status = $this->_addressFwProgram->rename(Core\Api_Subnet::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function renameNetwork(array $args)
		{
			$status = $this->_addressFwProgram->rename(Core\Api_Network::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function renameRule(array $args)
		{
			$status = $this->_ruleFwProgram->rename(Core\Api_Rule::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}
		// --------------------------------------------------

		// OBJECT > REMOVE
		// --------------------------------------------------
		public function removeSite(array $args)
		{
			$status = $this->_siteFwProgram->remove(Core\Api_Site::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function removeHost(array $args)
		{
			$status = $this->_addressFwProgram->remove(Core\Api_Host::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function removeSubnet(array $args)
		{
			$status = $this->_addressFwProgram->remove(Core\Api_Subnet::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function removeNetwork(array $args)
		{
			$status = $this->_addressFwProgram->remove(Core\Api_Network::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}

		public function removeRule(array $args)
		{
			$status = $this->_ruleFwProgram->remove(Core\Api_Rule::OBJECT_TYPE, $args);
			return $this->_setHasChanges($status);
		}
		// --------------------------------------------------

		// OBJECT > CLEAR
		// --------------------------------------------------
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
			$status = $this->_siteFwProgram->clear(Core\Api_Site::OBJECT_TYPE);
			return $this->_setHasChanges($status);
		}

		public function clearHosts()
		{
			$status = $this->_addressFwProgram->clear(Core\Api_Host::OBJECT_TYPE);
			return $this->_setHasChanges($status);
		}

		public function clearSubnets()
		{
			$status = $this->_addressFwProgram->clear(Core\Api_Subnet::OBJECT_TYPE);
			return $this->_setHasChanges($status);
		}

		public function clearNetworks()
		{
			$status = $this->_addressFwProgram->clear(Core\Api_Network::OBJECT_TYPE);
			return $this->_setHasChanges($status);
		}

		public function clearRules()
		{
			$status = $this->_ruleFwProgram->clear(Core\Api_Rule::OBJECT_TYPE);
			return $this->_setHasChanges($status);
		}
		// --------------------------------------------------

		// OBJECT > SHOW
		// --------------------------------------------------
		//@todo rename showAll() like clearAll
		public function showConfig()
		{
			if($this->_ruleFwProgram->isEditingRule()) {
				$editingRuleName = $this->_ruleFwProgram->getEditingRuleName();
				$this->showRule(array($editingRuleName));
			}
			else {
				$this->printObjectsList();
			}

			return true;
		}

		public function showSite(array $args)
		{
			return $this->_showObject(Core\Api_Site::OBJECT_TYPE, $args);
		}

		public function showHost(array $args)
		{
			return $this->_showObject(Core\Api_Host::OBJECT_TYPE, $args);
		}

		public function showSubnet(array $args)
		{
			return $this->_showObject(Core\Api_Subnet::OBJECT_TYPE, $args);
		}

		public function showNetwork(array $args)
		{
			return $this->_showObject(Core\Api_Network::OBJECT_TYPE, $args);
		}

		public function showRule(array $args)
		{
			return $this->_showObject(Core\Api_Rule::OBJECT_TYPE, $args);
		}

		protected function _showObject($type, array $args)
		{
			if(isset($args[0]))
			{
				$name = $args[0];

				if(array_key_exists($type, Shell_Program_Firewall_Object::OBJECT_CLASSES)) {
					$class = Shell_Program_Firewall_Object::OBJECT_CLASSES[$type];
				}
				else {
					throw new Exception("Unknown object type '".$type."'", E_USER_ERROR);
				}

				$objects = $this->_getObjectInfos($type, $name);

				if(count($objects) > 0) {
					$this->_printInformations($type, $objects);
				}
				else {
					$objectName = ucfirst($class::OBJECT_NAME);
					$this->_SHELL->error($objectName." '".$name."' introuvable", 'orange');
				}

				return true;
			}

			return false;
		}

		public function showSites()
		{
			return $this->_showObjectsInfos(Core\Api_Site::OBJECT_TYPE);
		}

		public function showHosts(array $args)
		{
			return $this->_showObjectsInfos(Core\Api_Host::OBJECT_TYPE, $args);
		}

		public function showSubnets(array $args)
		{
			return $this->_showObjectsInfos(Core\Api_Subnet::OBJECT_TYPE, $args);
		}

		public function showNetworks(array $args)
		{
			return $this->_showObjectsInfos(Core\Api_Network::OBJECT_TYPE, $args);
		}

		public function showRules(array $args)
		{
			return $this->_showObjectsInfos(Core\Api_Rule::OBJECT_TYPE, $args);
		}

		protected function _showObjectsInfos($type, array $args = null)
		{
			if(array_key_exists($type, Shell_Program_Firewall_Object::OBJECT_CLASSES)) {
				$class = Shell_Program_Firewall_Object::OBJECT_CLASSES[$type];
			}
			else {
				throw new Exception("Unknown object type '".$type."'", E_USER_ERROR);
			}

			if(isset($args[0])) {
				$infos = $this->_getObjectInfos($type, $args[0]);
			}
			else
			{
				$infos = array();
				$objects = $this->_objects[$class::OBJECT_KEY];

				switch($type)
				{
					case Core\Api_Site::OBJECT_TYPE:
					{
						foreach($objects as $site) {
							$infos[] = $this->_siteFwProgram->format($site, $this->_LIST_FIELDS);
						}
						break;
					}
					case Core\Api_Rule::OBJECT_TYPE:
					{
						foreach($objects as $rule) {
							$infos[] = $this->_ruleFwProgram->format($rule, $this->_LIST_FIELDS);
						}
						break;
					}
					default: {
						$infos = $objects;
					}
				}
			}

			if(count($infos) === 0) {
				$this->_SHELL->error("Aucun ".$class::OBJECT_NAME." trouvé", 'orange');
			}

			$this->_printObjectsList(array($type => $infos));
			return true;
		}
		// --------------------------------------------------

		// OBJECT > LOCATE
		// --------------------------------------------------
		public function locateHost(array $args)
		{
			return $this->_locate(Core\Api_Host::OBJECT_TYPE, $args);
		}

		public function locateSubnet(array $args)
		{
			return $this->_locate(Core\Api_Subnet::OBJECT_TYPE, $args);
		}

		public function locateNetwork(array $args)
		{
			return $this->_locate(Core\Api_Network::OBJECT_TYPE, $args);
		}

		public function locateRule(array $args)
		{
			return $this->_locate(Core\Api_Rule::OBJECT_TYPE, $args);
		}

		protected function _locate($type, array $args)
		{
			if(count($args) >= 1)
			{
				$strict = (isset($args[1]) && $args[1] === 'exact');

				$infos = array();

				if($type === Core\Api_Rule::OBJECT_TYPE) {
					$result = $this->_ruleFwProgram->locate($type, $args[0], $strict);
				}
				else {
					$result = $this->_addressFwProgram->locate($type, $args[0], $strict);
				}

				if(is_array($result) && count($result) > 0)
				{
					foreach($result as $rule) {
						$infos[] = $this->_ruleFwProgram->format($rule, $this->_LIST_FIELDS);
					}

					$this->_printObjectsList(array(Core\Api_Rule::OBJECT_TYPE => $infos));
					return true;
				}
				else {
					return $result;
				}
			}
			else {
				return false;
			}
		}
		// --------------------------------------------------

		// OBJECT > RULE
		// --------------------------------------------------
		public function rule_category(array $args)
		{
			return $this->_ruleFwProgram->category($args);
		}

		public function rule_fullmesh(array $args)
		{
			return $this->_ruleFwProgram->fullmesh($args);
		}

		public function rule_state(array $args)
		{
			return $this->_ruleFwProgram->state($args);
		}

		public function rule_action(array $args)
		{
			return $this->_ruleFwProgram->action($args);
		}

		public function rule_source($type, array $args)
		{
			return $this->_ruleFwProgram->source($type, $args);
		}

		public function rule_destination($type, array $args)
		{
			return $this->_ruleFwProgram->destination($type, $args);
		}

		public function rule_protocol($type, array $args)
		{
			return $this->_ruleFwProgram->protocol($type, $args);
		}

		public function rule_description(array $args)
		{
			return $this->_ruleFwProgram->description($args);
		}

		public function rule_check()
		{
			return $this->_ruleFwProgram->check();
		}

		public function rule_reset($attribute = null, $type = null, array $args = null)
		{
			return $this->_ruleFwProgram->reset($attribute, $type, $args);
		}

		public function rule_exit()
		{
			$status = $this->_ruleFwProgram->exit();
			return $this->_setHasChanges($status);	// /!\ Important pour l'autosave
		}
		// --------------------------------------------------

		// OBJECT > SEARCH
		// --------------------------------------------------
		public function printSearchObjects(array $args, $localSearch = true, $ipamSearch = true, $forceIpamSearch = true)
		{
			if(count($args) === 3)
			{
				$time1 = microtime(true);
				$objects = $this->_searchObjects($args[0], $args[1], $args[2], $localSearch, $ipamSearch, $forceIpamSearch);
				$time2 = microtime(true);

				if($objects !== false)
				{
					$this->_RESULTS->append($objects);
					$this->_SHELL->print('RECHERCHE ('.round($time2-$time1).'s)', 'black', 'white', 'bold');

					if(!$this->_SHELL->isOneShotCall())
					{
						if(isset($objects['hosts']))
						{
							$counter = count($objects['hosts']);
							$this->_SHELL->EOL()->print('HOSTS ('.$counter.')', 'black', 'white');

							if($counter > 0)
							{
								// /!\ Object Firewall_Api_Host ou ArrayObject
								foreach($objects['hosts'] as &$host)
								{
									$host = array(
										$host->name,
										$host->addressV4,
										$host->addressV6
									);
								}

								$table = C\Tools::formatShellTable($objects['hosts']);
								$this->_SHELL->print($table, 'grey');
							}
							else {
								$this->_SHELL->error('Aucun résultat', 'orange');
							}
						}

						if(isset($objects['subnets']))
						{
							$counter = count($objects['subnets']);
							$this->_SHELL->EOL()->print('SUBNETS ('.$counter.')', 'black', 'white');

							if($counter > 0)
							{
								// /!\ Object Firewall_Api_Subnet ou ArrayObject
								foreach($objects['subnets'] as &$subnet)
								{
									$subnet = array(
										$subnet->name,
										$subnet->subnetV4,
										$subnet->subnetV6
									);
								}

								$table = C\Tools::formatShellTable($objects['subnets']);
								$this->_SHELL->print($table, 'grey');
							}
							else {
								$this->_SHELL->error('Aucun résultat', 'orange');
							}
						}

						if(isset($objects['networks']))
						{
							$counter = count($objects['networks']);
							$this->_SHELL->EOL()->print('NETWORKS ('.$counter.')', 'black', 'white');

							if($counter > 0)
							{
								foreach($objects['networks'] as &$network)
								{
									$network = array(
										$network->name,
										$network->networkV4,
										$network->networkV6
									);
								}

								$table = C\Tools::formatShellTable($objects['networks']);
								$this->_SHELL->print($table, 'grey');
							}
							else {
								$this->_SHELL->error('Aucun résultat', 'orange');
							}
						}

						if(isset($objects['rules']))
						{
							$counter = count($objects['rules']);
							$this->_SHELL->EOL()->print('RULES ('.$counter.')', 'black', 'white');

							if($counter > 0)
							{
								foreach($objects['rules'] as &$rule)
								{
									$ruleSummary = array(
										$rule->name,
										$rule->category,
										'Fullmesh: '.$rule->fullmesh,
										'Status: '.$rule->state,
										'Action: '.$rule->action,
										$rule->description,
									);

									$ruleSummary = C\Tools::formatShellTable(array($ruleSummary), false, false, '/');
									$ruleSummary = C\Tools::e($ruleSummary, 'green', false, false, true);
									$ruelAcl = C\Tools::e($rule['acl'], 'blue', false, false, true);

									$rule = $ruleSummary.PHP_EOL.$ruelAcl;
								}

								$this->_SHELL->print(implode(PHP_EOL.PHP_EOL, $objects['rules']), 'grey');
							}
							else {
								$this->_SHELL->error('Aucun résultat', 'orange');
							}
						}

						$this->_SHELL->EOL();
					}
				}
				else {
					$this->_SHELL->error("Aucun résultat trouvé", 'orange');
				}

				return true;
			}

			return false;
		}

		protected function _searchObjects($context, $type, $search, $localSearch = true, $ipamSearch = true, $forceIpamSearch = true)
		{
			switch($type)
			{
				case Core\Api_Host::OBJECT_TYPE:
				{
					$hosts = array();

					if($localSearch) {
						$hosts = $this->_getHostInfos($search, self::SEARCH_FROM_CURRENT_CONTEXT, $context);
					}

					if($ipamSearch && ($forceIpamSearch || count($hosts) === 0)) {
						$ipamAddresses = $this->_ipamFwProgram->searchAddresses($search);
						$hosts = array_merge($hosts, $ipamAddresses);
					}

					return array('hosts' => $hosts);
					break;
				}
				case Core\Api_Subnet::OBJECT_TYPE:
				{
					$subnets = array();

					if($localSearch) {
						$subnets = $this->_getSubnetInfos($search, self::SEARCH_FROM_CURRENT_CONTEXT, $context);
					}

					if($ipamSearch && ($forceIpamSearch || count($subnets) === 0)) {
						$ipamSubnets = $this->_ipamFwProgram->searchSubnets($search);
						$subnets = array_merge($subnets, $ipamSubnets);
					}

					return array('subnets' => $subnets);
					break;
				}
				case Core\Api_Network::OBJECT_TYPE:
				{
					$networks = array();

					if($localSearch) {
						$networks = $this->_getNetworkInfos($search, self::SEARCH_FROM_CURRENT_CONTEXT, $context);
					}

					return array('networks' => $networks);
					break;
				}
				case Core\Api_Rule::OBJECT_TYPE:
				{
					$rules = array();

					if($localSearch) {
						$rules = $this->_getRuleInfos($search, self::SEARCH_FROM_CURRENT_CONTEXT, $context);
					}

					return array('rules' => $rules);
					break;
				}
				case 'all':
				{
					$hosts = $this->_searchObjects($context, 'host', $search, $localSearch, $ipamSearch, $forceIpamSearch);
					$subnets = $this->_searchObjects($context, 'subnet', $search, $localSearch, $ipamSearch, $forceIpamSearch);
					$networks = $this->_searchObjects($context, 'network', $search, $localSearch, $ipamSearch, $forceIpamSearch);
					$rules = $this->_searchObjects($context, 'rule', $search, $localSearch, $ipamSearch, $forceIpamSearch);
					return array_merge($hosts, $subnets, $networks, $rules);
					break;
				}
				default: {
					throw new Exception("Unknown object type '".$type."'", E_USER_ERROR);
				}
			}
		}

		protected function _getSiteInfos($search, $fromCurrentContext = true, $context = null, $strictKey = false, $strictMatch = false)
		{
			return $this->_getObjectInfos(Core\Api_Site::OBJECT_TYPE, $search, $strictKey, $strictMatch);
		}

		protected function _getHostInfos($search, $fromCurrentContext = true, $context = null, $strictKey = false, $strictMatch = false)
		{
			return $this->_getObjectInfos(Core\Api_Host::OBJECT_TYPE, $search, $strictKey, $strictMatch);
		}

		protected function _getSubnetInfos($search, $fromCurrentContext = true, $context = null, $strictKey = false, $strictMatch = false)
		{
			return $this->_getObjectInfos(Core\Api_Subnet::OBJECT_TYPE, $search, $strictKey, $strictMatch);
		}

		protected function _getNetworkInfos($search, $fromCurrentContext = true, $context = null, $strictKey = false, $strictMatch = false)
		{
			return $this->_getObjectInfos(Core\Api_Network::OBJECT_TYPE, $search, $strictKey, $strictMatch);
		}

		protected function _getRuleInfos($search, $fromCurrentContext = true, $context = null, $strictKey = false, $strictMatch = false)
		{
			return $this->_getObjectInfos(Core\Api_Rule::OBJECT_TYPE, $search, $strictKey, $strictMatch);
		}

		protected function _getObjectInfos($type, $search, $strictKey = false, $strictMatch = false)
		{
			$result = array();

			$Shell_Program_Firewall_Object_Abstract = $this->_fwPrograms[$type];
			$objects = $Shell_Program_Firewall_Object_Abstract->getObjects($type, $search, $strictKey, $strictMatch);

			foreach($objects as &$object) {
				$object = $Shell_Program_Firewall_Object_Abstract->format($object, $this->_LIST_FIELDS);
			}

			return $objects;
		}
		// --------------------------------------------------

		// LOCAL
		// --------------------------------------------------
		public function search($type, $search)
		{
			$args = array('.', $type, $search);
			return $this->printSearchObjects($args, true, false, false);
		}

		public function filter($filter, $type)
		{
			if($filter === 'duplicates')
			{
				switch($type)
				{
					case Core\Api_Host::OBJECT_TYPE:
					case Core\Api_Subnet::OBJECT_TYPE:
					case Core\Api_Network::OBJECT_TYPE: {
						$key = Shell_Program_Firewall_Object_Address::OBJECT_KEYS[$type];
						$results = $this->_addressFwProgram->filter($type, Shell_Program_Firewall_Object_Address::FILTER_DUPLICATES);
						break;
					}
					case Core\Api_Rule::OBJECT_TYPE: {
						$key = Shell_Program_Firewall_Object_Rule::OBJECT_KEYS[$type];
						$results = $this->_ruleFwProgram->filter($type, Shell_Program_Firewall_Object_Rule::FILTER_DUPLICATES);
						break;
					}
					default: {
						$key = false;
						$results = array();
					}
				}

				if($key !== false && count($results) > 0)
				{
					$items = array();
					$objects = $this->_objects[$key];

					foreach($results as $objectId => $result)
					{
						$item = array();

						foreach($result as $duplicateObjectId) {
							$item[] = $objects[$duplicateObjectId]->name;
						}

						$item = implode(', ', $item);
						$items[] = array($objects[$objectId]->name, $item);
					}

					$table = C\Tools::formatShellTable($items);
					$this->_SHELL->print($table, 'grey');
				}
				else {
					$this->_SHELL->print("Aucun résultat n'a été trouvé pour ce filtre '".$filter."'", 'green');
				}

				return true;
			}

			return false;
		}
		// --------------------------------------------------

		// IPAM
		// --------------------------------------------------
		public function ipamSearch($type, $search)
		{
			$args = array('.', $type, $search);
			return $this->printSearchObjects($args, false, true, true);
		}

		public function ipamImport($type, $search)
		{
			try {
				$Core_Api_Abstract = $this->_addressFwProgram->autoCreateObject($type, $search);
			}
			catch(E\Message $e) {		// Core\Exception\Message
				$this->_SHELL->throw($e);
				$Core_Api_Abstract = false;
			}
			catch(Exception $e) {		// App\Firewall\Exception
				$this->_SHELL->error("Une exception s'est produite durant l'importation des objets de type '".$type."':", 'orange');
				$this->_SHELL->error($e->getMessage(), 'orange');
				$Core_Api_Abstract = false;
			}

			if($Core_Api_Abstract instanceof Core\Api_Abstract) {
				$this->_SHELL->print("Objet '".$Core_Api_Abstract->name."' créé avec succès!", 'green');
				$this->_setHasChanges(true);
			}
			elseif($Core_Api_Abstract === null) {
				$this->_SHELL->error("Impossible de trouver l'objet '".$type."' correspondant à '".$search."'", 'orange');
			}
			else {
				$this->_SHELL->error("Impossible d'importer l'objet '".$type."' correspondant à '".$search."'", 'orange');
			}

			return true;
		}
		// --------------------------------------------------

		// CONFIG
		// --------------------------------------------------
		public function hasChanges()
		{
			return $this->_configFwProgram->hasChanges;
		}

		public function autoload()
		{
			return $this->_configFwProgram->autoload();
		}

		public function load(array $args)
		{
			return $this->_configFwProgram->load($args);
		}

		public function save(array $args)
		{
			return $this->_configFwProgram->save($args);
		}

		public function import($type, array $args)
		{
			$status = $this->syncFirewalls();

			if($status) {
				return $this->_configFwProgram->import($this->_firewalls, $type, $args);
			}
			else {
				$this->_SHELL->error("Une erreur s'est produite lors de la synchronisation des firewalls", 'orange');
				return false;
			}
		}

		public function export($type, array $args)
		{
			$status = $this->syncFirewalls();

			if($status) {
				return $this->_configFwProgram->export($this->_firewalls, $type, $args);
			}
			else {
				$this->_SHELL->error("Une erreur s'est produite lors de la synchronisation des firewalls", 'orange');
				return false;
			}
		}

		public function copy($type, array $args)
		{
			$status = $this->syncFirewalls();

			if($status) {
				return $this->_configFwProgram->copy($this->_firewalls, $type, $args);
			}
			else {
				$this->_SHELL->error("Une erreur s'est produite lors de la synchronisation des firewalls", 'orange');
				return false;
			}
		}

		protected function _setHasChanges($status)
		{
			if($status === true) {
				$this->_configFwProgram->hasChanges();
			}

			// /!\ Retourner le status! méthode magique
			return $status;
		}
		// --------------------------------------------------

		// Service_Cli_Abstract : SYSTEM METHODS
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

		protected function _getObjects($context = null)
		{
			$sites = array();

			foreach($this->_sites as $site) {
				$sites[] = $this->_siteFwProgram->format($site, $this->_LIST_FIELDS);
			}

			$rules = array();

			foreach($this->_rules as $rule) {
				$rules[] = $this->_ruleFwProgram->format($rule, $this->_LIST_FIELDS);
			}

			return array(
				'site' => $sites,
				'host' => $this->_hosts,
				'subnet' => $this->_subnets,
				'network' => $this->_networks,
				'rule' => $rules
			);
		}
		// --------------------------------------------------

		// ----------------- AutoCompletion -----------------
		/**
		  * For false search, that is bad arg, return default values or nothing
		  * For null search, that is no arg (space), return default values
		  * For string search, that is a valid arg, return the values found
		  *
		  * Options return must have key for system and value for user
		  * Key are used by AutoComplete arguments to find the true argument
		  * Value are used by AutoComplete arguments to inform user all available arguments
		  * Be carreful to always return Core\StatusValue object
		  *
		  * @param string $cmd Command
		  * @param false|null|string $search Search
		  * @return Core\StatusValue
		  */
		public function shellAutoC_srcDst($cmd, $search = null)
		{
			$Core_StatusValue = new C\StatusValue(false, array());

			if($this->_ruleFwProgram->isEditingRule() && C\Tools::is('string&&!empty', $search))
			{
				if(mb_strlen($search) < self::SHELL_AC__SRC_DST__MIN_SEARCH_LEN) {
					$this->_SHELL->error('L\'autocomplétion est disponible seulement pour les recherches de plus de '.self::SHELL_AC__SRC_DST__MIN_SEARCH_LEN.' caractères', 'orange');
				}
				else
				{
					/**
					  * /!\ Pour eviter le double PHP_EOL (celui du MSG et de la touche ENTREE)
					  * penser à désactiver le message manuellement avec un lineUP
					  */
					$this->_SHELL->displayWaitingMsg(true, false, 'Searching custom or IPAM objects');

					$cmdParts = explode(' ', $cmd);
					$object = end($cmdParts);

					$fieldToReturn = 'name';

					/**
					  * @todo
					  * $this->_ipamFwProgram->xxxx ne prends pas forcement en charge le wildcard * (oui pour un hostname, non pour une adresse IP)
					  * Du coups la recherche par adresse (IP, subnet, network) ne fonctionne pas correctement puisque ne permet qu'une recherche stricte
					  *
					  * Lorsque l'utilisateur commence à taper une IP (ou un subnet ou un network), il doit voir le nom de l'objet trouvé (c'est codé)
					  * mais cela ne fonctionne pas correctement car les tests isIPv46, isSubnetV46 ou isNetworkV46 ne fonctionne qu'avec une adresse valide
					  * donc pour un début d'adresse le champs système retourné sera le nom et non l'adresse de l'objet
					  * Le souci est comment savoir que l'utilisateur commence à rentrer une adresse et non un nom
					  *
					  * Le code fonctionne bien sans bug, c'est juste l'expérience utilisateur qui n'est pas optimale
					  */
					switch($object)
					{
						case Core\Api_Host::OBJECT_TYPE:
						{				
							if(Core\Tools::isIPv4($search)) {
								$fieldToReturn = Core\Api_Host::FIELD_ATTRv4;
							}
							elseif(Core\Tools::isIPv6($search)) {
								$fieldToReturn = Core\Api_Host::FIELD_ATTRv6;
							}

							$items = $this->_getHostInfos($search, self::SEARCH_FROM_CURRENT_CONTEXT, null, false, true);

							if(count($items) === 0)
							{
								try {
									$ipamAddresses = $this->_ipamFwProgram->getAddresses($search, false);
								}
								catch(Exception $e) {
									$this->_SHELL->error("[AC] L'erreur suivante s'est produite: ".$e->getMessage(), 'orange');
									$ipamAddresses = array();
								}

								$items = array_merge($items, $ipamAddresses);
							}
							break;
						}
						case Core\Api_Subnet::OBJECT_TYPE:
						{
							if(Core\Tools::isSubnetV4($search)) {
								$fieldToReturn = Core\Api_Subnet::FIELD_ATTRv4;
							}
							elseif(Core\Tools::isSubnetV6($search)) {
								$fieldToReturn = Core\Api_Subnet::FIELD_ATTRv6;
							}

							$items = $this->_getSubnetInfos($search, self::SEARCH_FROM_CURRENT_CONTEXT, null, false, true);

							if(count($items) === 0)
							{
								try {
									$ipamSubnets = $this->_ipamFwProgram->getSubnets($search, false);
								}
								catch(Exception $e) {
									$this->_SHELL->error("[AC] L'erreur suivante s'est produite: ".$e->getMessage(), 'orange');
									$ipamSubnets = array();
								}

								$items = array_merge($items, $ipamSubnets);
							}
							break;
						}
						case Core\Api_Network::OBJECT_TYPE:
						{
							if(Core\Tools::isNetworkV4($search, Core\Api_Network::SEPARATOR)) {
								$fieldToReturn = Core\Api_Network::FIELD_ATTRv4;
							}
							elseif(Core\Tools::isNetworkV6($search, Core\Api_Network::SEPARATOR)) {
								$fieldToReturn = Core\Api_Network::FIELD_ATTRv6;
							}

							$items = $this->_getNetworkInfos($search, self::SEARCH_FROM_CURRENT_CONTEXT, null, false, true);
							break;
						}
					}

					// Utile car la désactivation doit s'effectuer avec un lineUP, voir message plus haut
					$this->_SHELL->deleteWaitingMsg(true);

					if(isset($items))
					{
						$options = array();

						foreach($items as $item) {
							$options[$item[$fieldToReturn]] = $item['name'];
						}

						$Core_StatusValue->setStatus(true);
						$Core_StatusValue->setOptions($options);
					}
				}
			}

			return $Core_StatusValue;
		}
		// --------------------------------------------------
	}