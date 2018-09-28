<?php
	require_once(__DIR__ . '/main.php');

	abstract class FIREWALL_Abstract extends FIREWALL_Main
	{
		protected $_CONFIG;
		protected $_Firewall_Site;

		protected $_name = null;

		protected $_objects = array(
			'Firewall_Api_Host' => array(),
			'Firewall_Api_Subnet' => array(),
			'Firewall_Api_Network' => array(),
			'Firewall_Api_Rule' => array()
		);


		public function __construct(Firewall_Site $Firewall_Site)
		{
			$this->_CONFIG = CONFIG::getInstance();
			$this->_Firewall_Site = $Firewall_Site;

			$this->name($Firewall_Site->name);
		}

		public function name($name)
		{
			if(Tools::is('string&&!empty', $name) || Tools::is('int&&>=0', $name)) {
				$this->_name = (string) $name;
				return true;
			}

			return false;
		}

		public function addObject($object)
		{
			if($object instanceof Firewall_Api_Host) {
				$this->addHost($object);
			}
			elseif($object instanceof Firewall_Api_Subnet) {
				$this->addSubnet($object);
			}
			elseif($object instanceof Firewall_Api_Network) {
				$this->addNetwork($object);
			}
			elseif($object instanceof Firewall_Api_Rule) {
				$this->addRule($object);
			}
			else {
				$class = (is_object($object)) ? (get_class($object)) : ('');
				throw new Exception("Object type '".gettype($object)."'@'".$class."' is not allowed", E_USER_ERROR);
			}

			return $this;
		}

		public function addHost(Firewall_Api_Host $host)
		{
			return $this->_addObject('Firewall_Api_Host', $host);
		}

		public function addSubnet(Firewall_Api_Subnet $subnet)
		{
			return $this->_addObject('Firewall_Api_Subnet', $subnet);
		}

		public function addNetwork(Firewall_Api_Network $network)
		{
			return $this->_addObject('Firewall_Api_Network', $network);
		}

		public function addRule(Firewall_Api_Rule $rule)
		{
			return $this->_addObject('Firewall_Api_Rule', $rule);
		}

		protected function _addObject($class, $object)
		{
			$this->_objects[$class][] = $object;
			return $this;
		}

		public function addHosts(array $hosts)
		{
			return $this->_addObjects('Firewall_Api_Host', $hosts);
		}

		public function addSubnets(array $subnets)
		{
			return $this->_addObjects('Firewall_Api_Subnet', $subnets);
		}

		public function addNetworks(array $networks)
		{
			return $this->_addObjects('Firewall_Api_Network', $networks);
		}

		public function addRules(array $rules)
		{
			return $this->_addObjects('Firewall_Api_Rule', $rules);
		}

		protected function _addObjects($class, array $objects)
		{
			foreach($objects as $object)
			{
				if($object instanceof $class) {
					$this->_objects[$class][] = $object;
				}
			}
			return $this;
		}

		public function clearHosts()
		{
			return $this->_clearObjects('Firewall_Api_Host');
		}

		public function clearSubnets()
		{
			return $this->_clearObjects('Firewall_Api_Subnet');
		}

		public function clearNetworks()
		{
			return $this->_clearObjects('Firewall_Api_Network');
		}

		public function clearRules()
		{
			return $this->_clearObjects('Firewall_Api_Rule');
		}

		protected function _clearObjects($class)
		{
			$this->_objects[$class] = array();
			return $this;
		}

		public function __get($name)
		{
			switch($name)
			{
				case 'site': {
					return $this->_Firewall_Site;
				}
				case 'name':
				case 'label': {
					return $this->_name;
				}
				case 'host':
				case 'hosts': {
					return $this->_objects['Firewall_Api_Host'];
				}
				case 'subnet':
				case 'subnets': {
					return $this->_objects['Firewall_Api_Subnet'];
				}
				case 'network':
				case 'networks': {
					return $this->_objects['Firewall_Api_Network'];
				}
				case 'rule':
				case 'rules': {
					return $this->_objects['Firewall_Api_Rule'];
				}
				case 'object':
				case 'objects': {
					return $this->_objects;
				}
				default: {
					throw new Exception("Attribute name '".$name."' does not exist", E_USER_ERROR);
				}
			}
		}
	}