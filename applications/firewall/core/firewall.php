<?php
	namespace App\Firewall\Core;

	use Core as C;

	class Firewall
	{
		/**
		  * Firewall configuration
		  * @var Core\MyArrayObject
		  */
		protected $_config;

		/**
		  * Firewall site
		  * @var App\Firewall\Core\Site
		  */
		protected $_site;

		/**
		  * @var string
		  */
		protected $_name = null;

		/**
		  * @var array
		  */
		protected $_objects = array(
			Api_Host::OBJECT_KEY => array(),
			Api_Subnet::OBJECT_KEY => array(),
			Api_Network::OBJECT_KEY => array(),
			Api_Rule::OBJECT_KEY => array()
		);


		public function __construct(Site $site)
		{
			$CONFIG = C\Config::getInstance();
			$this->_config = $CONFIG->FIREWALL->configuration;

			$this->_site = $site;

			$this->name($site->name);
		}

		public function name($name)
		{
			if(C\Tools::is('string&&!empty', $name) || C\Tools::is('int&&>=0', $name)) {
				$this->_name = (string) $name;
				return true;
			}

			return false;
		}

		public function addObject($object)
		{
			if($object instanceof Api_Host) {
				$this->addHost($object);
			}
			elseif($object instanceof Api_Subnet) {
				$this->addSubnet($object);
			}
			elseif($object instanceof Api_Network) {
				$this->addNetwork($object);
			}
			elseif($object instanceof Api_Rule) {
				$this->addRule($object);
			}
			else {
				$class = (is_object($object)) ? (get_class($object)) : ('');
				throw new Exception("Object type '".gettype($object)."'@'".$class."' is not allowed", E_USER_ERROR);
			}

			return $this;
		}

		public function addHost(Api_Host $host)
		{
			return $this->_addObject($host);
		}

		public function addSubnet(Api_Subnet $subnet)
		{
			return $this->_addObject($subnet);
		}

		public function addNetwork(Api_Network $network)
		{
			return $this->_addObject($network);
		}

		public function addRule(Api_Rule $rule)
		{
			return $this->_addObject($rule);
		}

		protected function _addObject($object)
		{
			$this->_objects[$object::OBJECT_KEY][] = $object;
			return $this;
		}

		public function addHosts(array $hosts)
		{
			return $this->_addObjects('Api_Host', $hosts);
		}

		public function addSubnets(array $subnets)
		{
			return $this->_addObjects('Api_Subnet', $subnets);
		}

		public function addNetworks(array $networks)
		{
			return $this->_addObjects('Api_Network', $networks);
		}

		public function addRules(array $rules)
		{
			return $this->_addObjects('Api_Rule', $rules);
		}

		protected function _addObjects($class, array $objects)
		{
			$class = __NAMESPACE__ .'\\'.$class;
			$key = $class::OBJECT_KEY;

			foreach($objects as $object)
			{
				if($object instanceof $class) {
					$this->_objects[$key][] = $object;
				}
			}
			return $this;
		}

		public function clearHosts()
		{
			return $this->_clearObjects('Api_Host');
		}

		public function clearSubnets()
		{
			return $this->_clearObjects('Api_Subnet');
		}

		public function clearNetworks()
		{
			return $this->_clearObjects('Api_Network');
		}

		public function clearRules()
		{
			return $this->_clearObjects('Api_Rule');
		}

		protected function _clearObjects($class)
		{
			$class = __NAMESPACE__ .'\\'.$class;
			$this->_objects[$class::OBJECT_KEY] = array();
			return $this;
		}

		public function __get($name)
		{
			switch($name)
			{
				case 'config': {
					return $this->_config;
				}
				case 'site': {
					return $this->_site;
				}
				case 'name':
				case 'label': {
					return $this->_name;
				}
				case 'host':
				case 'hosts': {
					return $this->_objects[Api_Host::OBJECT_KEY];
				}
				case 'subnet':
				case 'subnets': {
					return $this->_objects[Api_Subnet::OBJECT_KEY];
				}
				case 'network':
				case 'networks': {
					return $this->_objects[Api_Network::OBJECT_KEY];
				}
				case 'rule':
				case 'rules': {
					return $this->_objects[Api_Rule::OBJECT_KEY];
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