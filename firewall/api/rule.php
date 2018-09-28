<?php
	class Firewall_Api_Rule extends Firewall_Api_Abstract
	{
		const OBJECT_TYPE = 'rule';
		const OBJECT_NAME = 'rule';
		const FIELD_NAME = 'name';

		const CATEG_MONOSITE = 'monosite';
		const CATEG_FAILOVER = 'failover';

		protected static $_TIMESTAMP = null;

		protected $_datas = array(
			'name' => null,
			'category' => null,
			'fullmesh' => false,
			'action' => false,
			'sources' => array(),
			'destinations' => array(),
			'protocols' => array(),
			'description' => '',
			'timestamp' => null,
		);


		public function __construct($name = null, $category = null, $description = null)
		{
			$this->name($name);
			$this->category($category);
			$this->description($description);

			if(self::$_TIMESTAMP === null) {
				self::$_TIMESTAMP = time();
			}

			$this->_datas['timestamp'] = self::$_TIMESTAMP;
		}

		public function name($name)
		{
			if(Tools::is('string&&!empty', $name) || Tools::is('int&&>=0', $name)) {
				$this->_datas['name'] = (string) $name;
				return true;
			}

			return false;
		}

		public function category($category = self::CATEG_MONOSITE)
		{
			if($category === null) {
				$category = self::CATEG_MONOSITE;
			}

			switch($category)
			{
				case self::CATEG_MONOSITE:
					$this->_datas['fullmesh'] = false;
					$this->_datas['category'] = $category;
					break;
				case self::CATEG_FAILOVER:
					$this->_datas['category'] = $category;
					break;
				default:
					throw new Exception("Rule category '".$category."' does not exist", E_USER_ERROR);
			}

			return true;
		}

		public function fullmesh($state = true)
		{
			$category = $this->category;

			if($this->category === self::CATEG_MONOSITE) {
				$this->_datas['fullmesh'] = false;
			}
			elseif($this->category === self::CATEG_FAILOVER)
			{
				if(Tools::is('bool', $state)) {
					$this->_datas['fullmesh'] = $state;
				}
				else
				{
					if($this->_datas['fullmesh'] === null) {
						$this->_datas['fullmesh'] = true;
					}
					else {
						$this->_datas['fullmesh'] = !$this->_datas['fullmesh'];
					}
				}
			}
			else {
				throw new Exception("Rule category '".$category."' is unknow", E_USER_ERROR);
			}

			return true;
		}

		public function action($state = false)
		{
			if(Tools::is('bool', $state)) {
				$this->_datas['action'] = $state;
				return true;
			}

			return false;
		}

		public function src(Firewall_Api_Address $source)
		{
			return $this->addSource($source);
		}

		public function source(Firewall_Api_Address $source)
		{
			return $this->addSource($source);
		}

		public function addSource(Firewall_Api_Address $source)
		{
			return $this->_addSrcDst('sources', $source);
		}

		public function sources(array $sources)
		{
			return $this->setSources($sources);
		}

		public function setSources(array $sources)
		{
			$this->reset('sources');

			foreach($sources as $source)
			{
				$status = $this->source($source);

				if(!$status) {
					$this->reset('sources');
					return false;
				}
			}

			return true;
		}

		public function dst(Firewall_Api_Address $destination)
		{
			return $this->addDestination($destination);
		}

		public function destination(Firewall_Api_Address $destination)
		{
			return $this->addDestination($destination);
		}

		public function addDestination(Firewall_Api_Address $destination)
		{
			return $this->_addSrcDst('destinations', $destination);
		}

		public function destinations(array $destinations)
		{
			return $this->setDestinations($destinations);
		}

		public function setDestinations(array $destinations)
		{
			$this->reset('destinations');

			foreach($destinations as $destination)
			{
				$status = $this->destination($destination);

				if(!$status) {
					$this->reset('destinations');
					return false;
				}
			}

			return true;
		}

		protected function _addSrcDst($attribute, Firewall_Api_Address $object)
		{
			if($object->isValid())
			{
				$name = $object->name;

				foreach(array('sources', 'destinations') as $attributes)
				{
					foreach($this->_datas[$attributes] as $attrObject)
					{
						if($name === $attrObject->name) {
							return false;
						}
					}
				}

				$this->_datas[$attribute][] = $object;

				uasort($this->_datas[$attribute], function($a, $b) {
					return strnatcasecmp($a->name, $b->name);
				});

				return true;
			}

			return false;
		}

		public function protocol(Firewall_Api_Protocol $protocol)
		{
			return $this->addProtocol($protocol);
		}

		public function addProtocol(Firewall_Api_Protocol $protocol)
		{
			if($protocol->isValid())
			{
				$name = $protocol->name;

				foreach($this->_datas['protocols'] as $protoObject)
				{
					if($name === $protoObject->name) {
						return false;
					}
				}

				$this->_datas['protocols'][] = $protocol;

				uasort($this->_datas['protocols'], function($a, $b) {
					return strnatcasecmp($a->name, $b->name);
				});

				return true;
			}

			return false;
		}

		public function description($description = '')
		{
			if(Tools::is('string', $description)) {
				$this->_datas['description'] = $description;
				return true;
			}

			return false;
		}

		public function isPresent(Firewall_Api_Address $object)
		{
			$type = $object->type;
			$name = $object->name;

			foreach(array('sources', 'destinations') as $attributes)
			{
				foreach($this->_datas[$attributes] as $attribute)
				{
					if($attribute->type === $type && $attribute->name === $name) {
						return true;
					}
				}
			}

			return false;
		}

		public function reset($attribute = null)
		{
			switch($attribute)
			{
				case 'src':
				case 'source':
				case 'sources':
					$this->_datas['sources'] = array();
					break;
				case 'dst':
				case 'destination':
				case 'destinations':
					$this->_datas['destinations'] = array();
					break;
				case 'protocol':
				case 'protocols':
					$this->_datas['protocols'] = array();
					break;
				case null:
				case true:
					$this->_datas['sources'] = array();
					$this->_datas['destinations'] = array();
					$this->_datas['protocols'] = array();
					break;
				default:
					return false;
			}

			return true;
		}

		public function check()
		{
			return $this->isValid();
		}

		public function isValid($returnInvalidAttributes = false)
		{
			$invalidAttributes = $this->_isValid();

			if($returnInvalidAttributes) {
				return $invalidAttributes;
			}
			else {
				return (count($invalidAttributes) === 0);
			}
		}

		protected function _isValid()
		{
			$invalidAttributes = array();

			$requiredAttributes = array(
				'bool' => array(
					'full mesh' => 'fullmesh',
					'action' => 'action'
				),
				'int' => array(
					'timestamp' => 'timestamp',
				),
				'string' => array(
					'name' => 'name',
					'category' => 'category'
				),
				'array' => array(
					'source' => 'sources',
					'destination' => 'destinations',
					'protocol' => 'protocols'
				)
			);

			foreach($requiredAttributes as $type => $attributes) {
				$this->_isValidAttributes($type, $attributes, $invalidAttributes);
			}

			return $invalidAttributes;
		}

		protected function _isValidAttributes($type, array $attributes, array &$invalidAttributes)
		{
			switch($type)
			{
				case 'bool': {
					$test = 'bool';
					break;
				}
				case 'int': {
					$test = 'int&&>0';
					break;
				}
				case 'string': {
					$test = 'string';
					break;
				}
				case 'array': {
					$test = 'array&&count>0';
					break;
				}
				default: {
					return false;
				}
			}

			/**
			  * /!\ Ne pas (ré)initialiser la variable
			  * Voir la méthode getInvalidAttributes
			  **/
			//$invalidAttributes = array();

			foreach($attributes as $attribute)
			{
				if(!Tools::is($test, $this->_datas[$attribute])) {
					$invalidAttributes[] = $attribute;
				}
			}

			return (count($invalidAttributes) === 0);
		}

		public function __get($name)
		{
			switch($name)
			{
				case 'monosite': {
					return ($this->_datas['category'] === self::CATEG_MONOSITE);
				}
				case 'failover': {
					return ($this->_datas['category'] === self::CATEG_FAILOVER);
				}
				default: {
					return parent::__get($name);
				}
			}
		}

		public function sleep()
		{
			$datas = $this->_datas;

			foreach(array('sources', 'destinations') as $attributes)
			{
				foreach($datas[$attributes] as &$attrObject) {
					$attrObject = get_class($attrObject).'::'.$attrObject->name;
				}
			}

			foreach($datas['protocols'] as &$attrObject) {
				$attrObject = $attrObject->protocol;
			}

			return $datas;
		}

		public function wakeup(array $datas, ArrayObject $objects = null)
		{
			if($objects !== null)
			{
				foreach(array('sources', 'destinations') as $attributes)
				{
					foreach($datas[$attributes] as &$attrObject)
					{
						$parts = explode('::', $attrObject, 2);

						if(count($parts) === 2)
						{
							if(array_key_exists($parts[0], $objects) && array_key_exists($parts[1], $objects[$parts[0]])) {
								$attrObject = $objects[$parts[0]][$parts[1]];
							}
							else {
								return false;
							}
						}
						else {
							return false;
						}
					}
				}

				foreach($datas['protocols'] as &$protocol)
				{
					$Firewall_Api_Protocol = new Firewall_Api_Protocol($protocol, $protocol);

					if($Firewall_Api_Protocol->isValid()) {
						$protocol = $Firewall_Api_Protocol;
					}
					else {
						return false;
					}
				}

				$this->_datas = $datas;
				return true;
			}
			else {
				return false;
			}
		}
	}