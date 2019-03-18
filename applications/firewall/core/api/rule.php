<?php
	namespace App\Firewall\Core;

	use ArrayObject;

	use Core as C;
	use Core\Exception as E;

	class Api_Rule extends Api_Abstract implements Api_Rule_Interface
	{
		const OBJECT_KEY = 'rule';
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
			'state' => false,
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

			$this->touch();
		}

		public function name($name)
		{
			if(C\Tools::is('string&&!empty', $name) || C\Tools::is('int&&>=0', $name)) {
				$this->_datas[self::FIELD_NAME] = (string) $name;
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
				if(C\Tools::is('bool', $state)) {
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

		public function state($state = false)
		{
			if(C\Tools::is('bool', $state)) {
				$this->_datas['state'] = $state;
				return true;
			}

			return false;
		}

		public function action($state = false)
		{
			if(C\Tools::is('bool', $state)) {
				$this->_datas['action'] = $state;
				return true;
			}

			return false;
		}

		public function src(Api_Address $addressApi)
		{
			return $this->addSource($addressApi);
		}

		public function source(Api_Address $addressApi)
		{
			return $this->addSource($addressApi);
		}

		public function addSource(Api_Address $addressApi)
		{
			return $this->_addSrcDst('sources', $addressApi);
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

		public function dst(Api_Address $addressApi)
		{
			return $this->addDestination($addressApi);
		}

		public function destination(Api_Address $addressApi)
		{
			return $this->addDestination($addressApi);
		}

		public function addDestination(Api_Address $addressApi)
		{
			return $this->_addSrcDst('destinations', $addressApi);
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

		protected function _addSrcDst($attribute, Api_Address $addressApi)
		{
			if($addressApi->isValid())
			{
				/**
				  * /!\ On interdit des doublons d'host car cela n'a pas de sens mais on l'autorise pour les subnet et les network
				  * /!\ Les doublons ne sont autorisés que entre les attributs source et destination et non au sein du même attribut
				  */
				if($addressApi::OBJECT_TYPE === Api_Host::OBJECT_TYPE) {
					$attributes = array('sources', 'destinations');
				}
				else {
					$attributes = array($attribute);
				}

				$type = $addressApi->type;
				$name = $addressApi->name;

				foreach($attributes as $_attributes)
				{
					foreach($this->_datas[$_attributes] as $Api_Address)
					{
						if($type === $Api_Address->type && $name === $Api_Address->name) {
							return false;
						}
					}
				}

				$this->_datas[$attribute][] = $addressApi;
				$this->_refresh($attribute);
				return true;
			}
			else {
				return false;
			}
		}

		public function protocol(Api_Protocol $protocolApi)
		{
			return $this->addProtocol($protocolApi);
		}

		public function addProtocol(Api_Protocol $protocolApi)
		{
			if($protocolApi->isValid())
			{
				$name = $protocolApi->name;

				foreach($this->_datas['protocols'] as $protoObject)
				{
					if($name === $protoObject->name) {
						return false;
					}
				}

				$this->_datas['protocols'][] = $protocolApi;
				$this->_refresh('protocols');
				return true;
			}

			return false;
		}

		public function description($description = '')
		{
			if(C\Tools::is('string', $description)) {
				$this->_datas['description'] = $description;
				return true;
			}

			return false;
		}

		public function replace(Api_Address $badAddressApi, Api_Address $newAddressApi)
		{
			$counter = 0 ;

			$badType = $badAddressApi->type;
			$badName = $badAddressApi->name;

			foreach(array('sources', 'destinations') as $attributes)
			{
				foreach($this->_datas[$attributes] as &$attribute)
				{
					if(($attribute->type === $badType && $attribute->name === $badName)) {
						$attribute = $newAddressApi;
						$counter++;
					}
				}
			}

			return ($counter > 0);
		}

		public function reset($attribute = null, $type = null, Api_Abstract $object = null)
		{
			switch(true)
			{
				case ($attribute === 'source'):
				{
					if($type !== null && $object !== null) {
						return $this->_resetAddress($this->_datas['sources'], $type, $object);
					}
					else {
						return false;
					}
					break;
				}
				case ($attribute === 'sources'): {
					$this->_datas['sources'] = array();
					break;
				}
				case ($attribute === 'destination'):
				{
					if($type !== null && $object !== null) {
						return $this->_resetAddress($this->_datas['destinations'], $type, $object);
					}
					else {
						return false;
					}
					break;
				}
				case ($attribute === 'destinations'): {
					$this->_datas['destinations'] = array();
					break;
				}
				case ($attribute === 'protocol'):
				{
					if($type !== null && $object !== null) {
						return $this->_resetProtocol($this->_datas['protocols'], $type, $object);
					}
					else {
						return false;
					}
					break;
				}
				case ($attribute === 'protocols'): {
					$this->_datas['protocols'] = array();
					break;
				}
				case ($attribute === null):
				case ($attribute === true): {
					$this->_datas['sources'] = array();
					$this->_datas['destinations'] = array();
					$this->_datas['protocols'] = array();
					break;
				}
				default: {
					return false;
				}
			}

			return true;
		}

		protected function _resetAddress(&$attributes, $type, Api_Address $addressApi)
		{
			switch($type)
			{
				case Api_Host::OBJECT_TYPE:
				case Api_Subnet::OBJECT_TYPE:
				case Api_Network::OBJECT_TYPE:
				{
					foreach($attributes as $index => $attribute)
					{
						if($attribute->type === $type && $attribute->name === $addressApi->name) {
							unset($attributes[$index]);
							return true;
						}
					}
					break;
				}
			}

			return false;
		}

		protected function _resetProtocol(&$attributes, $type, Api_Protocol $protocolApi)
		{
			foreach($attributes as $index => $attribute)
			{
				if($attribute->type === $type && $attribute->protocol === $protocolApi->protocol) {
					unset($attributes[$index]);
					return true;
				}
			}

			return false;
		}

		public function timestamp($timestamp)
		{
			if(C\Tools::is('int&&>0', $timestamp)) {
				$this->_datas['timestamp'] = $timestamp;
				return true;
			}

			return false;
		}

		public function touch()
		{
			$this->_datas['timestamp'] = self::$_TIMESTAMP;
			return $this;
		}

		/**
		  * Seulement si le timestamp n'est pas global
		  * Voir __construct pour comprendre
		  */
		/*public function touch()
		{
			$this->_datas['timestamp'] = time();
			return $this;
		}*/

		public function refresh()
		{
			$this->_refresh('sources');
			$this->_refresh('destinations');
			$this->_refresh('protocols');
			return $this;
		}

		protected function _refresh($attribute)
		{
			switch($attribute)
			{
				case 'sources':
				case 'destinations':
				case 'protocols':
				{
					uasort($this->_datas[$attribute], function($a, $b) {
						return strnatcasecmp($a->name, $b->name);
					});
					break;
				}
			}
		}

		public function match($search, $strict = false)
		{
			$fieldAttrs = array('description');

			return $this->_match($search, $fieldAttrs, $strict);
		}

		/**
		  * Check the Address argument is present for this rule
		  *
		  * Do not test attributeV4 or attributeV6 because
		  * the test must be about Address object and not it attributes
		  *
		  * @arg App\Firewall\Core\Api_Address $addressApi Address object to test
		  * @return bool Address is present for this rule
		  */
		public function isPresent(Api_Address $addressApi)
		{
			$type = $addressApi->type;
			$name = $addressApi->name;

			foreach(array('sources', 'destinations') as $attributes)
			{
				foreach($this->_datas[$attributes] as $attribute)
				{
					if(($attribute->type === $type && $attribute->name === $name)) {
						return true;
					}
				}
			}

			return false;
		}

		/**
		  * Check the Address argument is used for this rule
		  *
		  * Do not test name because the test must be
		  * about Address attributes and not the object
		  *
		  * @arg App\Firewall\Core\Api_Address $addressApi Address object to test
		  * @return bool Address is used for this rule
		  */
		public function isInUse(Api_Address $addressApi, $strict = false)
		{
			$type = $addressApi->type;
			$isIPv4 = $addressApi->isIPv4();
			$isIPv6 = $addressApi->isIPv6();
			$attributeV4 = $addressApi->attributeV4;
			$attributeV6 = $addressApi->attributeV6;

			foreach(array('sources', 'destinations') as $attributes)
			{
				foreach($this->_datas[$attributes] as $attribute)
				{
					if($strict)
					{
						if($attribute->type === $type && (
							($isIPv4 && $attribute->attributeV4 === $attributeV4) ||
							($isIPv6 && $attribute->attributeV6 === $attributeV6)))
						{
							return true;
						}
					}
					else
					{
						if($attribute->includes($addressApi)) {
							return true;
						}
					}
				}
			}

			return false;
		}

		public function isValid($returnInvalidAttributes = false)
		{
			$tests = array(
				'bool' => array(
					'fullmesh',
					'state',
					'action'
				),
				'int&&>0' => array(
					'timestamp',
				),
				'string&&!empty' => array(
					self::FIELD_NAME,
					'category'
				),
				'array&&count>0' => array(
					'sources',
					'destinations',
					'protocols'
				)
			);

			return $this->_isValid($tests, $returnInvalidAttributes);
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

		public function __clone()
		{
			$this->touch();
		}

		public function sleep()
		{
			$datas = $this->_datas;

			foreach(array('sources', 'destinations') as $attributes)
			{
				foreach($datas[$attributes] as &$attrObject) {
					$attrObject = $attrObject::OBJECT_KEY.'::'.$attrObject->name;
				}

				/**
				  * /!\ Important for json_encode
				  * Si des index sont manquants alors json_encode
				  * va indiquer explicitement les clés dans le tableau
				  */
				$datas[$attributes] = array_values($datas[$attributes]);
			}

			foreach($datas['protocols'] as &$attrObject) {
				$attrObject = $attrObject->protocol;
			}

			/**
			  * /!\ Important for json_encode
			  * Si des index sont manquants alors json_encode
			  * va indiquer explicitement les clés dans le tableau
			  */
			$datas['protocols'] = array_values($datas['protocols']);

			return $datas;
		}

		public function wakeup(array $datas, ArrayObject $objects = null)
		{
			if($objects !== null)
			{
				// @todo temporaire/compatibilité
				if(!array_key_exists('state', $datas)) {
					$datas['state'] = true;
				}

				$datas = array_intersect_key($datas, $this->_datas);
				$datas = array_merge($this->_datas, $datas);

				// /!\ Permets de s'assurer que les traitements spéciaux sont bien appliqués
				$this->name($datas['name']);
				$this->category($datas['category']);
				$this->fullmesh($datas['fullmesh']);
				$this->state($datas['state']);
				$this->action($datas['action']);
				$this->description($datas['description']);
				$this->timestamp($datas['timestamp']);

				foreach(array('source' => 'sources', 'destination' => 'destinations') as $attribute => $attributes)
				{
					foreach($datas[$attributes] as $attrObject)
					{
						$parts = explode('::', $attrObject, 2);

						if(count($parts) === 2)
						{
							if(array_key_exists($parts[0], $objects) && array_key_exists($parts[1], $objects[$parts[0]])) {
								call_user_func(array($this, $attribute), $objects[$parts[0]][$parts[1]]);
							}
							else {
								throw new E\Message("Address '".$attrObject."' is not valid", E_USER_ERROR);
							}
						}
						else {
							throw new E\Message("Address '".$attrObject."' is not valid", E_USER_ERROR);
						}
					}
				}

				foreach($datas['protocols'] as $protocol)
				{
					$Core_Api_Protocol = new Api_Protocol($protocol, $protocol);

					if($Core_Api_Protocol->isValid()) {
						$this->protocol($Core_Api_Protocol);
					}
					else {
						throw new E\Message("Protocol '".$protocol."' is not valid", E_USER_ERROR);
					}
				}

				return true;
			}
			else {
				return false;
			}
		}
	}