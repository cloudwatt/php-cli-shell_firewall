<?php
	namespace App\Firewall\Core;

	use Core as C;
	use Core\Exception as E;

	class Api_Rule extends Api_Abstract implements Api_Interface, Api_Rule_Interface
	{
		const OBJECT_KEY = 'rule';
		const OBJECT_TYPE = 'rule';
		const OBJECT_NAME = 'rule';

		const FIELD_NAME = 'name';

		const CATEG_MONOSITE = 'monosite';
		const CATEG_FAILOVER = 'failover';

		const SEPARATOR_TYPE = '::';

		protected static $_TIMESTAMP = null;

		protected $_datas = array(
			'_id_' => null,
			'name' => null,
			'category' => null,
			'fullmesh' => false,
			'state' => false,
			'action' => false,
			'sources' => array(),
			'destinations' => array(),
			'protocols' => array(),
			'description' => '',
			'tags' => array(),
			'timestamp' => null,
		);


		/**
		  * @param string $id ID
		  * @param string $name Name
		  * @param string $category Category
		  * @param string $description Description
		  * @return $this
		  */
		public function __construct($id = null, $name = null, $category = null, $description = null)
		{
			$this->id($id);
			$this->name($name);
			$this->category($category);
			$this->description($description);

			if(self::$_TIMESTAMP === null) {
				self::$_TIMESTAMP = time();
			}

			$this->touch();
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
				$_id_ = $addressApi->_id_;

				foreach($attributes as $_attributes)
				{
					foreach($this->_datas[$_attributes] as $Api_Address)
					{
						/**
						  * Des objets Address de type différents peuvent avoir le même nom
						  *
						  * Le contrôle de l'overlap d'adresses doit se faire en dehors de la cette classe
						  * afin de laisser le choix de l'autoriser ou de l'interdire et d'afficher un avertissement
						  */
						if($type === $Api_Address->type && $_id_ === $Api_Address->_id_) {
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

		/**
		  * @throw Core\Exception\Message
		  * @return void
		  */
		public function checkOverlapAddress()
		{
			$attributes = array(
				'sources' => array('sources', 'destinations'),
				'destinations' =>  array('destinations')
			);

			$testsDone = array();

			foreach($attributes as $attribute_A => $attributes_B)
			{
				foreach($attributes_B as $attribute_B)
				{
					foreach($this->_datas[$attribute_A] as $index_A => $addressApi_A)
					{
						foreach($this->_datas[$attribute_B] as $index_B => $addressApi_B)
						{
							if($index_A === $index_B || (isset($testsDone[$index_B]) && in_array($index_A, $testsDone[$index_B], true))) {
								continue;
							}
							/**
							  * /!\ On interdit des doublons d'host car cela n'a pas de sens mais on l'autorise pour les subnet et les network
							  * /!\ Les doublons ne sont autorisés que entre les attributs source et destination et non au sein du même attribut
							  */
							elseif($attribute_A !== $attribute_B && ($addressApi_A::OBJECT_TYPE !== Api_Host::OBJECT_TYPE || $addressApi_B::OBJECT_TYPE !== Api_Host::OBJECT_TYPE)) {
								continue;
							}

							$this->_addressesOverlap($addressApi_A, $addressApi_B);
							$testsDone[$index_B][] = $index_A;
						}
					}
				}
			}
		}

		/**
		  * @param string $srcDst
		  * @param App\Firewall\Core\Api_Address $addressApi
		  * @throw Core\Exception\Message
		  * @return void
		  */
		public function testAddressOverlap($srcDst, Api_Address $addressApi)
		{
			/**
			  * /!\ On interdit des doublons d'host car cela n'a pas de sens mais on l'autorise pour les subnet et les network
			  * /!\ Les doublons ne sont autorisés que entre les attributs source et destination et non au sein du même attribut
			  */
			if($addressApi::OBJECT_TYPE === Api_Host::OBJECT_TYPE) {
				$attributes = array('sources', 'destinations');
			}
			else
			{
				switch($srcDst)
				{
					case 'source':
					case 'sources': {
						$attributes = array('sources');
						break;
					}
					case 'destination':
					case 'destinations': {
						$attributes = array('destinations');
						break;
					}
					default: {
						throw new Exception("Rule attribute '".$srcDst."' is not valid", E_USER_ERROR);
					}
				}
			}

			$type = $addressApi->type;
			$_id_ = $addressApi->_id_;

			foreach($attributes as $_attributes)
			{
				foreach($this->_datas[$_attributes] as $Api_Address)
				{
					/**
					  * Lorsque l'utilisateur souhaite modifier une addresse
					  * alors il ne faut pas tester l'overlap sur elle même
					  */
					if($type !== $Api_Address->type || $_id_ !== $Api_Address->_id_) {
						$this->_addressesOverlap($addressApi, $Api_Address);
					}
				}
			}
		}

		/**
		  * @param App\Firewall\Core\Api_Address $addressApi_A
		  * @param App\Firewall\Core\Api_Address $addressApi_B
		  * @throw Core\Exception\Message
		  * @return void
		  */
		protected function _addressesOverlap(Api_Address $addressApi_A, Api_Address $addressApi_B)
		{
			$addressName_A = ucfirst($addressApi_A::OBJECT_NAME);
			$addressName_B = ucfirst($addressApi_B::OBJECT_NAME);

			switch($addressApi_A::OBJECT_TYPE)
			{
				case Api_Host::OBJECT_TYPE:
				{
					if($addressApi_B->includes($addressApi_A)) {
						throw new E\Message($addressName_B." '".$addressApi_B->name."' includes or overlaps the ".$addressName_A." '".$addressApi_A->name."'", E_USER_WARNING);
					}
					break;
				}
				case Api_Subnet::OBJECT_TYPE:
				case Api_Network::OBJECT_TYPE:
				{
					switch($addressApi_B::OBJECT_TYPE)
					{
						case Api_Host::OBJECT_TYPE:
						{
							if($addressApi_A->includes($addressApi_B)) {
								throw new E\Message($addressName_A." '".$addressApi_A->name."' includes the ".$addressName_B." '".$addressApi_B->name."'", E_USER_WARNING);
							}
							break;
						}
						case Api_Subnet::OBJECT_TYPE:
						case Api_Network::OBJECT_TYPE:
						{
							if($addressApi_A->includes($addressApi_B) || $addressApi_B->includes($addressApi_A)) {
								throw new E\Message($addressName_B." '".$addressApi_B->name."' includes or is included by the ".$addressName_A." '".$addressApi_A->name."'", E_USER_WARNING);
							}
							break;
						}
					}
					break;
				}
			}
		}

		/**
		  * Adds protocol
		  *
		  * @param App\Firewall\Core\Api_Protocol $protocolApi
		  * @return bool
		  */
		public function proto(Api_Protocol $protocolApi)
		{
			return $this->addProtocol($protocolApi);
		}

		/**
		  * Adds protocol
		  *
		  * @param App\Firewall\Core\Api_Protocol $protocolApi
		  * @return bool
		  */
		public function protocol(Api_Protocol $protocolApi)
		{
			return $this->addProtocol($protocolApi);
		}

		/**
		  * Adds protocol
		  *
		  * @param App\Firewall\Core\Api_Protocol $protocolApi
		  * @return bool
		  */
		public function addProtocol(Api_Protocol $protocolApi)
		{
			if($protocolApi->isValid())
			{
				$_id_ = $protocolApi->_id_;

				foreach($this->_datas['protocols'] as $Api_Protocol)
				{
					if($_id_ === $Api_Protocol->_id_) {
						return false;
					}
				}

				$this->_datas['protocols'][] = $protocolApi;
				$this->_refresh('protocols');
				return true;
			}

			return false;
		}

		public function protocols(array $protocols)
		{
			return $this->setProtocols($protocols);
		}

		public function setProtocols(array $protocols)
		{
			$this->reset('protocols');

			foreach($protocols as $protocol)
			{
				$status = $this->protocol($protocol);

				if(!$status) {
					$this->reset('protocols');
					return false;
				}
			}

			return true;
		}

		public function description($description = '')
		{
			if(C\Tools::is('string', $description)) {
				$this->_datas['description'] = $description;
				return true;
			}

			return false;
		}

		/**
		  * Adds tag
		  *
		  * @param App\Firewall\Core\Api_Tag $tagApi
		  * @return bool
		  */
		public function tag(Api_Tag $tagApi)
		{
			if($tagApi->isValid())
			{
				$_id_ = $tagApi->_id_;

				foreach($this->_datas['tags'] as $Api_Tag)
				{
					if($_id_ === $Api_Tag->_id_) {
						return false;
					}
				}

				$this->_datas['tags'][] = $tagApi;
				$this->_refresh('tags');
				return true;
			}

			return false;
		}

		/**
		  * Configures this rule
		  *
		  * @param string $attrName For Api_Address must be source(s) or destination(s)
		  * @param App\Firewall\Core\Api_Abstract $abstractApi
		  * @return bool
		  */
		public function configure($attrName, Api_Abstract $abstractApi)
		{
			if($abstractApi instanceof Api_Address)
			{
				switch($attrName)
				{
					case 'source':
					case 'sources': {
						$attrName = 'sources';
						break;
					}
					case 'destination':
					case 'destinations': {
						$attrName = 'destinations';
						break;
					}
					default: {
						return false;
					}
				}

				return $this->_addSrcDst($attrName, $abstractApi);
			}
			elseif($abstractApi instanceof Api_Protocol) {
				return $this->protocol($abstractApi);
			}
			elseif($abstractApi instanceof Api_Tag) {
				return $this->tag($abstractApi);
			}
			else {
				return false;
			}
		}

		public function replace(Api_Address $badAddressApi, Api_Address $newAddressApi, &$counter = null)
		{
			/**
			  * Dans certains cas l'utilisateur peut passer une variable counter qui n'est pas égale à 0
			  * Cela permet à l'utilisateur d'avoir un compteur total, donc ne pas tenter de le réinitialiser à 0
			  */
			if(!C\Tools::is('int', $counter)) {
				$counter = 0;
			}

			$localCounter = 0;

			foreach(array('source', 'destination') as $attribute)
			{
				/**
				  * Dans un 1er temps, on supprime l'ancien objet adresse
				  *
				  * Si et seulement si on a réussi à le supprimer et donc à le trouver
				  * alors on peut essayer de configurer le nouvel objet adresse mais
				  * si celui-ci est déjà présent alors il ne sera pas ajouté
				  *
				  * Le compteur doit par contre s'incrémenter afin d'indiquer un changement
				  */
				$resetStatus = $this->reset($attribute, $badAddressApi->type, $badAddressApi);

				if($resetStatus) {
					$configureStatus = $this->configure($attribute, $newAddressApi);
					$localCounter++;
				}
			}

			$counter += $localCounter;
			return ($localCounter > 0);
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
				case ($attribute === 'tag'):
				{
					if($type !== null && $object !== null) {
						return $this->_resetTag($this->_datas['tags'], $type, $object);
					}
					else {
						return false;
					}
				}
				case ($attribute === 'tags'): {
					$this->_datas['tags'] = array();
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
				case Api_Network::OBJECT_TYPE: {
					return $this->_reset($attributes, $type, $addressApi, 'name');
				}
			}

			return false;
		}

		protected function _resetProtocol(&$attributes, $type, Api_Protocol $protocolApi)
		{
			return $this->_reset($attributes, $type, $protocolApi, 'protocol');
		}

		protected function _resetTag(&$attributes, $type, Api_Tag $tagApi)
		{
			return $this->_reset($attributes, $type, $tagApi, 'tag');
		}

		protected function _reset(&$attributes, $type, Api_Abstract $api, $attrField)
		{
			foreach($attributes as $index => $attribute)
			{
				if($attribute->type === $type && $attribute->{$attrField} === $api->{$attrField}) {
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
			$this->_refresh('tags');
			return $this;
		}

		protected function _refresh($attribute)
		{
			switch($attribute)
			{
				case 'sources':
				case 'destinations':
				case 'protocols':
				case 'tags':
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
			/**
			  * Ne pas oublier name pour les règles avec un préfixe ou un suffixe
			  */
			$fieldAttrs = array(self::FIELD_NAME, 'description');
			$isMatched = $this->_match($search, $fieldAttrs, $strict);

			if(!$isMatched)
			{
				foreach($this->tags as $Api_Tag)
				{
					if($Api_Tag->match($search, $strict)) {
						$isMatched = true;
						break;
					}
				}
			}

			return $isMatched;
		}

		/**
		  * Checks the address argument is present for this rule
		  *
		  * Do not test attributeV4 or attributeV6 because
		  * the test must be about Address object and not it attributes
		  *
		  * @param App\Firewall\Core\Api_Address $addressApi Address object to test
		  * @return bool Address is present for this rule
		  */
		public function addressIsPresent(Api_Address $addressApi)
		{
			foreach(array('sources', 'destinations') as $attributes)
			{
				$isPresent = $this->_objectIsPresent($attributes, $addressApi);

				if($isPresent) {
					return true;
				}
			}

			return false;
		}

		/**
		  * Checks the protocol argument is present for this rule
		  *
		  * @param App\Firewall\Core\Api_Protocol $protocolApi Protocol object to test
		  * @return bool Protocol is present for this rule
		  */
		public function protocolIsPresent(Api_Protocol $protocolApi)
		{
			return $this->_objectIsPresent('protocols', $protocolApi);
		}

		/**
		  * Checks the tag argument is present for this rule
		  *
		  * @param App\Firewall\Core\Api_Tag $tagApi Tag object to test
		  * @return bool Tag is present for this rule
		  */
		public function tagIsPresent(Api_Tag $tagApi)
		{
			return $this->_objectIsPresent('tags', $tagApi);
		}

		/**
		  * Checks the address argument is present for this rule
		  *
		  * Do not test attributeV4 or attributeV6 because
		  * the test must be about Address object and not it attributes
		  *
		  * @param App\Firewall\Core\Api_Address $addressApi Address object to test
		  * @return bool Address is present for this rule
		  */
		public function isPresent(Api_Address $addressApi)
		{
			return $this->addressIsPresent($addressApi);
		}

		/**
		  * Checks the object argument is present for this rule
		  *
		  * Do not test object attributes because the test
		  * must be about object itself and not it attributes
		  *
		  * @param string $attributes Attributes field name
		  * @param App\Firewall\Core\Api_Abstract $objectApi Object object to test
		  * @return bool Object is present for this rule
		  */
		protected function _objectIsPresent($attributes, Api_Abstract $objectApi)
		{
			$type = $objectApi->type;
			$_id_ = $objectApi->_id_;

			foreach($this->_datas[$attributes] as $attribute)
			{
				if(($attribute->type === $type && $attribute->_id_ === $_id_)) {
					return true;
				}
			}

			return false;
		}

		/**
		  * Checks the address argument is used for this rule
		  *
		  * Do not test name because the test must be
		  * about Address attributes and not the object
		  *
		  * @param App\Firewall\Core\Api_Address $addressApi Address object to test
		  * @param bool $strict True to test equality between addresse attributes, false to test addresse attributes inclusion
		  * @param App\Firewall\Core\Api_Address $ignoreAddressApi Address object to ignore, use type and ID to compare address object
		  * @return bool Address is used for this rule
		  */
		public function addressIsInUse(Api_Address $addressApi, $strict = true, Api_Address $ignoreAddressApi = null)
		{
			$Api_Address = $this->getAddressIsInUse($addressApi, $strict, $ignoreAddressApi);
			return ($Api_Address !== false);
		}

		/**
		  * Gets the address argument is used for this rule
		  *
		  * Do not test name because the test must be
		  * about Address attributes and not the object
		  *
		  * @param App\Firewall\Core\Api_Address $addressApi Address object to test
		  * @param bool $strict True to test equality between addresse attributes, false to test addresse attributes inclusion
		  * @param App\Firewall\Core\Api_Address $ignoreAddressApi Address object to ignore, use type and ID to compare address object
		  * @return false|App\Firewall\Core\Api_Address Address is used for this rule
		  */
		public function getAddressIsInUse(Api_Address $addressApi, $strict = true, Api_Address $ignoreAddressApi = null)
		{
			$addressType = $addressApi->type;
			$isIPv4 = $addressApi->isIPv4();
			$isIPv6 = $addressApi->isIPv6();
			$attributeV4 = $addressApi->attributeV4;
			$attributeV6 = $addressApi->attributeV6;

			if($ignoreAddressApi !== null) {
				$ignoreType = $ignoreAddressApi->type;
				$ignoreId = $ignoreAddressApi->_id_;
			}

			foreach(array('sources', 'destinations') as $attributes)
			{
				foreach($this->_datas[$attributes] as $Api_Address)
				{
					$currentType = $Api_Address->type;

					if($ignoreAddressApi !== null && $ignoreType === $currentType && $ignoreId === $Api_Address->_id_) {
						continue;
					}

					if($strict)
					{
						if($currentType === $addressType && (
							($isIPv4 && $Api_Address->attributeV4 === $attributeV4) ||
							($isIPv6 && $Api_Address->attributeV6 === $attributeV6)))
						{
							return $Api_Address;
						}
					}
					else
					{
						if($Api_Address->includes($addressApi)) {
							return $Api_Address;
						}
					}
				}
			}

			return false;
		}

		/**
		  * Checks the protocol argument is used for this rule
		  *
		  * Do not test name because the test must be
		  * about Protocol attributes and not the object
		  *
		  * @param App\Firewall\Core\Api_Protocol $protocolApi Protocol object to test
		  * @return bool Protocol is used for this rule
		  */
		public function protocolIsInUse(Api_Protocol $protocolApi, $strict = true)
		{
			$Api_Protocol = $this->getProtocolIsInUse($protocolApi, $strict);
			return ($Api_Protocol !== false);
		}

		/**
		  * Gets the protocol argument is used for this rule
		  *
		  * Do not test name because the test must be
		  * about Protocol attributes and not the object
		  *
		  * @param App\Firewall\Core\Api_Protocol $protocolApi Protocol object to test
		  * @return false|App\Firewall\Core\Api_Protocol Protocol is used for this rule
		  */
		public function getProtocolIsInUse(Api_Protocol $protocolApi, $strict = true)
		{
			$type = $protocolApi->type;
			$protocol = $protocolApi->protocol;

			foreach($this->_datas['protocols'] as $Api_Protocol)
			{
				if($strict)
				{
					if($Api_Protocol->type === $type && $Api_Protocol->protocol === $protocol) {
						return $Api_Protocol;
					}
				}
				else
				{
					if($Api_Protocol->includes($protocolApi)) {
						return $Api_Protocol;
					}
				}
			}

			return false;
		}

		/**
		  * Checks the tag argument is used for this rule
		  *
		  * Do not test name because the test must be
		  * about Tag attributes and not the object
		  *
		  * @param App\Firewall\Core\Api_Tag $tagApi Tag object to test
		  * @return bool Tag is used for this rule
		  */
		public function tagIsInUse(Api_Tag $tagApi, $strict = true)
		{
			$Api_Tag = $this->getTagIsInUse($tagApi, $strict);
			return ($Api_Tag !== false);
		}

		/**
		  * Gets the tag argument is used for this rule
		  *
		  * Do not test name because the test must be
		  * about Tag attributes and not the object
		  *
		  * @param App\Firewall\Core\Api_Tag $tagApi Tag object to test
		  * @return false|App\Firewall\Core\Api_Tag Tag is used for this rule
		  */
		public function getTagIsInUse(Api_Tag $tagApi, $strict = true)
		{
			$type = $tagApi->type;
			$tag = $tagApi->tag;

			foreach($this->_datas['tags'] as $Api_Tag)
			{
				if($Api_Tag->type === $type && $Api_Tag->tag === $tag) {
					return $Api_Tag;
				}
			}

			return false;
		}

		/**
		  * Checks the address argument is used for this rule
		  *
		  * Do not test name because the test must be
		  * about Address attributes and not the object
		  *
		  * @param App\Firewall\Core\Api_Address $addressApi Address object to test
		  * @return bool Address is used for this rule
		  */
		public function isInUse(Api_Address $addressApi, $strict = true)
		{
			return $this->addressIsInUse($addressApi, $strict);
		}

		public function isValid($returnInvalidAttributes = false)
		{
			$tests = array(
				array('fullmesh' => 'bool'),
				array('state' => 'bool'),
				array('action' => 'bool'),
				array(self::FIELD_NAME => 'string&&!empty'),
				array('category' => 'string&&!empty'),
				array('sources' => 'array&&count>0'),
				array('destinations' => 'array&&count>0'),
				array('protocols' => 'array&&count>0'),
				array('tags' => 'array&&count>=0'),
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

		/**
		  * @return array
		  */
		public function sleep()
		{
			$datas = $this->_datas;

			/*if(self::FIELD_ID !== 'id') {
				$datas['id'] = $datas[self::FIELD_ID];
				unset($datas[self::FIELD_ID]);
			}*/
			unset($datas[self::FIELD_ID]);

			if(self::FIELD_NAME !== 'name') {
				$datas['name'] = $datas[self::FIELD_NAME];
				unset($datas[self::FIELD_NAME]);
			}

			foreach(array('sources', 'destinations') as $attributes)
			{
				foreach($datas[$attributes] as &$attrObject) {
					$attrObject = $attrObject::OBJECT_TYPE.self::SEPARATOR_TYPE.$attrObject->name;
				}
				unset($attrObject);

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
			unset($attrObject);

			foreach($datas['tags'] as &$attrObject) {
				$attrObject = $attrObject->tag;
			}
			unset($attrObject);

			/**
			  * /!\ Important for json_encode
			  * Si des index sont manquants alors json_encode
			  * va indiquer explicitement les clés dans le tableau
			  */
			$datas['protocols'] = array_values($datas['protocols']);
			$datas['tags'] = array_values($datas['tags']);

			return $datas;
		}

		/**
		  * @param $datas array
		  * @return bool
		  */
		public function wakeup(array $datas)
		{
			// @todo temporaire/compatibilité
			// ------------------------------
			if(!array_key_exists('id', $datas)) {
				$datas['id'] = $datas['name'];
			}

			if(!array_key_exists('state', $datas)) {
				$datas['state'] = true;
			}

			if(!array_key_exists('tags', $datas)) {
				$datas['tags'] = array();
			}
			// ------------------------------

			// /!\ Permets de s'assurer que les traitements spéciaux sont bien appliqués
			$this->id($datas['id']);
			$this->name($datas['name']);
			$this->category($datas['category']);
			$this->fullmesh($datas['fullmesh']);
			$this->state($datas['state']);
			$this->action($datas['action']);
			$this->description($datas['description']);
			$this->timestamp($datas['timestamp']);

			foreach($datas['protocols'] as $protocol)
			{
				$Api_Protocol = new Api_Protocol($protocol, $protocol);
				$status = $Api_Protocol->protocol($protocol);

				if($status && $Api_Protocol->isValid()) {
					$this->protocol($Api_Protocol);
				}
				else {
					throw new E\Message("Protocol '".$protocol."' is not valid", E_USER_ERROR);
				}
			}

			foreach($datas['tags'] as $tag)
			{
				$Api_Tag = new Api_Tag($tag, $tag);
				$status = $Api_Tag->tag($tag);

				if($status && $Api_Tag->isValid()) {
					$this->tag($Api_Tag);
				}
				else {
					throw new E\Message("Tag '".$tag."' is not valid", E_USER_ERROR);
				}
			}
			
			return true;
		}
	}