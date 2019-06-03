<?php
	namespace App\Firewall;

	use ArrayObject;

	use Core as C;
	use Core\Exception as E;

	use Cli as Cli;

	use App\Firewall\Core;

	class Shell_Program_Firewall_Object_Address extends Shell_Program_Firewall_Object_Abstract
	{
		const OBJECT_NAME = 'address';

		const OBJECT_IDS = array(
			Core\Api_Host::OBJECT_TYPE,
			Core\Api_Subnet::OBJECT_TYPE,
			Core\Api_Network::OBJECT_TYPE
		);

		const OBJECT_KEYS = array(
			Core\Api_Host::OBJECT_TYPE => Core\Api_Host::OBJECT_KEY,
			Core\Api_Subnet::OBJECT_TYPE => Core\Api_Subnet::OBJECT_KEY,
			Core\Api_Network::OBJECT_TYPE => Core\Api_Network::OBJECT_KEY
		);

		const OBJECT_CLASSES = array(
			Core\Api_Host::OBJECT_TYPE => '\App\Firewall\Core\Api_Host',
			Core\Api_Subnet::OBJECT_TYPE => '\App\Firewall\Core\Api_Subnet',
			Core\Api_Network::OBJECT_TYPE => '\App\Firewall\Core\Api_Network'
		);

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Ipam
		  */
		protected $_ipamFwProgram;


		public function __construct(Cli\Shell\Main $SHELL, ArrayObject $objects)
		{
			parent::__construct($SHELL, $objects);

			$this->_ipamFwProgram = new Shell_Program_Firewall_Ipam();
		}

		public function insert($type, $name)
		{
			if($this->_typeIsAllowed($type))
			{
				$name = preg_replace('#(^\s+)|(\s+$)#i', '', $name);

				if(C\Tools::is('string&&!empty', $name))
				{
					$class = $this->_typeToClass($type);
					$objectName = ucfirst($class::OBJECT_NAME);

					if(!$this->objectExists($type, $name, true)) {
						$Core_Api_Address = new $class($name, $name);
						$this->_register($Core_Api_Address);
						return $Core_Api_Address;
					}
					else {
						throw new E\Message("Un ".$objectName." avec le même nom existe déjà", E_USER_WARNING);
					}
				}
			}

			return false;
		}

		public function create($type, array $args)
		{
			if($this->_typeIsAllowed($type))
			{
				if(isset($args[0]) && isset($args[1]))
				{
					$name = $args[0];
					$attr0 = $args[1];
					$attr1 = (isset($args[2])) ? ($args[2]) : (null);

					try {
						$Core_Api_Address = $this->insert($type, $name);
					}
					catch(\Exception $e) {
						$this->_SHELL->throw($e);
						$Core_Api_Address = null;
					}

					if($Core_Api_Address instanceof Core\Api_Address)
					{
						$objectName = ucfirst($Core_Api_Address::OBJECT_NAME);

						$status0 = $Core_Api_Address->configure($attr0);

						if($attr1 !== null) {
							$status1 = $Core_Api_Address->configure($attr1);
						}
						else {
							$status1 = true;
						}

						$isValid = $Core_Api_Address->isValid();

						if($status0 && $status1 && $isValid) {
							$this->_SHELL->print($objectName." '".$Core_Api_Address->name."' créé", 'green');
						}
						else {
							$this->_unregister($Core_Api_Address);
							$this->_SHELL->error($objectName." '".$Core_Api_Address->name."' invalide", 'red');
						}
					}
					elseif($Core_Api_Address === false) {			// Evite d'afficher ce message si une exception s'est produite
						$objectName = $this->getName($type);
						$this->_SHELL->error("Une erreur s'est produite durant la création d'un objet '".$objectName."'", 'orange');
					}

					return true;
				}
			}

			return false;
		}

		public function modify($type, array $args)
		{
			if(isset($args[0]) && isset($args[1]))
			{
				$name = $args[0];
				$attr0 = $args[1];
				$attr1 = (isset($args[2])) ? ($args[2]) : (null);

				if(($Core_Api_Address = $this->getObject($type, $name)) !== false)
				{
					$objectName = ucfirst($Core_Api_Address::OBJECT_NAME);

					$oldAttrV4 = $Core_Api_Address->attributeV4;
					$oldAttrV6 = $Core_Api_Address->attributeV6;

					$Core_Api_Address->reset($Core_Api_Address::FIELD_ATTRv4);
					$Core_Api_Address->reset($Core_Api_Address::FIELD_ATTRv6);

					$status_0 = $Core_Api_Address->configure($attr0);
					$status_1 = $Core_Api_Address->configure($attr1);
					$isValid = $Core_Api_Address->isValid();

					$status = ($status_0 && ($attr1 === null || $status_1) && $isValid);

					if($status)
					{
						$rules = $this->_objects[Core\Api_Rule::OBJECT_KEY];

						foreach($rules as $Core_Api_Rule)
						{
							$isPresent = $Core_Api_Rule->addressIsPresent($Core_Api_Address);

							if($isPresent)
							{
								try {
									$Core_Api_Rule->checkOverlapAddress();
								}
								catch(E\Message $e) {
									$this->_SHELL->error("RULE '".$Core_Api_Rule->name."': ".$e->getMessage(), 'orange');
								}

								/**
								  * Afficher seulement une alerte car les objets adresse sont différents mais l'adressage lui est identique
								  */
								if(($Core_Api_Address__like = $Core_Api_Rule->getAddressIsInUse($Core_Api_Address, true, $Core_Api_Address)) !== false) {
									$message = $Core_Api_Address__like::OBJECT_NAME." '".$Core_Api_Address__like->name."' possède un adressage identique";
									$this->_SHELL->error("RULE '".$Core_Api_Rule->name."': ".$message, 'red');
								}
							}
						}

						$this->_SHELL->print($objectName." '".$name."' modifié", 'green');
					}
					else {
						$Core_Api_Address->configure($oldAttrV4);
						$Core_Api_Address->configure($oldAttrV6);
						$this->_SHELL->print($objectName." '".$name."' n'a pas pu être mis à jour", 'orange');
					}
				}
				else {
					$objectName = $this->getName($type, true);
					$this->_SHELL->error($objectName." '".$name."' introuvable", 'orange');
				}

				return true;
			}

			return false;
		}

		public function rename($type, array $args)
		{
			if(isset($args[0]) && isset($args[1]))
			{
				$name = $args[0];
				$name = preg_replace('#(^\s+)|(\s+$)#i', '', $name);

				$newName = $args[1];
				$newName = preg_replace('#(^\s+)|(\s+$)#i', '', $newName);

				if(C\Tools::is('string&&!empty', $name) && C\Tools::is('string&&!empty', $newName))
				{
					if($name !== $newName)
					{
						if(($Core_Api_Address = $this->getObject($type, $name)) !== false)
						{
							$objectName = ucfirst($Core_Api_Address::OBJECT_NAME);
							$Core_Api_Address__new = $this->getObject($type, $newName, true);

							/**
							  * Si une adresse de même type avec le nouveau nom n'existe pas OU
							  * Si la même adresse correspond au nouveau nom: changement de case
							  */
							if($Core_Api_Address__new === false || $Core_Api_Address__new->_id_ === $Core_Api_Address->_id_)
							{
								$unregisterStatus = $this->_unregister($Core_Api_Address);

								if($unregisterStatus)
								{
									$renameIdStatus = $Core_Api_Address->id($newName);
									$renameNameStatus = $Core_Api_Address->name($newName);
									$registerStatus = $this->_register($Core_Api_Address);

									if($renameIdStatus && $renameNameStatus && $registerStatus)
									{
										$rules = $this->_objects[Core\Api_Rule::OBJECT_KEY];

										foreach($rules as $Core_Api_Rule)
										{
											$isPresent = $Core_Api_Rule->addressIsPresent($Core_Api_Address);

											if($isPresent) {
												$Core_Api_Rule->refresh();
											}
										}

										$this->_SHELL->print($objectName." '".$name."' renommé en '".$newName."'", 'green');
									}
									elseif(!$registerStatus) {		// /!\ Plus important que le renommage
										throw new Exception($objectName." '".$newName."' semble avoir été perdu", E_ERROR);		// Critical: do not use E\Message and E_USER_ERROR
									}
									else {
										throw new Exception($objectName." '".$newName."' n'a pas pu être renommé", E_ERROR);	// Critical: do not use E\Message and E_USER_ERROR
									}
								}
								else {
									throw new Exception($objectName." '".$newName."' semble être verrouillé", E_ERROR);			// Critical: do not use E\Message and E_USER_ERROR
								}
							}
							else {
								$this->_SHELL->error($objectName." '".$newName."' existe déjà", 'orange');
							}
						}
						else {
							$objectName = $this->getName($type, true);
							$this->_SHELL->error($objectName." '".$name."' n'existe pas", 'orange');
						}
					}
					else {
						$objectName = $this->getName($type, true);
						$this->_SHELL->print($objectName." '".$name."' est déjà correctement nommé", 'blue');
					}

					return true;
				}
			}

			return false;
		}

		public function remove($type, array $args)
		{
			if(isset($args[0]))
			{
				$name = $args[0];

				if(($Core_Api_Address = $this->getObject($type, $name)) !== false)
				{
					$rules = $this->_objects[Core\Api_Rule::OBJECT_KEY];

					foreach($rules as $Core_Api_Rule)
					{
						if($Core_Api_Rule->isPresent($Core_Api_Address)) {
							$this->_SHELL->error("Rule '".$Core_Api_Rule->name."' utilise cet object", 'orange');
							$isUsed = true;
							break;
						}
					}

					if(!isset($isUsed)) {
						$this->_unregister($Core_Api_Address);
						$objectName = ucfirst($Core_Api_Address::OBJECT_NAME);
						$this->_SHELL->print($objectName." '".$name."' supprimé", 'green');
					}
				}
				else {
					$objectName = $this->getName($type, true);
					$this->_SHELL->error($objectName." '".$name."' introuvable", 'orange');
				}

				return true;
			}

			return false;
		}

		public function locate($type, $search, $strict = false)
		{
			if($this->_typeIsAllowed($type))
			{
				$objectName = $this->getName($type, true);

				$Core_Api_Address = $this->getObject($type, $search, false, true);

				if($Core_Api_Address !== false)
				{
					$results = array();
					$rules = $this->_objects[Core\Api_Rule::OBJECT_KEY];

					foreach($rules as $ruleId => $rule)
					{
						$isInUse = $rule->isInUse($Core_Api_Address, $strict);

						if($isInUse) {
							$results[$ruleId] = $rule;
						}
					}

					if(count($results) > 0) {
						return $results;
					}
					else {
						$this->_SHELL->print("Aucune règle ne semble correspondre à cet objet ".$objectName, 'green');
					}
				}
				else {
					$this->_SHELL->error("L'objet ".$objectName." '".$search."' n'existe pas, impossible de réaliser la recherche", 'orange');
				}

				return true;
			}
			else {
				return false;
			}
		}

		public function filter($type, $filter, $strict = false)
		{
			if($filter === self::FILTER_DUPLICATES)
			{
				$key = $this->_typeToKey($type);

				if($key !== false)
				{
					$results = array();
					$runCache = array();
					$objects = $this->_objects[$key];

					foreach($objects as $addressId_a => $Firewall_Api_Address__a)
					{
						$runCache[] = $addressId_a;

						foreach($objects as $addressId_b => $Firewall_Api_Address__b)
						{
							/**
							  * /!\ La vérification (in_array) clé $addressId_b est correct!
							  */
							if(in_array($addressId_b, $runCache, true)) {
								continue;
							}
							else
							{
								if($Firewall_Api_Address__a->attributeV4 === $Firewall_Api_Address__b->attributeV4 &&
									$Firewall_Api_Address__a->attributeV6 === $Firewall_Api_Address__b->attributeV6)
								{
									$results[$addressId_a][] = $addressId_b;
								}
							}
						}
					}

					return $results;
				}
				else {
					return false;
				}
			}
			else {
				throw new Exception("Unknown filter '".$filter."'", E_USER_ERROR);
			}
		}

		public function refresh($type, array $args)
		{
			if(isset($args[0]))
			{
				$name = $args[0];
				$objectName = $this->getName($type, true);

				if(($Core_Api_Address = $this->getObject($type, $name)) !== false)
				{
					$status = false;
					$name = $Core_Api_Address->name;
					$objectName = ucfirst($Core_Api_Address::OBJECT_NAME);

					try {
						$status = $this->_refresh($type, $Core_Api_Address);
					}
					catch(E\Message $e) {
						$this->_SHELL->throw($e);
					}
					catch(\Exception $e) {
						$this->_SHELL->error("L'erreur suivante s'est produite: ".$e->getMessage(), 'orange');
					}

					if($status === false) {
						$this->_SHELL->print($objectName." '".$name."' n'a pas pu être actualisé", 'orange');
					}
				}
				else {
					$this->_SHELL->error($objectName." '".$name."' n'existe pas localement", 'orange');
				}

				return true;
			}
			else {
				return false;
			}
		}

		public function refreshAll($type)
		{
			$key = $this->_typeToKey($type);

			if($key !== false)
			{
				$objects = $this->_objects[$key];

				foreach($objects as $Core_Api_Address)
				{
					$status = null;
					$name = $Core_Api_Address->name;
					$objectName = ucfirst($Core_Api_Address::OBJECT_NAME);

					try {
						$status = $this->_refresh($type, $Core_Api_Address);
					}
					catch(E\Message $e) {
						$this->_SHELL->throw($e);
					}
					catch(\Exception $e) {
						$this->_SHELL->error("L'erreur suivante s'est produite: ".$e->getMessage(), 'orange');
					}

					if($status === false) {
						$this->_SHELL->print($objectName." '".$name."' n'a pas pu être actualisé", 'orange');
					}
				}

				return true;
			}
			else {
				return false;
			}
		}

		protected function _refresh($type, Core\Api_Address $addressApi)
		{
			$name = $addressApi->name;
			$Core_Api_Address__clone = clone $addressApi;
			$objectName = ucfirst($addressApi::OBJECT_NAME);

			$Core_Api_Address__ipam = $this->getIpamObjectApi($type, $name, true);

			if($Core_Api_Address__ipam === null) {
				throw new E\Message($objectName." '".$name."' introuvable dans l'IPAM", E_USER_WARNING);
			}
			elseif($Core_Api_Address__ipam === false) {
				throw new E\Message($objectName." '".$name."' est présent plus de 2 fois dans l'IPAM", E_USER_ERROR);
			}
			else
			{
				if($Core_Api_Address__ipam->name === $name)	// Sécurité
				{
					$IPvStatus = array(4 => null, 6 => null);
					$rules = $this->_objects[Core\Api_Rule::OBJECT_KEY];

					foreach($addressApi::FIELD_ATTRS as $IPv => $attribute)
					{
						$ipamAttribute = $Core_Api_Address__ipam->{$attribute};

						if($ipamAttribute !== null)
						{
							if($ipamAttribute !== $addressApi->{$attribute})
							{
								$addressApi->configure($ipamAttribute);
								$IPvStatus[$IPv] = true;

								foreach($rules as $Core_Api_Rule)
								{
									$isPresent = $Core_Api_Rule->addressIsPresent($addressApi);

									if($isPresent)
									{
										try {
											$Core_Api_Rule->checkOverlapAddress();
										}
										catch(E\Message $e) {
											$this->_SHELL->error("RULE '".$Core_Api_Rule->name."': ".$e->getMessage(), 'orange');
										}

										/**
										  * Afficher seulement une alerte car les objets adresse sont différents mais l'adressage lui est identique
										  */
										if(($Core_Api_Address = $Core_Api_Rule->getAddressIsInUse($addressApi, true, $addressApi)) !== false) {
											$message = $Core_Api_Address::OBJECT_NAME." '".$Core_Api_Address->name."' possède un adressage identique";
											$this->_SHELL->error("RULE '".$Core_Api_Rule->name."': ".$message, 'red');
										}
									}
								}
							}
						}
						elseif($addressApi->isIPv($IPv)) {
							$addressApi->reset($attribute);
							$IPvStatus[$IPv] = false;
						}
					}

					if($IPvStatus[4] === false) {
						$this->_SHELL->print($objectName." '".$name."': suppression IPv4 (".$Core_Api_Address__clone->attributeV4.")", 'orange');
					}
					elseif($IPvStatus[4] === true) {
						$this->_SHELL->print($objectName." '".$name."': mise à jour IPv4 (".$addressApi->attributeV4.")", 'green');
					}
					else {
						$this->_SHELL->print($objectName." '".$name."': IPv4 à jour (".$addressApi->attributeV4.")", 'blue');
					}

					if($IPvStatus[6] === false) {
						$this->_SHELL->print($objectName." '".$name."': suppression IPv6 (".$Core_Api_Address__clone->attributeV6.")", 'orange');
					}
					elseif($IPvStatus[6] === true) {
						$this->_SHELL->print($objectName." '".$name."': mise à jour IPv6 (".$addressApi->attributeV6.")", 'green');
					}
					else {
						$this->_SHELL->print($objectName." '".$name."': IPv6 à jour (".$addressApi->attributeV6.")", 'blue');
					}

					return true;
				}
				else {
					throw new E\Message($objectName." '".$name."' ne semble pas correspondre à l'objet retourné par l'IPAM", E_USER_ERROR);
				}
			}

			return false;
		}

		public function getLocalObjectApi($type, $arg, $strictKey = true)
		{
			$object = $this->getObject($type, $arg, $strictKey, true);
			return ($object !== false) ? ($object) : (null);
		}

		public function getIpamObjectApi($type, $arg, $strict = true)
		{
			//$this->_SHELL->print("Recherche IPAM '".$arg."'", 'blue');

			$results = $this->_ipamFwProgram->getObjects($type, $arg, $strict);		// Pas de try/catch afin de laisser le parent gérer de lui-même
			$class = $this->_typeToClass($type);

			if($class !== false)
			{
				switch(count($results))
				{
					case 0: {
						return null;
					}
					case 1:
					{
						/**
						  * On ne sait pas si le résultat est IPv4 ou IPv6, donc on essait de configurer les deux
						  * /!\ Le résultat doit comporter les deux éléments IPv4 et IPv6 même si seulement l'un des deux existe
						  */
						$Core_Api_Address = new $class($results[0]['name'], $results[0]['name'], $results[0][$class::FIELD_ATTRv4], $results[0][$class::FIELD_ATTRv6]);
						break;
					}
					case 2:
					{
						if($results[0]['name'] === $results[1]['name'])
						{
							$Core_Api_Address = new $class($results[0]['name'], $results[0]['name']);

							foreach($results as $result)
							{
								foreach($class::FIELD_ATTRS as $attribute)
								{
									if($result[$attribute] !== null) {
										$Core_Api_Address->configure($result[$attribute]);
									}
								}
							}

							break;
						}
						else {
							return false;
						}
					}
					default: {
						return false;
					}
				}

				/**
				  * When IPAM entry has empty name
				  * Use autonaming system instead
				  */
				if($Core_Api_Address->name === null)
				{
					$addressName = $this->getAutoNamingAddress($Core_Api_Address);

					if($addressName !== false) {
						$Core_Api_Address->id($addressName);
						$Core_Api_Address->name($addressName);
					}
					else {
						return false;
					}
				}

				return $Core_Api_Address;
			}
			else {
				return false;
			}
		}

		/**
		  * @param $type string Object type
		  * @param $arg string Object name or address
		  * @param $strictKey bool Strict key search mode
		  * @param $allowCreateFromAddress bool Allow to create object from address or not
		  * @throw Exception|Core\Exception\Message
		  * @return null|false|Core\Api_Address Return null if object can not be found, false if error occur or the object API instance found
		  */
		public function autoCreateObject($type, $arg, $strictKey = false, $allowCreateFromAddress = true)
		{
			if($this->_typeIsAllowed($type))
			{
				/**
				  * 1. On recherche l'objet qui correspond exactement, c'est à dire la clé doit correspondre (name)
				  * 2. Si aucun objet n'a été trouvé précédement alors on essaye de trouver un objet qui matcherait (ip)
				  */
				$Core_Api_Address = $this->getLocalObjectApi($type, $arg, true);

				if(!$strictKey && $Core_Api_Address === null) {
					$Core_Api_Address = $this->getLocalObjectApi($type, $arg, false);
				}

				if($Core_Api_Address === null)
				{
					$state = false;
					$Core_Api_Address = $this->getIpamObjectApi($type, $arg, true);

					if($Core_Api_Address === null)
					{
						if($allowCreateFromAddress)
						{
							$addressName = $this->getAutoNamingAddress($arg);

							if($addressName !== false)
							{
								$objectApiExists = $this->objectExists($type, $addressName);

								if(!$objectApiExists)
								{
									$Core_Api_Address = $this->insert($type, $addressName);

									if($Core_Api_Address !== false)
									{
										$status = $Core_Api_Address->configure($arg);

										if($status) {
											return $Core_Api_Address;
										}
										else {
											$this->_unregister($Core_Api_Address);
										}
									}
								}
							}
						}

						return null;
					}
					elseif($Core_Api_Address instanceof Core\Api_Address)
					{
						/**
						  * Si $arg est une adresse, et que dans l'IPAM deux objets existent avec le même nom
						  * alors localement cette adresse n'existe pas mais un objet avec ce nom, lui, peut exister
						  *
						  * Ne pas essayer d'utiliser la section de l'IPAM car tous les IPAM n'ont pas forcément une section
						  * /!\ C'est donc à l'utilisateur d'effectuer un refresh ou de créer manuellement l'objet adresse
						  *
						  * Vérifier aussi, dans le cas où l'objet existe et que $arg est une adresse (v4 ou v6),
						  * que ce n'est pas un ajout d'IP (v4 ou v6) réalisé après la création de l'objet dans l'outil
						  */
						$Core_Api_Address__local = $this->getObject($type, $Core_Api_Address->name);

						if($Core_Api_Address__local !== false)	// Un objet avec le même nom existe en local
						{
							if($Core_Api_Address__local->attributeV4 === $Core_Api_Address->attributeV4 && !$Core_Api_Address__local->isIPv6() && $Core_Api_Address->isIPv6()) {
								$Core_Api_Address__local->configure($Core_Api_Address->attributeV6);
								return $Core_Api_Address__local;
							}
							elseif($Core_Api_Address__local->attributeV6 === $Core_Api_Address->attributeV6 && !$Core_Api_Address__local->isIPv4() && $Core_Api_Address->isIPv4()) {
								$Core_Api_Address__local->configure($Core_Api_Address->attributeV4);
								return $Core_Api_Address__local;
							}
							else
							{
								$addressName = $this->getAutoNamingAddress($Core_Api_Address);

								if($addressName !== false)
								{
									$objectApiExists = $this->objectExists($type, $addressName);

									if(!$objectApiExists)
									{
										$this->_SHELL->error("Un objet en local existe déjà avec le même nom '".$Core_Api_Address->name."'", 'orange');
										$this->_SHELL->print("Le nom '".$addressName."' a été utilisé en substitution", 'green');

										if(!$Core_Api_Address->id($addressName) || !$Core_Api_Address->name($addressName)) {
											throw new E\Message("L'objet n'a pas pu être renommé en '".$addressName."'", E_USER_WARNING);
										}
									}
									else {
										throw new E\Message("Un objet en local existe déjà avec le même nom '".$Core_Api_Address->name."'", E_USER_WARNING);
									}
								}
								else {
									throw new Exception("Unable to auto-naming address object '".$Core_Api_Address->name."'", E_USER_ERROR);
								}
							}
						}

						if($Core_Api_Address instanceof Core\Api_Subnet) {
							$state = $this->_register($Core_Api_Address, false, true);
						}
						elseif($Core_Api_Address instanceof Core\Api_Host) {
							$state = $this->_register($Core_Api_Address, false, true);
						}
						else {
							throw new Exception("Return object '".get_class($Core_Api_Address)."' is not allowed", E_USER_ERROR);
						}

						if($state) {
							return $Core_Api_Address;
						}
						else {
							throw new Exception("Unable to register custom object from IPAM object(s)", E_USER_ERROR);
						}
					}
					elseif($Core_Api_Address !== false) {
						throw new Exception("Return type '".gettype($Core_Api_Address)."' is not allowed", E_USER_ERROR);
					}
				}
				elseif($Core_Api_Address instanceof Core\Api_Address) {
					return $Core_Api_Address;
				}
				elseif($Core_Api_Address !== false) {
					throw new Exception("Return type '".gettype($Core_Api_Address)."' is not allowed", E_USER_ERROR);
				}
			}

			return false;
		}

		/**
		  * @param string|App\Core\Api_Address $address
		  * @return false|string Address auto name
		  */
		public function getAutoNamingAddress($address)
		{
			/**
			  * Do not use - as separator because
			  * network address has it as separator
			  */
			if($address instanceof Core\Api_Address) {
				$address = $address->ipv4.'_'.$address->ipv6;
				$address = trim($address, '_');
				$isValid = true;
			}
			elseif(Core\Tools::isIP($address) || Core\Tools::isSubnet($address) || Core\Tools::isNetwork($address, Core\Api_Network::SEPARATOR)) {
				$isValid = true;
			}
			else {
				$isValid = false;
			}

			return ($isValid) ? ('AUTO_ADD__'.$address) : (false);
		}
	}