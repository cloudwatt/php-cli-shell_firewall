<?php
	namespace App\Firewall;

	use ArrayObject;

	use Core as C;
	use Core\Exception as E;

	use Cli as Cli;

	use App\Firewall\Core;

	class Shell_Program_Firewall_Object_Address extends Shell_Program_Firewall_Object_Abstract
	{
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

		protected function _getAddress($type, $name)
		{
			return $this->_getObject($type, $name);
		}

		public function locate($type, $search, $strict = false)
		{
			if($this->_typeIsAllowed($type))
			{
				$objectName = $this->typeToName($type, true);

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
						$this->_SHELL->print("Aucune règle ne semble correspondre à cet ".$objectName, 'green');
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

		public function refresh($type, array $args)
		{
			if(isset($args[0]))
			{
				$name = $args[0];

				if(($Core_Api_Address = $this->_getAddress($type, $name)) !== false)
				{
					$objectName = ucfirst($Core_Api_Address::OBJECT_NAME);

					try {
						$results = $this->_ipamFwProgram->getObjects($type, $name, true, false);
					}
					catch(Exception $e) {
						$this->_SHELL->error("L'erreur suivante s'est produite: ".$e->getMessage(), 'orange');
						$results = array();
					}

					switch(count($results))
					{
						case 0: {
							$this->_SHELL->error($objectName." '".$name."' introuvable dans l'IPAM", 'orange');
							break;
						}
						case 1:
						case 2:
						{
							$callable = array($Core_Api_Address, $Core_Api_Address::FIELD_ATTR_FCT);

							foreach($results as $result)
							{
								if($result[$Core_Api_Address::FIELD_NAME] === $name)	// Sécurité
								{
									foreach(array(4, 6) as $IPv)
									{
										$class = get_class($Core_Api_Address);
										$field = constant($class.'::FIELD_ATTRv'.$IPv);

										$attribute = $result[$field];

										if($attribute !== null)
										{
											if($attribute !== $Core_Api_Address->{$field})
											{
												$status = call_user_func($callable, $attribute);

												if($status) {
													$this->_SHELL->print($objectName." '".$name."' a été mis à jour: '".$attribute."'", 'green');
												}
												else {
													$this->_SHELL->print($objectName." '".$name."' n'a pas pu être mis à jour: '".$attribute."'", 'orange');
												}
											}
											else {
												$this->_SHELL->print($objectName." '".$name."' est déjà à jour pour '".$attribute."'", 'green');
											}
										}
										else {
											$this->_SHELL->print($objectName." '".$name."' ne possède pas d'adresse IPv".$IPv." dans l'IPAM", 'orange');
										}
									}
								}
							}

							break;
						}
						default: {
							$this->_SHELL->error($objectName." '".$name."' est présent plus de 2 fois dans l'IPAM", 'orange');
						}
					}
				}
				else {
					$objectName = $this->typeToName($type, true);
					$this->_SHELL->error($objectName." '".$name."' n'existe pas localement", 'orange');
				}

				return true;
			}

			return false;
		}

		public function refreshAll($type)
		{
			$key = $this->_typeToKey($type);

			if($key !== false)
			{
				$objects = $this->_objects[$key];

				foreach($objects as $Core_Api_Address) {
					$this->refresh($type, array($Core_Api_Address->name));
				}

				return true;
			}
			else {
				return false;
			}
		}

		public function create($type, array $args)
		{
			if($this->_typeIsAllowed($type))
			{
				if(isset($args[0]) && isset($args[1]))
				{
					$name = $args[0];
					$name = preg_replace('#(^\s+)|(\s+$)#i', '', $name);

					if(C\Tools::is('string&&!empty', $name))
					{
						$attr0 = $args[1];
						$attr1 = (isset($args[2])) ? ($args[2]) : (null);

						$class = $this->_typeToClass($type);
						$objectName = ucfirst($class::OBJECT_NAME);

						if(!$this->objectExists($type, $name, true))
						{
							$Core_Api_Address = new $class($name, $attr0, $attr1);
							$isValid = $Core_Api_Address->isValid();

							if($isValid) {
								$this->_register($Core_Api_Address);
								$this->_SHELL->print($objectName." '".$name."' créé", 'green');
							}
							else {
								$this->_SHELL->error($objectName." '".$name."' invalide", 'red');
							}
						}
						else {
							$this->_SHELL->error("Un ".$objectName." avec le même nom existe déjà", 'orange');
						}

						return true;
					}
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

				if(($Core_Api_Address = $this->_getAddress($type, $name)) !== false)
				{
					$objectName = ucfirst($Core_Api_Address::OBJECT_NAME);

					if($attr1 === null) {
						$Core_Api_Address->reset($Core_Api_Address::FIELD_ATTRv4);
						$Core_Api_Address->reset($Core_Api_Address::FIELD_ATTRv6);
					}

					$status_0 = call_user_func(array($Core_Api_Address, $Core_Api_Address::FIELD_ATTR_FCT), $attr0);
					$status_1 = call_user_func(array($Core_Api_Address, $Core_Api_Address::FIELD_ATTR_FCT), $attr1);
					$isValid = $Core_Api_Address->isValid();

					if(($status_0 || $status_1) && $isValid) {
						$this->_SHELL->print($objectName." '".$name."' modifié", 'green');
					}
					elseif($isValid) {
						$this->_SHELL->print($objectName." '".$name."' n'a pas pu être mis à jour", 'orange');
					}
					else {
						$this->_unregister($Core_Api_Address);
						$this->_SHELL->error($objectName." '".$name."' invalide", 'red');
					}
				}
				else {
					$objectName = $this->typeToName($type, true);
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
					if(($Core_Api_Address = $this->_getAddress($type, $name)) !== false)
					{
						$objectName = ucfirst($Core_Api_Address::OBJECT_NAME);

						if(!$this->objectExists($type, $newName, true))
						{
							$this->_unregister($Core_Api_Address);
							$Core_Api_Address->name($newName);
							$this->_register($Core_Api_Address);

							$rules = $this->_objects[Core\Api_Rule::OBJECT_KEY];

							foreach($rules as $ruleId => $rule)
							{
								$isInUse = $rule->isInUse($Core_Api_Address);

								if($isInUse) {
									$rule->refresh();
								}
							}

							$this->_SHELL->print($objectName." '".$name."' renommé en '".$newName."'", 'green');
						}
						else {
							$this->_SHELL->error($objectName." '".$newName."' existe déjà", 'orange');
						}
					}
					else {
						$objectName = $this->typeToName($type, true);
						$this->_SHELL->error($objectName." '".$name."' introuvable", 'orange');
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

				if(($Core_Api_Address = $this->_getAddress($type, $name)) !== false)
				{
					$rules = $this->_objects[Core\Api_Rule::OBJECT_KEY];

					foreach($rules as $ruleObject)
					{
						if($ruleObject->isPresent($Core_Api_Address)) {
							$this->_SHELL->error("Rule '".$ruleObject->name."' utilise cet object", 'orange');
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
					$objectName = $this->typeToName($type, true);
					$this->_SHELL->error($objectName." '".$name."' introuvable", 'orange');
				}

				return true;
			}

			return false;
		}

		public function filter($type, $filter)
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
					case 1: {
						return new $class($results[0]['name'], $results[0][$class::FIELD_ATTRv4], $results[0][$class::FIELD_ATTRv6]);
					}
					case 2:
					{
						if($results[0]['name'] === $results[1]['name'])
						{
							$name = $results[0]['name'];
							$Core_Api_Address = new $class($results[0]['name']);

							$attributes = $class::FIELD_ATTRS;

							foreach($results as $result)
							{
								foreach($attributes as $attribute)
								{
									if($result[$attribute] !== null) {
										$callable = array($Core_Api_Address, $class::FIELD_ATTR_FCT);
										call_user_func($callable, $result[$attribute]);
									}
								}
							}

							return $Core_Api_Address;
						}
						else {
							return false;
						}
					}
					default: {
						return false;
					}
				}
			}
			else {
				return false;
			}
		}

		/**
		  * @param $type string Object type
		  * @param $arg string Object name or address
		  * @param $strictKey bool Strict key search mode
		  * @return null|false|Core\Api_Address Return null if object can not be found, false if error occur or the object API instance found
		  */
		public function autoCreateObject($type, $arg, $strictKey = false)
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
					
					if($Core_Api_Address === null || $Core_Api_Address === false) {
						return $Core_Api_Address;
					}
					elseif($Core_Api_Address instanceof Core\Api_Abstract)
					{
						/**
						  * Si $arg est une adresse, et que dans l'IPAM deux objets existent avec le même nom
						  * alors localement cette adresse n'existe pas mais localement un objet avec ce nom existe
						  *
						  * /!\ C'est à l'utilisateur d'effectuer un refresh ou de créer manuellement l'objet
						  */
						$objectApiExists = $this->objectExists($type, $Core_Api_Address->name);

						if(!$objectApiExists)
						{
							if($Core_Api_Address instanceof Core\Api_Subnet) {
								$state = $this->_register($Core_Api_Address, true);
							}
							elseif($Core_Api_Address instanceof Core\Api_Host) {
								$state = $this->_register($Core_Api_Address, true);
							}
							else {
								throw new Exception("Return object '".get_class($Core_Api_Address)."' is not allowed", E_USER_ERROR);
							}
						}
						else {
							throw new E\Message("Un objet en local existe déjà avec le même nom '".$Core_Api_Address->name."'", E_USER_WARNING);
						}
					}
					else {
						throw new Exception("Return type '".gettype($Core_Api_Address)."' is not allowed", E_USER_ERROR);
					}

					if($state && $Core_Api_Address !== false) {
						return $Core_Api_Address;
					}
					else {
						throw new Exception("Unable to create custom object from IPAM object(s)", E_USER_ERROR);
					}
				}
				elseif($Core_Api_Address !== false) {
					return $Core_Api_Address;
				}
			}

			return false;
		}
	}