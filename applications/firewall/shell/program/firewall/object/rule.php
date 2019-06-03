<?php
	namespace App\Firewall;

	use ArrayObject;

	use Core as C;
	use Core\Exception as E;

	use Cli as Cli;

	use App\Firewall\Core;

	class Shell_Program_Firewall_Object_Rule extends Shell_Program_Firewall_Object_Abstract
	{
		const OBJECT_NAME = 'rule';

		const RULE_NAME_MODE_AUTO = true;

		const OBJECT_IDS = array(
			Core\Api_Rule::OBJECT_TYPE
		);

		const OBJECT_KEYS = array(
			Core\Api_Rule::OBJECT_TYPE => Core\Api_Rule::OBJECT_KEY
		);

		const OBJECT_CLASSES = array(
			Core\Api_Rule::OBJECT_TYPE => 'App\Firewall\Core\Api_Rule'
		);

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Object_Address
		  */
		protected $_addressFwProgram;

		/**
		  * @var App\Firewall\Core\Api_Rule
		  */
		protected $_editingRuleApi = null;

		/**
		  * @var string
		  */
		protected $_terminalShellPrompt = '';


		public function __construct(Cli\Shell\Main $SHELL, ArrayObject $objects)
		{
			parent::__construct($SHELL, $objects);

			$this->_addressFwProgram = new Shell_Program_Firewall_Object_Address($this->_SHELL, $this->_objects);
		}

		public function isEditingRule()
		{
			return $this->_isEditingRule(false);
		}

		public function getEditingRuleType()
		{
			return ($this->isEditingRule()) ? ($this->_editingRuleApi::OBJECT_TYPE) : (false);
		}

		public function getEditingRuleName()
		{
			return ($this->isEditingRule()) ? ($this->_editingRuleApi->name) : (false);
		}

		protected function _isEditingRule($printError = true)
		{
			if($this->_editingRuleApi === null)
			{
				if($printError) {
					$this->_SHELL->error("Merci de rentrer dans le mode d'édition de règle au préalable ('create rule', 'modify rule' ou 'clone rule')", 'orange');
				}

				return false;
			}
			else {
				return true;
			}
		}

		protected function _getEditingRule()
		{
			return ($this->_isEditingRule(true)) ? ($this->_editingRuleApi) : (false);
		}

		protected function _matchEditingRule($name)
		{
			return ($this->_isEditingRule(false)) ? ($this->_editingRuleApi->name === $name) : (false);
		}

		/**
		  * /!\ Publique, doit accepter un ID "humain"
		  * @return false|mixed Name
		  */
		public static function normalizeName($name)
		{
			if(self::RULE_NAME_MODE_AUTO && C\Tools::is('int&&>0', $name)) {
				return ($name-1);
			}

			return parent::normalizeName($name);
		}

		/**
		  * /!\ Protégée, doit accepter un ID "machine"
		  * @return false|mixed Name
		  */
		protected static function _normalizeName($name)
		{
			if(self::RULE_NAME_MODE_AUTO && C\Tools::is('int&&>=0', $name)) {
				return ($name+1);
			}

			return parent::normalizeName($name);
		}

		public function getNextName($type = Core\Api_Rule::OBJECT_TYPE)
		{
			$key = $this->_typeToKey($type);
			$name = $this->_nextRuleId($key);
			return $this->_normalizeName($name);
		}

		protected function _nextRuleId($key)
		{
			$id = 0;
			$counter = count($this->_objects[$key]);

			if(self::RULE_NAME_MODE_AUTO)
			{
				$keys = array_keys($this->_objects[$key]);

				foreach($keys as $key)
				{
					if(C\Tools::is('int&&>=0', $key)) {
						$id = (max($id, $key) + 1);
					}
				}
			}

			return max($id, $counter);
		}

		public function insert($type, $name = null, $category = null)
		{
			return $this->_insert($type, $name, $category, false);
		}

		protected function _insert($type, $name = null, $category = null, $enterEditingMode = false)
		{
			if($this->_typeIsAllowed($type))
			{
				$key = $this->_typeToKey($type);

				if(self::RULE_NAME_MODE_AUTO && $name === null) {
					$name = $this->_nextRuleId($key);
					$name = $this->_normalizeName($name);
				}

				if($name !== null)
				{
					if(!$this->objectExists($type, $name))
					{
						$class = $this->_typeToClass($type);

						switch(true)
						{
							case ($category === null):
							case ($category === Core\Api_Rule::CATEG_MONOSITE):
							case ($category === Core\Api_Rule::CATEG_FAILOVER): {
								$Core_Api_Rule = new $class($name, $name, $category);
								break;
							}
							default: {
								throw new E\Message("Cette catégorie de règle '".$category."' n'est pas valide", E_USER_ERROR);
							}
						}

						$this->_register($Core_Api_Rule);

						if($enterEditingMode) {
							$this->_editingRuleApi = $Core_Api_Rule;
						}

						return $Core_Api_Rule;
					}
					else {
						throw new E\Message("Une règle avec le même nom '".$name."' existe déjà", E_USER_ERROR);
					}
				}
				else {
					throw new E\Message("Merci de préciser le nom de la règle", E_USER_ERROR);
				}
			}

			return false;
		}

		public function create($type, array $args)
		{
			if(isset($args[0]))
			{
				$category = $args[0];

				if(self::RULE_NAME_MODE_AUTO || isset($args[1]))
				{
					$name = (isset($args[1])) ? ($args[1]) : (null);

					try {
						$Core_Api_Rule = $this->_insert($type, $name, $category, true);
					}
					catch(\Exception $e) {
						$this->_SHELL->throw($e);
						$Core_Api_Rule = null;
					}

					if($Core_Api_Rule instanceof Core\Api_Rule_Interface)
					{
						$this->_SHELL->deleteWaitingMsg();		// Garanti la suppression du message

						if(!$this->isEditingRule()) {
							$this->_terminalShellPrompt = $this->_TERMINAL->getShellPrompt();
						}

						$name = $Core_Api_Rule->name;			// En mode auto, permet de récupérer le nom de la règle
						$objectName = mb_strtoupper($Core_Api_Rule::OBJECT_NAME);
						$this->_TERMINAL->setShellPrompt($objectName.' ('.$category.') ['.$name.']');
					}
					elseif($Core_Api_Rule === false) {			// Evite d'afficher ce message si une exception s'est produite
						$this->_SHELL->error("Une erreur s'est produite durant la création d'une règle", 'orange');
					}

					return true;
				}
				else {
					$this->_SHELL->error("Merci de préciser le nom de la règle", 'orange');
				}
			}

			return false;
		}

		public function clone($type, array $args)
		{
			if($this->_typeIsAllowed($type))
			{
				if(isset($args[0]))
				{
					$srcName = $args[0];

					if(self::RULE_NAME_MODE_AUTO || isset($args[1]))
					{
						$dstName = (isset($args[1])) ? ($args[1]) : (null);

						if(($Core_Api_Rule = $this->getObject($type, $srcName)) !== false)
						{
							if($dstName === null || !$this->objectExists($type, $dstName))
							{
								$Core_Api_Rule = clone $Core_Api_Rule;
								// /!\ Ne pas garder le timestamp afin d'éviter à l'utilisateur de confondre les règles après le clonage

								$ruleCategory = $Core_Api_Rule->category;

								if($dstName === null) {
									$key = $this->_typeToKey($type);
									$dstName = $this->_nextRuleId($key);
									$dstName = $this->_normalizeName($dstName);
								}

								$Core_Api_Rule->id($dstName);
								$Core_Api_Rule->name($dstName);
								$this->_register($Core_Api_Rule);
								$this->_editingRuleApi = $Core_Api_Rule;

								$this->_SHELL->deleteWaitingMsg();		// Garanti la suppression du message

								if(!$this->isEditingRule()) {
									$this->_terminalShellPrompt = $this->_TERMINAL->getShellPrompt();
								}

								$objectName = mb_strtoupper($Core_Api_Rule::OBJECT_NAME);
								$this->_TERMINAL->setShellPrompt($objectName.' ('.$ruleCategory.') ['.$dstName.']');
							}
							else {
								$this->_SHELL->error("Une règle avec le même nom '".$dstName."' existe déjà", 'orange');
							}
						}
						else {
							$this->_SHELL->error("La règle '".$srcName."' n'existe pas", 'orange');
						}

						return true;
					}
					else {
						$this->_SHELL->error("Merci de préciser le nom de la règle", 'orange');
					}
				}
			}

			return false;
		}

		/**
		  * @param App\Firewall\Core\Api_Abstract $Core_Api_Abstract
		  * @param array $object
		  * @return bool
		  * @throw Core\Exception\Message
		  */
		protected function _wakeup(Core\Api_Abstract $Core_Api_Abstract, array $object)
		{
			$status = $Core_Api_Abstract->wakeup($object);

			if($status)
			{
				foreach(array('source' => 'sources', 'destination' => 'destinations') as $attribute => $attributes)
				{
					if(array_key_exists($attributes, $object))
					{
						foreach($object[$attributes] as $Core_Api_Address)
						{
							$status = $Core_Api_Abstract->configure($attribute, $Core_Api_Address);

							if(!$status) {
								throw new E\Message("Impossible d'ajouter l'adresse '".$Core_Api_Address->name."' à la règle '".$Core_Api_Abstract->name."'", E_USER_ERROR);
							}
						}
					}
				}

				return true;
			}
			else {
				return false;
			}
		}

		public function update($type, $name)
		{
			return $this->_update($type, $name, false);
		}

		protected function _update($type, $name, $enterEditingMode = false)
		{
			if($this->_typeIsAllowed($type))
			{
				if(!$this->_matchEditingRule($name))
				{
					if(($Core_Api_Rule = $this->getObject($type, $name)) !== false)
					{
						if($enterEditingMode) {
							$this->_editingRuleApi = $Core_Api_Rule;
						}

						return $Core_Api_Rule;
					}
					else {
						throw new E\Message("La règle '".$name."' n'existe pas", E_USER_WARNING);
					}
				}
				else {
					throw new E\Message("La règle '".$name."' est déjà en cours d'édition", E_USER_WARNING);
				}
			}

			return false;
		}

		public function modify($type, array $args)
		{
			if(isset($args[0]))
			{
				$name = $args[0];

				try {
					$Core_Api_Rule = $this->_update($type, $name, true);
				}
				catch(\Exception $e) {
					$this->_SHELL->throw($e);
					$Core_Api_Rule = null;
				}

				if($Core_Api_Rule instanceof Core\Api_Rule_Interface)
				{
					$category = $Core_Api_Rule->category;

					$this->_SHELL->deleteWaitingMsg();		// Garanti la suppression du message

					if(!$this->isEditingRule()) {
						$this->_terminalShellPrompt = $this->_TERMINAL->getShellPrompt();
					}

					$objectName = mb_strtoupper($Core_Api_Rule::OBJECT_NAME);
					$this->_TERMINAL->setShellPrompt($objectName.' ('.$category.') ['.$name.']');
				}
				elseif($Core_Api_Rule === false) {			// Evite d'afficher ce message si une exception s'est produite
					$this->_SHELL->error("Une erreur s'est produite durant la modification d'une règle", 'orange');
				}

				return true;
			}

			return false;
		}

		public function replace($type, $badType, $badName, $newType, $newName)
		{
			if($this->_typeIsAllowed($type))
			{
				if($this->_addressFwProgram->isType($badType) && $this->_addressFwProgram->isType($newType))
				{
					$Core_Api_Address__bad = $this->_addressFwProgram->getObject($badType, $badName, true);
					$Core_Api_Address__new = $this->_addressFwProgram->getObject($newType, $newName, true);

					if($Core_Api_Address__bad === false) {
						$objectName = $this->_addressFwProgram->getName($badType);
						$this->_SHELL->error("L'objet '".$badName."' de type '".$objectName."' semble ne pas exister", 'orange');
					}
					elseif($Core_Api_Address__new === false) {
						$objectName = $this->_addressFwProgram->getName($newType);
						$this->_SHELL->error("L'objet '".$newName."' de type '".$objectName."' semble ne pas exister", 'orange');
					}
					else
					{
						$counter = 0;
						$key = $this->_typeToKey($type);

						foreach($this->_objects[$key] as $Core_Api_Rule)
						{
							$newAddressApiIsPresent = $Core_Api_Rule->addressIsPresent($Core_Api_Address__new);
							$status = $Core_Api_Rule->replace($Core_Api_Address__bad, $Core_Api_Address__new, $counter);

							if($status && $newAddressApiIsPresent) {
								$message = "l'objet '".$Core_Api_Address__bad::OBJECT_NAME."' '".$Core_Api_Address__bad->name."' a été supprimé car ";
								$message .= "l'objet '".$Core_Api_Address__new::OBJECT_NAME."' '".$Core_Api_Address__new->name."' était déjà présent";
								$this->_SHELL->error("RULE '".$Core_Api_Rule->name."': ".$message, 'red');
							}
						}

						if($counter === 1) {
							$this->_SHELL->print("1 règle a été mise à jour", 'green');
						}
						elseif($counter > 1) {
							$this->_SHELL->print($counter." règles ont été mises à jour", 'green');
						}
						else {
							$this->_SHELL->error("Aucune règle n'a été mise à jour", 'orange');
						}
					}

					return true;
				}
			}

			return false;
		}

		public function move(Core\Api_Abstract $objectApi, $newName)
		{
			return $this->_rename($objectApi, null, $newName, true);
		}

		public function appoint($type, $name, $newName)
		{
			return $this->_rename($type, $name, $newName, false);
		}

		protected function _rename($typeOrObjectApi, $name, $newName, $checkInstance)
		{
			if($typeOrObjectApi instanceof Core\Api_Rule_Interface) {
				$type = $typeOrObjectApi::OBJECT_TYPE;
				$name = $typeOrObjectApi->name;
				$Core_Api_Rule = $typeOrObjectApi;
				$checkPresence = true;
				//$checkInstance = true;	// @todo laisser le choix ou le forcer par sécurité?
			}
			else {
				$type = $typeOrObjectApi;
				$checkPresence = false;
				$checkInstance = false;
			}

			if($this->_typeIsAllowed($type) && $name !== null)
			{
				if(!$this->_matchEditingRule($name))
				{
					if($name !== $newName)
					{
						if(!isset($Core_Api_Rule) && ($Core_Api_Rule = $this->getObject($type, $name)) === false) {
							throw new E\Message("La règle '".$name."' n'existe pas", E_USER_WARNING);
						}

						if(!$checkPresence || $this->objectExists($type, $name))
						{
							$Core_Api_Rule__new = $this->getObject($type, $newName, true);

							/**
							  * Si une règle de même type avec le nouveau nom n'existe pas OU
							  * Si la même règle correspond au nouveau nom: changement de case
							  */
							if($Core_Api_Rule__new === false || $Core_Api_Rule__new->_id_ === $Core_Api_Rule->_id_)
							{
								$unregisterStatus = $this->_unregister($Core_Api_Rule, false, $checkInstance);

								if($unregisterStatus)
								{
									$renameIdStatus = $Core_Api_Rule->id($newName);
									$renameNameStatus = $Core_Api_Rule->name($newName);
									$registerStatus = $this->_register($Core_Api_Rule);

									if(!$registerStatus) {		// /!\ Plus important que le renommage
										throw new Exception("La règle '".$newName."' semble avoir été perdue", E_ERROR);		// Critical: do not use E\Message and E_USER_ERROR
									}
									elseif(!$renameIdStatus || !$renameNameStatus) {
										throw new Exception("La règle '".$newName."' n'a pas pu être renommée", E_ERROR);		// Critical: do not use E\Message and E_USER_ERROR
									}
								}
								else {
									throw new Exception("La règle '".$newName."' semble être verrouillée", E_ERROR);			// Critical: do not use E\Message and E_USER_ERROR
								}
							}
							else {
								throw new E\Message("La règle '".$newName."' existe déjà", E_USER_WARNING);
							}
						}
						else {
							throw new E\Message("La règle '".$name."' n'existe pas", E_USER_WARNING);
						}
					}
					else {
						throw new E\Message("La règle '".$name."' est déjà correctement nommée", E_USER_NOTICE);
					}

					return true;
				}
				else {
					throw new E\Message("Impossible de renommer une règle en cours d'édition", E_USER_WARNING);
				}
			}
			else {
				throw new E\Message("Impossible de renommer la règle (type or name are not valid)", E_USER_ERROR);
			}

			return false;
		}

		public function rename($type, array $args)
		{
			if(isset($args[0]) && isset($args[1]))
			{
				$oldName = $args[0];
				$newName = $args[1];

				try {
					$status = $this->_rename($type, $oldName, $newName, false);
				}
				catch(\Exception $e) {
					$this->_SHELL->throw($e);
					$status = null;
				}

				if($status === true) {
					$this->_SHELL->print("Règle '".$oldName."' renommée en '".$newName."'", 'green');
				}
				elseif($status === false) {
					$this->_SHELL->error("Impossible de renommer la règle '".$oldName."'", 'orange');
				}

				return true;
			}

			return false;
		}

		public function drop(Core\Api_Abstract $objectApi, $checkInstance = false)
		{
			return $this->_delete($objectApi, null, $checkInstance);
		}

		public function delete($type, $name)
		{
			return $this->_delete($type, $name, false);
		}

		protected function _delete($typeOrObjectApi, $name = null, $checkInstance = false)
		{
			if($typeOrObjectApi instanceof Core\Api_Rule_Interface) {
				$type = $typeOrObjectApi::OBJECT_TYPE;
				$name = $typeOrObjectApi->name;
				$Core_Api_Rule = $typeOrObjectApi;
				$checkPresence = true;
				//$checkInstance = true;	// @todo laisser le choix ou le forcer par sécurité?
			}
			else {
				$type = $typeOrObjectApi;
				$checkPresence = false;
				$checkInstance = false;
			}

			if($this->_typeIsAllowed($type) && $name !== null)
			{
				if(!$this->_matchEditingRule($name))
				{
					if(!isset($Core_Api_Rule) && ($Core_Api_Rule = $this->getObject($type, $name)) === false) {
						throw new E\Message("La règle '".$name."' n'existe pas", E_USER_WARNING);
					}

					if(!$checkPresence || $this->objectExists($type, $name)) {
						return $this->_unregister($Core_Api_Rule, false, $checkInstance);
					}
					else {
						throw new E\Message("La règle '".$name."' n'existe pas", E_USER_WARNING);
					}
				}
				else {
					throw new E\Message("Impossible de supprimer une règle en cours d'édition", E_USER_WARNING);
				}
			}
			else {
				throw new E\Message("Impossible de supprimer la règle (type or name are not valid)", E_USER_ERROR);
			}
		}

		public function remove($type, array $args)
		{
			if(isset($args[0]))
			{
				$name = $args[0];

				try {
					$status = $this->_delete($type, $name);
				}
				catch(\Exception $e) {
					$this->_SHELL->throw($e);
					$status = null;
				}

				if($status === true) {
					$this->_SHELL->print("Règle '".$name."' supprimée!", 'green');
				}
				elseif($status === false) {
					$this->_SHELL->error("Impossible de supprimer la règle '".$name."'", 'orange');
				}

				return true;
			}

			return false;
		}

		public function clear($type)
		{
			$this->exit();
			return parent::clear($type);
		}

		public function locate($type, $search, $strict = false)
		{
			if($this->_typeIsAllowed($type))
			{
				$results = array();
				$key = $this->_typeToKey($type);

				foreach($this->_objects[$key] as $ruleId => $Core_Api_Rule)
				{
					if($Core_Api_Rule->match($search, $strict)) {
						$results[$ruleId] = $Core_Api_Rule;
					}
				}

				if(count($results) > 0) {
					return $results;
				}
				else {
					$this->_SHELL->print("Aucune règle ne semble correspondre à cette recherche", 'green');
				}

				return true;
			}
			else {
				return false;
			}
		}

		public function locateFlow($type, array $args, $strict = false)
		{
			if($this->_typeIsAllowed($type))
			{
				if(count($args) >= 6)
				{
					$srcAddress = $args[1];
					$dstAddress = $args[3];
					$protocol = $args[5];

					$Core_Api_Address__src = Core\Api_Address::factory($srcAddress);
					$Core_Api_Address__dst = Core\Api_Address::factory($dstAddress);

					if($Core_Api_Address__src !== false && $Core_Api_Address__src->isValid() &&
						$Core_Api_Address__dst !== false && $Core_Api_Address__dst->isValid())
					{
						if(isset($args[6])) {
							$protocol .= Core\Api_Protocol::PROTO_SEPARATOR.$args[6];
						}

						$Core_Api_Protocol = new Core\Api_Protocol($protocol, $protocol);
						$status = $Core_Api_Protocol->protocol($protocol);

						if($status && $Core_Api_Protocol->isValid())
						{
							$time1 = microtime(true);
							$this->_SHELL->print("Recherche d'un flow...", 'orange');

							$results = array();
							$key = $this->_typeToKey($type);

							foreach($this->_objects[$key] as $ruleId => $Core_Api_Rule)
							{
								if($Core_Api_Rule->addressIsInUse($Core_Api_Address__src, false) &&
									$Core_Api_Rule->addressIsInUse($Core_Api_Address__dst, false) &&
									$Core_Api_Rule->protocolIsInUse($Core_Api_Protocol, false))
								{
									$results[$ruleId] = $Core_Api_Rule;
								}
							}

							$time2 = microtime(true);
							$this->_TERMINAL->deleteMessage(1, true);
							$this->_SHELL->print("Recherche d'un flow (".round($time2-$time1)."s) [OK]", 'green');

							if(count($results) > 0) {
								return $results;
							}
							else {
								$this->_SHELL->print("Aucune règle ne semble correspondre à ce flow", 'green');
							}

							return true;
						}
					}
				}
			}

			return false;
		}

		public function filter($type, $filter, $strict = false)
		{
			if($this->_typeIsAllowed($type))
			{
				if($filter === self::FILTER_DUPLICATES)
				{
					$results = array();
					$runCache = array();

					$time1 = microtime(true);
					$this->_SHELL->print("Vérification des doublons ...", 'orange');

					$key = $this->_typeToKey($type);

					foreach($this->_objects[$key] as $ruleId_a => $Firewall_Api_Rule__a)
					{
						$runCache[] = $ruleId_a;

						foreach($this->_objects[$key] as $ruleId_b => $Firewall_Api_Rule__b)
						{
							/**
							  * /!\ La vérification (in_array) clé $ruleId_b est correct!
							  */
							if(in_array($ruleId_b, $runCache, true)) {
								continue;
							}
							else
							{
								$filterSrcDst = function($address_a, $address_b)
								{
									if($address_a->attributeV4 === $address_b->attributeV4 && $address_a->attributeV6 === $address_b->attributeV6) {
										return 0;
									}
									else {
										return strnatcasecmp($address_a->name, $address_b->name);
									}
								};

								$diffSrcA = array_udiff($Firewall_Api_Rule__a->sources, $Firewall_Api_Rule__b->sources, $filterSrcDst);

								if(count($diffSrcA) > 0) {
									continue;
								}

								$diffSrcB = array_udiff($Firewall_Api_Rule__b->sources, $Firewall_Api_Rule__a->sources, $filterSrcDst);

								if(count($diffSrcB) > 0) {
									continue;
								}

								$diffDstA = array_udiff($Firewall_Api_Rule__a->destinations, $Firewall_Api_Rule__b->destinations, $filterSrcDst);

								if(count($diffDstA) > 0) {
									continue;
								}

								$diffDstB = array_udiff($Firewall_Api_Rule__b->destinations, $Firewall_Api_Rule__a->destinations, $filterSrcDst);

								if(count($diffDstB) > 0) {
									continue;
								}

								$filterProto = function($protocol_a, $protocol_b)
								{
									if($protocol_a->protocol === $protocol_b->protocol) {
										return 0;
									}
									else {
										return strnatcasecmp($protocol_a->name, $protocol_b->name);
									}
								};

								$diffProtoA = array_udiff($Firewall_Api_Rule__a->protocols, $Firewall_Api_Rule__b->protocols, $filterProto);

								if(count($diffProtoA) > 0) {
									continue;
								}

								$diffProtoB = array_udiff($Firewall_Api_Rule__b->protocols, $Firewall_Api_Rule__a->protocols, $filterProto);

								if(count($diffProtoB) > 0) {
									continue;
								}

								$results[$ruleId_a][] = $ruleId_b;
							}
						}
					}

					$time2 = microtime(true);
					$this->_TERMINAL->deleteMessage(1, true);
					$this->_SHELL->print("Vérification des doublons (".round($time2-$time1)."s) [OK]", 'green');

					return $results;
				}
				else {
					throw new Exception("Unknown filter '".$filter."'", E_USER_ERROR);
				}
			}
			else {
				return false;
			}
		}

		public function filterFlow($type, $filter, $strict = false)
		{
			if($this->_typeIsAllowed($type))
			{
				if($filter === self::FILTER_DUPLICATES)
				{
					$flows = array();
					$results = array();

					$time1 = microtime(true);
					$this->_SHELL->print("Inventaire des flows ...", 'orange');

					$key = $this->_typeToKey($type);

					foreach($this->_objects[$key] as $ruleId => $Firewall_Api_Rule)
					{
						foreach($Firewall_Api_Rule->sources as $Core_Api_Address__src)
						{
							foreach($Firewall_Api_Rule->destinations as $Core_Api_Address__dst)
							{
								foreach($Firewall_Api_Rule->protocols as $Core_Api_Protocol)
								{
									$flows[] = new ArrayObject(array(
										'ruleId' => $ruleId,
										'ruleName' => $Firewall_Api_Rule->name,
										'source' => $Core_Api_Address__src,
										'destination' => $Core_Api_Address__dst,
										'protocol' => $Core_Api_Protocol
									), ArrayObject::ARRAY_AS_PROPS);
								}
							}
						}
					}

					$time2 = microtime(true);
					$this->_TERMINAL->deleteMessage(1, true);
					$this->_SHELL->print("Inventaire des flows (".round($time2-$time1)."s) [OK]", 'green');
					$this->_SHELL->print("Vérification doublons ...", 'orange');

					foreach($flows as $index_a => $flow_a)
					{
						$this->_TERMINAL->deleteMessage(1, true);
						$this->_SHELL->print("Vérification doublons ... (RULE '".$flow_a->ruleName."')...", 'orange');

						foreach($flows as $index_b => $flow_b)
						{
							if($index_a === $index_b) {
								continue;
							}
							else
							{
								/**
								  * /!\ A peut ne pas inclure B mais B peut inclure A
								  * donc toujours effectuer les tests pour les 2 combinaisons
								  */
								$srcStatus = $flow_a->source->includes($flow_b->source);
								$dstStatus = $flow_a->destination->includes($flow_b->destination);
								$protoStatus = $flow_a->protocol->includes($flow_b->protocol);

								if($srcStatus && $dstStatus && $protoStatus &&
									(!array_key_exists($flow_b->ruleId, $results) || !in_array($flow_a->ruleId, $results[$flow_b->ruleId], true)))
								{
									$results[$flow_a->ruleId][] = $flow_b->ruleId;
								}
							}
						}
					}

					$time3 = microtime(true);
					$this->_TERMINAL->deleteMessage(1, true);
					$this->_SHELL->print("Vérification doublons (".round($time3-$time2)."s) [OK]", 'green');

					foreach($results as &$result) {
						$result = array_unique($result);
					}
					unset($result);

					return $results;
				}
				else {
					throw new Exception("Unknown filter '".$filter."'", E_USER_ERROR);
				}
			}
			else {
				return false;
			}
		}

		public function filterAttributes($type, $filter, $attribute)
		{
			if($this->_typeIsAllowed($type))
			{
				if($filter === self::FILTER_DUPLICATES)
				{
					$attributes = array();
					$results = array();

					switch($attribute)
					{
						case 'addresses': {
							$attributes[] = 'sources';
							$attributes[] = 'destinations';
							break;
						}
						case 'protocols': {
							$attributes[] = 'protocols';
							break;
						}
						case 'tags': {
							$attributes[] = 'tags';
							break;
						}
						case 'all': {
							$attributes[] = 'sources';
							$attributes[] = 'destinations';
							$attributes[] = 'protocols';
							$attributes[] = 'tags';
						}
					}

					$key = $this->_typeToKey($type);

					foreach($attributes as $attribute)
					{
						$time1 = microtime(true);
						$this->_SHELL->print("Vérification des doublons dans attribut '".$attribute."' ...", 'orange');

						foreach($this->_objects[$key] as $ruleId => $Core_Api_Rule)
						{
							$stores = array();

							foreach($Core_Api_Rule[$attribute] as $Core_Api_Abstract) {
								$stores[$Core_Api_Abstract::OBJECT_TYPE][] = $Core_Api_Abstract->_id_;
							}

							foreach($stores as $store)
							{
								foreach(array_count_values($store) as $id => $counter)
								{
									if($counter > 1)
									{
										if(!isset($results[$ruleId][$attribute])) {
											$results[$ruleId][$attribute] = 0;
										}

										$results[$ruleId][$attribute]++;
									}
								}
							}
						}

						$time2 = microtime(true);
						$this->_TERMINAL->deleteMessage(1, true);
						$this->_SHELL->print("Vérification doublons dans attribut '".$attribute."' (".round($time2-$time1)."s) [OK]", 'green');
					}

					return $results;
				}
				else {
					throw new Exception("Unknown filter '".$filter."'", E_USER_ERROR);
				}
			}
			else {
				return false;
			}
		}

		protected function _format(Core\Api_Abstract $objectApi, array $listFields, $view, $return)
		{
			if($objectApi instanceof Core\Api_Rule)
			{
				switch($return)
				{
					case self::RETURN_OBJECT:
					case self::RETURN_TABLE: {
						$rule = $objectApi->toObject();
						break;
					}
					case self::RETURN_ARRAY: {
						$rule = $objectApi->toArray();
						break;
					}
					default: {
						throw new Exception("Format return type '".$return."' is not valid", E_USER_ERROR);
					}
				}

				$rule['id'] = $rule['name'];
				$rule['date'] = date('Y-m-d H:i:s', $rule['timestamp']).' ('.$rule['timestamp'].')';
				$rule['fullmesh'] = ($rule['fullmesh']) ? ('yes') : ('no');
				$rule['state'] = ($rule['state']) ? ('enable') : ('disable');
				$rule['action'] = ($rule['action']) ? ('permit') : ('deny');

				if($view !== self::VIEW_BRIEF)
				{
					foreach(array('sources', 'destinations') as $attribute)
					{
						foreach($rule[$attribute] as &$item) {
							$item = sprintf($listFields['rule'][$attribute]['format'], $item->name, $item->attributeV4, $item->attributeV6);
						}
						unset($item);

						$rule[$attribute] = implode(PHP_EOL, $rule[$attribute]);
					}

					foreach($rule['protocols'] as &$item) {
						$item = sprintf($listFields['rule']['protocols']['format'], $item->name, $item->protocol);
					}
					unset($item);

					$rule['protocols'] = implode(PHP_EOL, $rule['protocols']);

					$acl = array(array($rule['sources'], $rule['destinations'], $rule['protocols']));
					$rule['acl'] = C\Tools::formatShellTable($acl);
				}

				if($view === self::VIEW_EXTENSIVE)
				{
					foreach($rule['tags'] as &$item) {
						$item = sprintf($listFields['rule']['tags']['format'], $item->name, $item->tag);
					}
					unset($item);

					$rule['tags'] = implode(PHP_EOL, $rule['tags']);
				}
				else
				{
					foreach($rule['tags'] as &$item) {
						$item = '#'.$item->tag;
					}
					unset($item);

					$rule['tags'] = implode(' ', $rule['tags']);
				}

				if($return === self::RETURN_TABLE)
				{
					$table = array(
						$rule['name'],
						$rule['category'],
						'Fullmesh: '.$rule['fullmesh'],
						'Status: '.$rule['state'],
						'Action: '.$rule['action'],
						$rule['description'],
						$rule['tags']
					);

					return C\Tools::formatShellTable(array($table), false, false, '/');
				}
				else {
					return $rule;
				}
			}
			else {
				throw new Exception("Object API must be an instance of Core\Api_Rule", E_USER_ERROR);
			}
		}

		public function category(array $args)
		{
			if(isset($args[0]))
			{
				$Core_Api_Rule = $this->_getEditingRule();

				if($Core_Api_Rule !== false)
				{
					$category = $args[0];

					switch($category)
					{
						case Core\Api_Rule::CATEG_MONOSITE:
						case Core\Api_Rule::CATEG_FAILOVER: {
							$status = $Core_Api_Rule->category($category);
							break;
						}
						default: {
							$this->_SHELL->error("Cette catégorie de règle '".$category."' n'est pas valide", 'orange');
							return false;
						}
					}

					if($status) {
						$this->_SHELL->error("Catégorie '".$category."' OK!", 'green');								
					}
					else {
						$this->_SHELL->error("Impossible d'effectuer l'opération", 'orange');
					}
				}

				return true;
			}

			return false;
		}

		public function fullmesh(array $args)
		{
			if(!isset($args[0])) {
				$args[0] = null;
			}

			$Core_Api_Rule = $this->_getEditingRule();

			if($Core_Api_Rule !== false)
			{
				switch($args[0])
				{
					case 'en':
					case 'enable': {
						$fullmesh = true;
						break;
					}
					case 'dis':
					case 'disable': {
						$fullmesh = false;
						break;
					}
					default: {
						$fullmesh = null;
					}
				}

				if($Core_Api_Rule->category === Core\Api_Rule::CATEG_MONOSITE) {
					$this->_SHELL->error("L'option 'Full Mesh' n'est disponible que pour les règles de catégorie 'Failover'", 'orange');
				}
				else
				{
					$status = $Core_Api_Rule->fullmesh($fullmesh);

					if($status) {
						$fullmesh = $Core_Api_Rule->fullmesh;
						$fullmesh = ($fullmesh) ? ('enable') : ('disable');
						$this->_SHELL->error("Full mesh '".$fullmesh."' OK!", 'green');								
					}
					else {
						$this->_SHELL->error("Impossible d'effectuer l'opération", 'orange');
					}
				}
			}

			return true;
		}

		public function state(array $args)
		{
			if(isset($args[0]))
			{
				$Core_Api_Rule = $this->_getEditingRule();

				if($Core_Api_Rule !== false)
				{
					switch($args[0])
					{
						case 'en':
						case 'enable': {
							$state = true;
							break;
						}
						case 'dis':
						case 'disable': {
							$state = false;
							break;
						}
						default: {
							return false;
						}
					}

					$status = $Core_Api_Rule->state($state);

					if($status) {
						$this->_SHELL->print("Statut '".$args[0]."' OK!", 'green');								
					}
					else {
						$this->_SHELL->error("Impossible d'effectuer l'opération", 'orange');
					}
				}

				return true;
			}

			return false;
		}

		public function action(array $args)
		{
			if(isset($args[0]))
			{
				$Core_Api_Rule = $this->_getEditingRule();

				if($Core_Api_Rule !== false)
				{
					switch($args[0])
					{
						case 'allow':
						case 'permit': {
							$action = true;
							break;
						}
						case 'forbid':
						case 'deny': {
							$action = false;
							break;
						}
						default: {
							return false;
						}
					}

					$status = $Core_Api_Rule->action($action);

					if($status) {
						$this->_SHELL->print("Action '".$args[0]."' OK!", 'green');								
					}
					else {
						$this->_SHELL->error("Impossible d'effectuer l'opération", 'orange');
					}
				}

				return true;
			}

			return false;
		}

		public function source($type, array $args)
		{
			return $this->_srcDst('source', $type, $args);
		}

		public function destination($type, array $args)
		{
			return $this->_srcDst('destination', $type, $args);
		}

		protected function _srcDst($attribute, $type, array $args)
		{
			if(isset($args[0]))
			{
				$Core_Api_Rule = $this->_getEditingRule();

				if($Core_Api_Rule !== false)
				{
					$address = $args[0];

					/**
					  * Cela permet notamment de garantir que l'IP ne changera pas en prod dans le cas où elle changerait dans l'IPAM
					  */
					try {
						$Core_Api_Address = $this->_addressFwProgram->autoCreateObject($type, $address);
					}
					catch(E\Message $e) {
						$this->_SHELL->throw($e);
						return true;
					}
					catch(\Exception $e) {
						$this->_SHELL->error("Une exception s'est produite durant la recherche des objets de type '".$type."':", 'orange');
						$this->_SHELL->error($e->getFile().' | '.$e->getLine().' | '.$e->getMessage(), 'orange');
						return true;
					}

					// /!\ switch utilise une comparaison large (==)
					if($Core_Api_Address === null) {
						$this->_SHELL->error("Impossible de trouver cet objet '".$address."' dans l'inventaire LOCAL ou IPAM", 'orange');
					}
					elseif($Core_Api_Address === false) {
						$this->_SHELL->error("Plusieurs objets correspondent à '".$address."' dans l'inventaire LOCAL ou IPAM", 'orange');
					}
					else
					{
						try {
							$Core_Api_Rule->testAddressOverlap($attribute, $Core_Api_Address);
						}
						catch(E\Message $e) {
							$this->_SHELL->error($e->getMessage(), 'orange');
						}

						$status = $Core_Api_Rule->configure($attribute, $Core_Api_Address);

						if($status) {
							$this->_SHELL->print(ucfirst($attribute)." '".$Core_Api_Address->name."' OK!", 'green');								
						}
						else {
							$this->_SHELL->error("Impossible d'effectuer l'opération, vérifiez qu'il n'y a pas de doublon ou que la source et la destination n'ont pas d'objets en communs", 'orange');
						}
					}
				}

				return true;
			}

			return false;
		}

		/**
		  * $type for future use
		  */
		public function protocol($type, array $args)
		{
			if(isset($args[0]))
			{
				$Core_Api_Rule = $this->_getEditingRule();

				if($Core_Api_Rule !== false)
				{
					$protocol = $args[0];

					if(isset($args[1])) {
						$protocol .= Core\Api_Protocol::PROTO_SEPARATOR.$args[1];
					}

					$Core_Api_Protocol = new Core\Api_Protocol($protocol, $protocol);
					$status = $Core_Api_Protocol->protocol($protocol);

					if($status && $Core_Api_Protocol->isValid())
					{
						$status = $Core_Api_Rule->protocol($Core_Api_Protocol);

						if($status) {
							$this->_SHELL->print("Protocol '".$protocol."' OK!", 'green');								
						}
						else {
							$this->_SHELL->error("Impossible d'effectuer l'opération, vérifiez qu'il n'y a pas de doublon ou que la source et la destination n'ont pas d'objets en communs", 'orange');
						}
					}
					else {
						$this->_SHELL->error("Protocole invalide, entrez un protocole par commande et vérifiez sa syntaxe: ip, tcp|udp 12345[-12345], icmp type:code", 'orange');
					}
				}

				return true;
			}

			return false;
		}

		public function description(array $args)
		{
			if(isset($args[0]))
			{
				$Core_Api_Rule = $this->_getEditingRule();

				if($Core_Api_Rule !== false)
				{
					$description = $args[0];

					$status = $Core_Api_Rule->description($description);

					if($status) {
						$this->_SHELL->print("Description '".$description."' OK!", 'green');								
					}
					else {
						$this->_SHELL->error("Impossible d'effectuer l'opération", 'orange');
					}
				}

				return true;
			}

			return false;
		}

		/**
		  * $type for future use
		  */
		public function tags($type, array $args)
		{
			if(isset($args[0]))
			{
				$Core_Api_Rule = $this->_getEditingRule();

				if($Core_Api_Rule !== false)
				{
					$tags = $args;

					foreach($tags as $tag)
					{
						$Core_Api_Tag = new Core\Api_Tag($tag, $tag);
						$status = $Core_Api_Tag->tag($tag);

						if($status && $Core_Api_Tag->isValid())
						{
							$status = $Core_Api_Rule->tag($Core_Api_Tag);

							if($status) {
								$this->_SHELL->print("Tag '".$tag."' OK!", 'green');								
							}
							else {
								$this->_SHELL->error("Impossible d'effectuer l'opération, vérifiez qu'il n'y a pas de tag en doublon", 'orange');
							}
						}
						else {
							$this->_SHELL->error("Tag non valide", 'orange');
						}
					}
				}

				return true;
			}

			return false;
		}

		public function check()
		{
			$Core_Api_Rule = $this->_getEditingRule();

			if($Core_Api_Rule !== false)
			{
				$invalidAttributes = $Core_Api_Rule->isValid(true);

				if(count($invalidAttributes) === 0) {
					$this->_SHELL->print("Cette règle semble correctement configurée mais cela ne dispense pas l'administrateur de vérifier personnellement", 'green');
				}
				else {
					$this->_SHELL->error("Cette règle n'est pas correctement configurée notamment pour les attributs suivants: ".implode(', ', $invalidAttributes), 'orange');
				}

				return true;
			}

			return false;
		}

		public function reset($attribute = null, $type = null, array $args = null)
		{
			$Core_Api_Rule = $this->_getEditingRule();

			if($Core_Api_Rule !== false)
			{
				if(isset($args[0]))
				{
					if($this->_addressFwProgram->isType($type))
					{
						$address = $args[0];

						$Core_Api_Address = $this->_addressFwProgram->getObject($type, $address, true);

						if($Core_Api_Address !== false) {
							$object = $Core_Api_Address;
						}
						else {
							$objectName = $this->_addressFwProgram->getName($type);
							$this->_SHELL->error("L'objet ".$objectName." '".$address."' n'existe pas, impossible de réaliser l'opération", 'orange');
							return false;
						}
					}
					elseif($type === Core\Api_Protocol::OBJECT_TYPE)
					{
						$protocol = $args[0];

						if(isset($args[1])) {
							$protocol .= Core\Api_Protocol::PROTO_SEPARATOR.$args[1];
						}

						$Core_Api_Protocol = new Core\Api_Protocol($protocol, $protocol);
						$isValidProtocol = $Core_Api_Protocol->protocol($protocol);

						if($isValidProtocol && $Core_Api_Protocol->isValid()) {
							$object = $Core_Api_Protocol;
						}
						else {
							$this->_SHELL->error("Protocole '".$protocol."' non valide, impossible de réaliser l'opération", 'orange');
							return false;
						}
					}
					elseif($type === Core\Api_Tag::OBJECT_TYPE)
					{
						$tag = $args[0];

						$Core_Api_Tag = new Core\Api_Tag($tag, $tag);
						$isValidTag = $Core_Api_Tag->tag($tag);

						if($isValidTag && $Core_Api_Tag->isValid()) {
							$object = $Core_Api_Tag;
						}
						else {
							$this->_SHELL->error("Tag '".$tag."' non valide, impossible de réaliser l'opération", 'orange');
							return false;
						}
					}
					else {
						throw new Exception("Object type '".$type."' is not valid", E_USER_ERROR);
					}
				}
				else {
					$type = null;
					$object = null;
				}

				$status = $Core_Api_Rule->reset($attribute, $type, $object);

				if($status) {
					$this->_SHELL->print("Reset OK!", 'green');								
				}
				else {
					$this->_SHELL->error("Impossible d'effectuer l'opération", 'orange');
				}

				return true;
			}

			return false;
		}

		public function exit()
		{
			$this->_SHELL->deleteWaitingMsg();

			if($this->_isEditingRule(false)) {
				$this->_TERMINAL->setShellPrompt($this->_terminalShellPrompt);
				$this->_terminalShellPrompt = '';
				$this->_editingRuleApi = null;
				return true;
			}

			return false;
		}
	}		