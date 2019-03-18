<?php
	namespace App\Firewall;

	use ArrayObject;

	use Core as C;
	use Core\Exception as E;

	use Cli as Cli;

	use App\Firewall\Core;

	class Shell_Program_Firewall_Object_Rule extends Shell_Program_Firewall_Object_Abstract
	{
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
		  * @var string Rule type
		  */
		protected $_editingRuleType = null;

		/**
		  * @var mixed Rule ID or name
		  */
		protected $_editingRuleName = null;

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
			return ($this->isEditingRule()) ? ($this->_editingRuleType) : (false);
		}

		/**
		  * /!\ Publique, doit retourner l'ID "humain"
		  */
		public function getEditingRuleName()
		{
			if($this->isEditingRule()) {
				return $this->_normalizeName($this->_editingRuleName);
			}
			else {
				return false;
			}
		}

		/**
		  * /!\ Publique, doit accepter un ID "humain"
		  * @return false|mixed Name
		  */
		public static function normalizeName($name)
		{
			if(self::RULE_NAME_MODE_AUTO)
			{
				if(C\Tools::is('int&&>0', $name)) {
					$name--;
				}
				else {
					return false;
				}
			}

			return $name;
		}

		protected function _ruleExists($type, $name)
		{
			return $this->_objectExists($type, $name);
		}

		protected function _getRule($type, $name)
		{
			return $this->_getObject($type, $name);
		}

		protected function _isEditingRule($printError = true)
		{
			if($this->_editingRuleName === null)
			{
				if($printError) {
					$this->_SHELL->error("Merci de rentrer dans le mode d'édition de règle au préalable ('create rule' ou 'modify rule')", 'orange');
				}

				return false;
			}
			else {
				return true;
			}
		}

		protected function _matchEditingRule($ruleName)
		{
			return ($this->_editingRuleName === $ruleName);
		}

		protected function _getEditingRule()
		{
			return $this->_getObject($this->_editingRuleType, $this->_editingRuleName);
		}

		/**
		  * /!\ Protégée, doit accepter un ID "machine"
		  * @return false|mixed Name
		  */
		protected static function _normalizeName($name)
		{
			if(self::RULE_NAME_MODE_AUTO)
			{
				if(C\Tools::is('int&&>=0', $name)) {
					$name++;
				}
				else {
					return false;
				}
			}

			return $name;
		}

		protected function _nextRuleId($key)
		{
			/**
			  * /!\ Ne pas utiliser count, il peut y avoir des trous
			  */
			$rulesKeys = array_keys($this->_objects[$key]);
			$sysRuleName = max(-1, end($rulesKeys));
			$sysRuleName++;

			return $sysRuleName;
		}

		public function locate($type, $search, $strict = false)
		{
			if($this->_typeIsAllowed($type))
			{
				$search = preg_quote($search, '#');
				$search = str_replace('\\*', '.*', $search);
				$search = ($strict) ? ('^('.$search.')$') : ('('.$search.')');

				$results = array();
				$key = $this->_typeToKey($type);

				foreach($this->_objects[$key] as $ruleId => $Core_Api_Rule)
				{
					$isMatched = preg_match('#'.$search.'#i', $Core_Api_Rule->description);

					if($isMatched) {
						$results[$ruleId] = $Core_Api_Rule;
					}
				}

				if(count($results) > 0) {
					return $results;
				}
				else {
					$this->_SHELL->print("Aucune règle ne semble correspondre à cette description", 'green');
				}

				return true;
			}
			else {
				return false;
			}
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
					$sysRuleName = $this->_nextRuleId($key);
					$usrRuleName = $this->_normalizeName($sysRuleName);
				}
				elseif(C\Tools::is('int&&>0', $name) || C\Tools::is('string&&!empty', $name)) {
					$usrRuleName = $name;
					$sysRuleName = $this->normalizeName($usrRuleName);
				}
				else {
					$usrRuleName = $sysRuleName = false;
				}

				if($sysRuleName !== false && $usrRuleName !== false)
				{
					if(!$this->_ruleExists($type, $sysRuleName, true))
					{
						$class = $this->_typeToClass($type);

						switch(true)
						{
							case ($category === null):
							case ($category === Core\Api_Rule::CATEG_MONOSITE):
							case ($category === Core\Api_Rule::CATEG_FAILOVER): {
								$Core_Api_Rule = new $class($usrRuleName, $category);
								break;
							}
							default: {
								throw new E\Message("Cette catégorie de règle '".$category."' n'est pas valide", E_USER_ERROR);
							}
						}

						$this->_objects[$key][$sysRuleName] = $Core_Api_Rule;

						if($enterEditingMode) {
							$this->_editingRuleName = $sysRuleName;
							$this->_editingRuleType = $type;
						}

						return $Core_Api_Rule;
					}
					else {
						throw new E\Message("Une règle avec le même nom '".$usrRuleName."' existe déjà", E_USER_ERROR);
					}
				}
				else {
					throw new E\Message("Impossible de déterminer correctement le nom de la règle", E_USER_ERROR);
				}
			}

			return false;
		}

		public function create($type, array $args)
		{
			if(isset($args[0]))
			{
				if(self::RULE_NAME_MODE_AUTO) {
					$ruleName = null;
					$ruleCategory = $args[0];
				}
				elseif(isset($args[1])) {
					$ruleName = $args[0];
					$ruleCategory = $args[1];
				}
				else {
					return false;
				}

				try {
					$Core_Api_Rule = $this->_insert($type, $ruleName, $ruleCategory, true);
				}
				catch(\Exception $e) {
					$this->_SHELL->throw($e);
					$Core_Api_Rule = null;
				}

				if(is_object($Core_Api_Rule))				// On ne sait pas la classe, dépend de $type
				{
					$this->_SHELL->deleteWaitingMsg();		// Garanti la suppression du message

					if(!$this->isEditingRule()) {
						$this->_terminalShellPrompt = $this->_TERMINAL->getShellPrompt();
					}

					$ruleName = $Core_Api_Rule->name;
					$objectName = mb_strtoupper($Core_Api_Rule::OBJECT_NAME);
					$this->_TERMINAL->setShellPrompt($objectName.' ('.$ruleCategory.') ['.$ruleName.']');
				}
				elseif($Core_Api_Rule === false) {
					$this->_SHELL->error("Une erreur s'est produite durant la création d'une règle", 'orange');
				}

				return true;
			}

			return false;
		}

		public function clone($type, array $args)
		{
			if($this->_typeIsAllowed($type))
			{
				if(isset($args[0]))
				{
					if(self::RULE_NAME_MODE_AUTO) {
						$usrRuleName = $args[0];
						$sysRuleName = $this->normalizeName($usrRuleName);
					}
					else {
						// @todo a coder
						return false;
					}

					if($sysRuleName !== false)
					{
						if(($Core_Api_Rule = $this->_getRule($type, $sysRuleName)) !== false)
						{
							$Core_Api_Rule = clone $Core_Api_Rule;
							// /!\ Ne pas garder le timestamp afin d'éviter à l'utilisateur de confondre les règles après le clonage

							if(isset($args[1]))
							{
								$ruleCategory = $args[1];

								switch($ruleCategory)
								{
									case Core\Api_Rule::CATEG_MONOSITE:
									case Core\Api_Rule::CATEG_FAILOVER: {
										$Core_Api_Rule->category($ruleCategory);
										break;
									}
									default: {
										$this->_SHELL->error("Cette catégorie de règle '".$ruleCategory."' n'est pas valide", 'orange');
										return false;
									}
								}
							}
							else {
								$ruleCategory = $Core_Api_Rule->category;
							}

							$key = $this->_typeToKey($type);
							$sysRuleName = $this->_nextRuleId($key);

							$this->_editingRuleType = $type;
							$this->_editingRuleName = $sysRuleName;

							$usrRuleName = $this->_normalizeName($sysRuleName);
							$this->_objects[$key][] = $Core_Api_Rule;
							$Core_Api_Rule->name($usrRuleName);

							$this->_SHELL->deleteWaitingMsg();		// Garanti la suppression du message

							if(!$this->isEditingRule()) {
								$this->_terminalShellPrompt = $this->_TERMINAL->getShellPrompt();
							}

							$objectName = mb_strtoupper($Core_Api_Rule::OBJECT_NAME);
							$this->_TERMINAL->setShellPrompt($objectName.' ('.$ruleCategory.') ['.$usrRuleName.']');
						}
						else {
							$this->_SHELL->error("Cet ID de règle '".$usrRuleName."' n'existe pas", 'orange');
						}
					}
					else {
						$this->_SHELL->error("Cet ID de règle '".$usrRuleName."' n'est pas valide", 'orange');
					}

					return true;
				}
			}

			return false;
		}

		public function update($type, $name)
		{
			return $this->_update($type, $name, false);
		}

		protected function _update($type, $name, $enterEditingMode = false)
		{
			if($this->_typeIsAllowed($type))
			{
				$usrRuleName = $name;
				$sysRuleName = $this->normalizeName($usrRuleName);

				if($sysRuleName !== false)
				{
					if(!$this->_matchEditingRule($sysRuleName))
					{
						if(($Core_Api_Rule = $this->_getRule($type, $sysRuleName)) !== false)
						{
							if($enterEditingMode) {
								$this->_editingRuleType = $type;
								$this->_editingRuleName = $sysRuleName;
							}

							return $Core_Api_Rule;
						}
						else {
							throw new E\Message("Cet ID de règle '".$usrRuleName."' n'existe pas", E_USER_WARNING);
						}
					}
					else {
						throw new E\Message("La règle '".$usrRuleName."' est déjà en cours d'édition", E_USER_WARNING);
					}
				}
				else {
					throw new E\Message("Cet ID de règle '".$usrRuleName."' n'est pas valide", E_USER_ERROR);
				}
			}

			return false;
		}

		public function modify($type, array $args)
		{
			if(isset($args[0]))
			{
				$usrRuleName = $args[0];

				try {
					$Core_Api_Rule = $this->_update($type, $usrRuleName, true);
				}
				catch(\Exception $e) {
					$this->_SHELL->throw($e);
					$Core_Api_Rule = null;
				}

				if($Core_Api_Rule instanceof Core\Api_Rule_Interface)
				{
					$ruleCategory = $Core_Api_Rule->category;

					$this->_SHELL->deleteWaitingMsg();		// Garanti la suppression du message

					if(!$this->isEditingRule()) {
						$this->_terminalShellPrompt = $this->_TERMINAL->getShellPrompt();
					}

					$objectName = mb_strtoupper($Core_Api_Rule::OBJECT_NAME);
					$this->_TERMINAL->setShellPrompt($objectName.' ('.$ruleCategory.') ['.$usrRuleName.']');
				}
				elseif($Core_Api_Rule === false) {
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
						$objectName = $this->_addressFwProgram->typeToName($badType);
						$this->_SHELL->error("L'objet '".$badName."' de type '".$objectName."' semble ne pas exister", 'orange');
					}
					elseif($Core_Api_Address__new === false) {
						$objectName = $this->_addressFwProgram->typeToName($newType);
						$this->_SHELL->error("L'objet '".$newName."' de type '".$objectName."' semble ne pas exister", 'orange');
					}
					else
					{
						$counter = 0;
						$key = $this->_typeToKey($type);

						foreach($this->_objects[$key] as $Core_Api_Rule) {
							$status = $Core_Api_Rule->replace($Core_Api_Address__bad, $Core_Api_Address__new);
							if($status) { $counter++; }
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

		public function rename($type, array $args)
		{
			if($this->_typeIsAllowed($type))
			{
				if(isset($args[0]) && isset($args[1]))
				{
					$usrRuleName = $args[0];
					$sysRuleName = $this->normalizeName($usrRuleName);

					$newUsrRuleName = $args[1];
					$newSysRuleName = $this->normalizeName($newUsrRuleName);

					if($sysRuleName !== false && $newSysRuleName !== false)
					{
						if(!$this->_matchEditingRule($sysRuleName))
						{
							$objectName = $this->typeToName($type, true);

							if(($Core_Api_Rule = $this->_getRule($type, $sysRuleName)) !== false)
							{
								if(!$this->_ruleExists($type, $newSysRuleName))
								{					
									$key = $this->_typeToKey($type);
							
									$Core_Api_Rule->name($newUsrRuleName);
									$this->_objects[$key][$newSysRuleName] = $Core_Api_Rule;
									unset($this->_objects[$key][$sysRuleName]);
									ksort($this->_objects[$key]);

									$this->_SHELL->print($objectName." '".$usrRuleName."' renommé en '".$newUsrRuleName."'", 'green');
								}
								else {
									$this->_SHELL->error($objectName." '".$newUsrRuleName."' existe déjà", 'orange');
								}
							}
							else {
								$this->_SHELL->error($objectName." '".$usrRuleName."' introuvable", 'orange');
							}
						}
						else {
							$this->_SHELL->error("Impossible de renommer une règle en cours d'édition", 'orange');
						}
					}
					else {
						$this->_SHELL->error("Les ID de règle '".$usrRuleName."' '".$newUsrRuleName."' ne sont pas valides", 'orange');
					}

					return true;
				}
			}

			return false;
		}

		public function delete($typeOrRuleApi, $name = null)
		{
			if($typeOrRuleApi instanceof Core\Api_Rule_Interface) {
				$type = $typeOrRuleApi::OBJECT_TYPE;
				$name = $typeOrRuleApi->name;
				$Core_Api_Rule = $typeOrRuleApi;
				$checkInstance = true;
			}
			else {
				$type = $typeOrRuleApi;
				$checkInstance = false;
			}

			if($this->_typeIsAllowed($type))
			{
				$usrRuleName = $name;
				$sysRuleName = $this->normalizeName($usrRuleName);

				if($sysRuleName !== false)
				{
					if(!$this->_matchEditingRule($sysRuleName))
					{
						$key = $this->_typeToKey($type);

						if($this->_ruleExists($type, $sysRuleName))
						{
							// http://php.net/manual/fr/language.oop5.object-comparison.php
							if(!$checkInstance || $Core_Api_Rule === $this->_objects[$key][$sysRuleName]) {
								unset($this->_objects[$key][$sysRuleName]);
								return true;
							}
						}
						else {
							throw new E\Message("La règle '".$usrRuleName."' n'existe pas", E_USER_WARNING);
						}
					}
					else {
						throw new E\Message("Impossible de supprimer une règle en cours d'édition", E_USER_WARNING);
					}
				}
				else {
					throw new E\Message("Ce nom de règle '".$usrRuleName."' n'est pas valide", E_USER_ERROR);
				}
			}

			return false;
		}

		public function remove($type, array $args)
		{
			if(isset($args[0]))
			{
				$usrRuleName = $args[0];

				try {
					$status = $this->delete($type, $usrRuleName);
				}
				catch(\Exception $e) {
					$this->_SHELL->throw($e);
					$status = null;
				}

				if($status === true) {
					$this->_SHELL->print("Règle '".$usrRuleName."' supprimée", 'green');
				}
				elseif($status === false) {
					$this->_SHELL->error("Une erreur s'est produite durant la suppression d'une règle", 'orange');
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

		public function filter($type, $filter)
		{
			if($this->_typeIsAllowed($type))
			{
				if($filter === self::FILTER_DUPLICATES)
				{
					$results = array();
					$runCache = array();

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

		public function format(Core\Api_Abstract $objectApi, array $listFields)
		{
			if($objectApi instanceof Core\Api_Rule)
			{
				$rule = $objectApi->toObject();

				$rule['id'] = $rule['name'];
				$rule['date'] = date('Y-m-d H:i:s', $rule['timestamp']).' ('.$rule['timestamp'].')';
				$rule['fullmesh'] = ($rule['fullmesh']) ? ('yes') : ('no');
				$rule['state'] = ($rule['state']) ? ('enable') : ('disable');
				$rule['action'] = ($rule['action']) ? ('permit') : ('deny');

				foreach(array('sources', 'destinations') as $attribute)
				{
					foreach($rule[$attribute] as &$item) {
						$item = sprintf($listFields['rule'][$attribute]['format'], $item->name, $item->attributeV4, $item->attributeV6);
					}

					$rule[$attribute] = implode(PHP_EOL, $rule[$attribute]);
				}

				foreach($rule['protocols'] as &$item) {
					$item = sprintf($listFields['rule']['protocols']['format'], $item->name, $item->protocol);
				}

				$rule['protocols'] = implode(PHP_EOL, $rule['protocols']);

				$acl = array(array($rule['sources'], $rule['destinations'], $rule['protocols']));
				$rule['acl'] = C\Tools::formatShellTable($acl);

				return $rule;
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
					$ruleCategory = $args[0];

					switch($ruleCategory)
					{
						case Core\Api_Rule::CATEG_MONOSITE:
						case Core\Api_Rule::CATEG_FAILOVER: {
							$status = $Core_Api_Rule->category($ruleCategory);
							break;
						}
						default: {
							$this->_SHELL->error("Cette catégorie de règle '".$ruleCategory."' n'est pas valide", 'orange');
							return false;
						}
					}

					if($status) {
						$this->_SHELL->error("Catégorie '".$ruleCategory."' OK!", 'green');								
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
						case 'enable':
							$state = true;
							break;
						case 'disable':
							$state = false;
							break;
						default:
							return false;
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
						case 'permit':
							$action = true;
							break;
						case 'deny':
							$action = false;
							break;
						default:
							return false;
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
					$arg = $args[0];

					/**
					  * Cela permet notamment de garantir que l'IP ne changera pas en prod dans le cas où elle changerait dans l'IPAM
					  */
					try {
						$Core_Api_Address = $this->_addressFwProgram->autoCreateObject($type, $arg);
					}
					catch(E\Message $e) {		// Core\Exception\Message
						$this->_SHELL->throw($e);
						return true;
					}
					catch(Exception $e) {		// App\Firewall\Exception
						$this->_SHELL->error("Une exception s'est produite durant la recherche des objets de type '".$type."':", 'orange');
						$this->_SHELL->error($e->getMessage(), 'orange');
						return true;
					}

					// /!\ switch utilise une comparaison large (==)
					if($Core_Api_Address === null) {
						$this->_SHELL->error("Impossible de trouver cet objet '".$arg."' dans l'inventaire LOCAL ou IPAM", 'orange');
					}
					elseif($Core_Api_Address === false) {
						$this->_SHELL->error("Plusieurs objets correspondent à '".$arg."' dans l'inventaire LOCAL ou IPAM", 'orange');
					}
					else
					{
						$callable = array($Core_Api_Rule, $attribute);
						$status = call_user_func($callable, $Core_Api_Address);

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

					$Core_Api_Protocol = new Core\Api_Protocol($protocol);
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
						$Core_Api_Address = $this->_addressFwProgram->getObject($type, $args[0], true);

						if($Core_Api_Address !== false) {
							$object = $Core_Api_Address;
						}
						else {
							$objectName = $this->_addressFwProgram->typeToName($type);
							$this->_SHELL->error("L'objet ".$objectName." '".$args[0]."' n'existe pas, impossible de réaliser l'opération", 'orange');
							return false;
						}
					}
					elseif($type === Core\Api_Protocol::OBJECT_TYPE)
					{
						$Core_Api_Protocol = new Core\Api_Protocol();
						$Core_Api_Protocol->protocol($args[0]);

						if(isset($args[1])) {
							$Core_Api_Protocol->options($args[1]);
						}

						$object = $Core_Api_Protocol;
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
				$this->_editingRuleType = null;
				$this->_editingRuleName = null;
				return true;
			}

			return false;
		}
	}		