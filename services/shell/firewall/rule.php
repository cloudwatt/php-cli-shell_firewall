<?php
	require_once(__DIR__ . '/object.php');
	require_once(__DIR__ . '/ipam.php');

	class Service_Shell_Firewall_Rule extends Service_Shell_Firewall_Object
	{
		protected $_Service_Shell_Firewall_Ipam;

		protected $_rules = null;
		protected $_editingRuleId = null;


		public function __construct(Service_Abstract $MAIN, SHELL $SHELL, ArrayObject $objects)
		{
			parent::__construct($MAIN, $SHELL, $objects);

			$this->_rules =& $this->_objects['Firewall_Api_Rule']; // /!\ reference!
			$this->_Service_Shell_Firewall_Ipam = new Service_Shell_Firewall_Ipam();
		}

		public function isEditingRule()
		{
			return ($this->_editingRuleId !== null);
		}

		public function getEditingRuleId()
		{
			return ($this->isEditingRule()) ? ($this->_editingRuleId) : (false);
		}

		public function create($class, array $args)
		{
			if($class === 'Firewall_Api_Rule')
			{
				$this->_MAIN->deleteWaitingMsg();		// Garanti la suppression du message

				if(isset($args[0]))
				{
					$ruleCategory = $args[0];

					if($this->_editingRuleId === null)
					{
						switch($ruleCategory)
						{
							case Firewall_Api_Rule::CATEG_MONOSITE:
							case Firewall_Api_Rule::CATEG_FAILOVER:
							{
								$this->_editingRuleId = $ruleId = count($this->_rules);
								$this->_rules[] = new Firewall_Api_Rule($ruleId+1, $ruleCategory);

								$objectName = mb_strtoupper(Firewall_Api_Rule::OBJECT_NAME);
								$this->_SHELL->setShellPrompt($objectName.' ('.$ruleCategory.') ['.($ruleId+1).']');
								break;
							}
							default: {
								$this->_MAIN->error("Cette catégorie de règle '".$ruleCategory."' n'est pas valide", 'orange');
							}
						}
					}
					else {
						$this->_MAIN->error("La règle '".($this->_editingRuleId+1)."' est déjà en cours d'édition", 'orange');
					}

					return true;
				}

				return false;
			}
			else {
				return parent::create($class, $args);
			}
		}

		public function modify($class, array $args)
		{
			if($class === 'Firewall_Api_Rule')
			{
				if(isset($args[0]))
				{
					$id = $args[0];

					if($this->_editingRuleId === null)
					{
						if(Tools::is('int&&>0', $id))
						{
							$ruleId = (int) ($id-1);

							if(isset($this->_rules[$ruleId]))
							{
								$this->_editingRuleId = $ruleId;

								$Firewall_Api_Rule = $this->_rules[$ruleId];
								$ruleCategory = $Firewall_Api_Rule->category;

								$this->_SHELL->setShellPrompt('RULE ('.$ruleCategory.') ['.$id.']');
							}
							else {
								$this->_MAIN->error("Cet ID de règle '".$id."' n'existe pas", 'orange');
							}
						}
						else {
							$this->_MAIN->error("Cet ID de règle '".$id."' n'est pas valide", 'orange');
						}
					}
					else {
						$this->_MAIN->error("La règle '".($this->_editingRuleId+1)."' est déjà en cours d'édition", 'orange');
					}

					return true;
				}

				return false;
			}
			else {
				return parent::modify($class, $args);
			}
		}

		public function remove($class, array $args)
		{
			if($class === 'Firewall_Api_Rule')
			{
				if(isset($args[0]))
				{
					$id = $args[0];
					$ruleId = (int) ($id-1);

					if($this->_editingRuleId === null || $this->_editingRuleId !== $ruleId) {
						return parent::remove('Firewall_Api_Rule', array($ruleId));
					}
					else {
						$this->_MAIN->error("Impossible de supprimer une règle en cours d'édition", 'orange');
					}

					return true;
				}

				return false;
			}
			else {
				return parent::remove($class, $args);
			}
		}

		public function clear($class)
		{
			$this->exit();
			return parent::clear('Firewall_Api_Rule');
		}

		public function format($ruleId, array $listFields)
		{
			if(isset($this->_rules[$ruleId]))
			{
				$rule = $this->_rules[$ruleId]->toObject();

				$rule['id'] = (int) ($ruleId+1);
				$rule['fullmesh'] = ($rule['fullmesh']) ? ('yes') : ('no');
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

				return $rule;
			}
			else {
				return false;
			}
		}

		public function fullmesh(array $args)
		{
			if(!isset($args[0])) {
				$args[0] = null;
			}

			if($this->_isEditingRule())
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

				$Firewall_Api_Rule = $this->_rules[$this->_editingRuleId];

				if($Firewall_Api_Rule->category === Firewall_Api_Rule::CATEG_MONOSITE) {
					$this->_MAIN->error("L'option 'Full Mesh' n'est disponible que pour les règles de catégorie 'Failover'", 'orange');
				}
				else
				{
					$status = $Firewall_Api_Rule->fullmesh($fullmesh);

					if($status) {
						$fullmesh = $Firewall_Api_Rule->fullmesh;
						$fullmesh = ($fullmesh) ? ('enable') : ('disable');
						$this->_MAIN->error("Full mesh '".$fullmesh."' OK!", 'green');								
					}
					else {
						$this->_MAIN->error("Impossible d'effectuer l'opération", 'orange');
					}
				}
			}

			return true;
		}

		public function action(array $args)
		{
			if(isset($args[0]))
			{
				if($this->_isEditingRule())
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

					$Firewall_Api_Rule = $this->_rules[$this->_editingRuleId];
					$status = $Firewall_Api_Rule->action($action);

					if($status) {
						$this->_MAIN->print("Action '".$args[0]."' OK!", 'green');								
					}
					else {
						$this->_MAIN->error("Impossible d'effectuer l'opération", 'orange');
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
				if($this->_isEditingRule())
				{
					$arg = $args[0];

					/**
					  * Cela permet notamment de garantir que l'IP ne changera pas en prod dans le cas où elle changerait dans l'IPAM
					  */
					$result = $this->_autoCreateObject($type, $arg);

					// /!\ switch utilise une comparaison large (==)
					if($result === null) {
						$this->_MAIN->error("Impossible de trouver cet objet '".$arg."' dans l'inventaire LOCAL ou IPAM", 'orange');
					}
					elseif($result === false) {
						$this->_MAIN->error("Plusieurs objets correspondent à '".$arg."' dans l'inventaire LOCAL ou IPAM", 'orange');
					}
					else
					{
						$Firewall_Api_Rule = $this->_rules[$this->_editingRuleId];
						$status = $Firewall_Api_Rule->{$attribute}($result);

						if($status) {
							$this->_MAIN->print(ucfirst($attribute)." '".$result."' OK!", 'green');								
						}
						else {
							$this->_MAIN->error("Impossible d'effectuer l'opération, vérifiez qu'il n'y a pas de doublon ou que la source et la destination n'ont pas d'objets en communs", 'orange');
						}
					}
				}

				return true;
			}

			return false;
		}

		public function protocol(array $args)
		{
			if(isset($args[0]))
			{
				if($this->_isEditingRule())
				{
					$protocol = $args[0];

					if(isset($args[1])) {
						$protocol .= Firewall_Api_Protocol::PROTO_SEPARATOR.$args[1];
					}

					$Firewall_Api_Protocol = new Firewall_Api_Protocol($protocol);
					$status = $Firewall_Api_Protocol->protocol($protocol);

					if($status && $Firewall_Api_Protocol->isValid())
					{
						$Firewall_Api_Rule = $this->_rules[$this->_editingRuleId];
						$status = $Firewall_Api_Rule->protocol($Firewall_Api_Protocol);

						if($status) {
							$this->_MAIN->print("Protocol '".$protocol."' OK!", 'green');								
						}
						else {
							$this->_MAIN->error("Impossible d'effectuer l'opération, vérifiez qu'il n'y a pas de doublon ou que la source et la destination n'ont pas d'objets en communs", 'orange');
						}
					}
					else {
						$this->_MAIN->error("Protocole invalide, entrez un protocole par commande et vérifiez sa syntaxe: ip, tcp|udp 12345[-12345], icmp type:code", 'orange');
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
				if($this->_isEditingRule())
				{
					$description = $args[0];

					$Firewall_Api_Rule = $this->_rules[$this->_editingRuleId];
					$status = $Firewall_Api_Rule->description($description);

					if($status) {
						$this->_MAIN->print("Description '".$description."' OK!", 'green');								
					}
					else {
						$this->_MAIN->error("Impossible d'effectuer l'opération", 'orange');
					}
				}

				return true;
			}

			return false;
		}

		public function check()
		{
			if($this->_editingRuleId !== null)
			{
				$Firewall_Api_Rule = $this->_rules[$this->_editingRuleId];
				$invalidAttributes = $Firewall_Api_Rule->isValid(true);

				if(count($invalidAttributes) === 0) {
					$this->_MAIN->print("Cette règle semble correctement configurée mais cela ne dispense pas l'administrateur de vérifier personnellement", 'green');
				}
				else {
					$this->_MAIN->error("Cette règle n'est pas correctement configurée notamment pour les attributs suivants: ".implode(', ', $invalidAttributes), 'orange');
				}

				return true;
			}

			return false;
		}

		public function reset($attribute = null)
		{
			if($this->_editingRuleId !== null)
			{
				$Firewall_Api_Rule = $this->_rules[$this->_editingRuleId];
				$status = $Firewall_Api_Rule->reset($attribute);

				if($status) {
					$this->_MAIN->print("Reset OK!", 'green');								
				}
				else {
					$this->_MAIN->error("Impossible d'effectuer l'opération", 'orange');
				}

				return true;
			}

			return false;
		}

		public function exit()
		{
			$this->_MAIN->deleteWaitingMsg();

			if($this->_editingRuleId !== null) {
				$this->_SHELL->resetShellPrompt();
				$this->_editingRuleId = null;
				return true;
			}

			return false;
		}

		protected function _isEditingRule()
		{
			if($this->_editingRuleId === null) {
				$this->_MAIN->error("Merci de rentrer dans le mode d'édition de règle au préalable ('create rule' ou 'modify rule')", 'orange');
				return false;
			}
			else {
				return true;
			}
		}

		protected function _autoCreateObject($type, $arg)
		{
			$objectApi = $this->getLocalObjectApi($type, $arg);

			if($objectApi === null)
			{
				$state = false;
				$objectApi = $this->getIpamObjectApi($type, $arg);

				if($objectApi instanceof Firewall_Api_Subnet) {
					$state = $this->_register('Firewall_Api_Subnet', $objectApi);
				}
				elseif($objectApi instanceof Firewall_Api_Host) {
					$state = $this->_register('Firewall_Api_Host', $objectApi);
				}
				elseif($objectApi === null || $objectApi === false) {
					return $objectApi;
				}
				else {
					throw new Exception("Return type '".gettype($objectApi)."' is not allowed", E_USER_ERROR);
				}

				if($state && $objectApi !== false) {
					return $objectApi;
				}
				else {
					throw new Exception("Unable to create custom object from IPAM object(s)", E_USER_ERROR);
				}
			}
			elseif($objectApi !== false) {
				return $objectApi;
			}
			else {
				return false;
			}
		}

		public function getLocalObjectApi($type, $arg, $strict = true)
		{
			if(array_key_exists($type, self::OBJECT_TYPE_CLASS)) {
				$object = $this->getObject(self::OBJECT_TYPE_CLASS[$type], $arg);
			}
			else {
				throw new Exception("Unknown type '".$type."'", E_USER_ERROR);
			}

			return ($object !== false) ? ($object) : (null);
		}

		public function getIpamObjectApi($type, $arg, $strict = true)
		{
			$results = $this->_Service_Shell_Firewall_Ipam->getObjects($type, $arg, $strict);

			switch(count($results))
			{
				case 0: {
					return null;
				}
				case 1: {
					$class = self::OBJECT_TYPE_CLASS[$type];
					return new $class($results[0]['name'], $results[0][$class::FIELD_ATTRv4], $results[0][$class::FIELD_ATTRv6]);
				}
				case 2:
				{
					if($results[0]['name'] === $results[1]['name'])
					{
						$name = $results[0]['name'];
						$class = self::OBJECT_TYPE_CLASS[$type];
						$Firewall_Api_Address = new $class($results[0]['name']);

						$attributes = $class::FIELD_ATTRS;

						foreach($results as $result)
						{
							foreach($attributes as $attribute)
							{
								if($result[$attribute] !== null) {
									$Firewall_Api_Address->{$class::FIELD_ATTR_FCT}($result[$attribute]);
								}
							}
						}

						return $Firewall_Api_Address;
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
	}		