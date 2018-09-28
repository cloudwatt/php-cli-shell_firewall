<?php
	class Service_Shell_Firewall_Object
	{
		const OBJECT_TYPE = array(
			Firewall_Api_Site::OBJECT_TYPE,
			Firewall_Api_Host::OBJECT_TYPE,
			Firewall_Api_Subnet::OBJECT_TYPE,
			Firewall_Api_Network::OBJECT_TYPE,
			Firewall_Api_Rule::OBJECT_TYPE
		);

		const OBJECT_TYPE_CLASS = array(
			Firewall_Api_Site::OBJECT_TYPE => 'Firewall_Api_Site',
			Firewall_Api_Host::OBJECT_TYPE => 'Firewall_Api_Host',
			Firewall_Api_Subnet::OBJECT_TYPE => 'Firewall_Api_Subnet',
			Firewall_Api_Network::OBJECT_TYPE => 'Firewall_Api_Network',
			Firewall_Api_Rule::OBJECT_TYPE => 'Firewall_Api_Rule'
		);

		protected $_MAIN;
		protected $_SHELL;

		protected $_objects;


		public function __construct(Service_Abstract $MAIN, SHELL $SHELL, ArrayObject $objects)
		{
			$this->_MAIN = $MAIN;
			$this->_SHELL = $SHELL;

			$this->_objects = $objects;
		}

		/**
		  * Les objects doivent avoir des noms uniques afin que le système d'autocompletion fonctionne correctement
		  */
		public function create($class, array $args)
		{
			if(isset($args[0]) && isset($args[1]))
			{
				$id = $args[0];
				$attr0 = $args[1];
				$attr1 = (isset($args[2])) ? ($args[2]) : (null);

				$objectName = ucfirst($class::OBJECT_NAME);

				foreach($this->_objects as $objClass => $objects)
				{
					if(array_key_exists($id, $objects)) {
						$this->_MAIN->error('Un '.ucfirst($objClass::OBJECT_NAME)." avec le même nom existe déjà", 'orange');
						return true;
					}
				}

				$objectApi = new $class($id, $attr0, $attr1);
				$status = $objectApi->isValid();

				if($status) {
					$this->_objects[$class][$id] = $objectApi;
					$this->_MAIN->print($objectName." '".$id."' créé", 'green');
				}
				else {
					$this->_MAIN->error($objectName." '".$id."' invalide", 'orange');
				}

				return true;
			}

			return false;
		}

		public function modify($class, array $args)
		{
			if(isset($args[0]) && isset($args[1]))
			{
				$id = $args[0];
				$attr0 = $args[1];
				$attr1 = (isset($args[2])) ? ($args[2]) : (null);

				$objects = $this->_objects[$class];
				$objectName = ucfirst($class::OBJECT_NAME);

				if(array_key_exists($id, $objects))
				{
					$objectApi = $objects[$id];

					if($attr1 === null) {
						$objectApi->reset($class::FIELD_ATTRv4);
						$objectApi->reset($class::FIELD_ATTRv6);
						
					}

					$objectApi->{$class::FIELD_ATTRS_FCT}($attr0, $attr1);
					$status = $objectApi->isValid();

					if(!$status) {
						unset($objects[$id]);
						$this->_MAIN->error($objectName." '".$id."' invalide", 'orange');
					}
					else {
						$this->_MAIN->print($objectName." '".$id."' modifié", 'green');
					}
				}
				else {
					$this->_MAIN->error($objectName." '".$id."' introuvable", 'orange');
				}

				return true;
			}

			return false;
		}

		public function remove($class, array $args)
		{
			if(isset($args[0]))
			{
				$id = $args[0];

				$objects = &$this->_objects[$class];
				$objectName = ucfirst($class::OBJECT_NAME);

				if(array_key_exists($id, $objects))
				{
					$ruleClass = self::OBJECT_TYPE_CLASS['rule'];

					if($class !== $ruleClass)
					{
						$rules = $this->_objects[$ruleClass];

						foreach($rules as $ruleObject)
						{
							if($ruleObject->isPresent($objects[$id])) {
								$ruleId = $ruleObject->name;
								$this->_MAIN->error("Rule '".($ruleId+1)."' utilise cet object", 'orange');
								$isUsed = true;
								break;
							}
						}
					}

					if(!isset($isUsed)) {
						unset($objects[$id]);
						$this->_MAIN->print($objectName." '".$id."' supprimé", 'green');
						// @todo $id + 1 pour ruleId
					}
				}
				else {
					$this->_MAIN->error($objectName." '".$id."' introuvable", 'orange');
					// @todo $id + 1 pour ruleId
				}

				return true;
			}

			return false;
		}

		public function clear($class)
		{
			$objects =& $this->_objects[$class];	// /!\ Important
			$objects = array();

			$objectName = ucfirst($class::OBJECT_NAME);
			$this->_MAIN->print($objectName." réinitialisé", 'green');
			return true;
		}

		public function getObject($class, $id)
		{
			$objects = $this->_objects[$class];
			return (array_key_exists($id, $objects)) ? ($objects[$id]) : (false);
		}

		// @todo a coder
		/*public function getObjects($class, $arg, $strict = true)
		{
			
		}*/

		protected function _register($class, Firewall_Api_Address $objectApi)
		{
			$id = $objectApi->name;
			$status = $objectApi->isValid();

			if($status) {
				$this->_objects[$class][$id] = $objectApi;
				return true;
			}
			else {
				return false;
			}
		}
	}