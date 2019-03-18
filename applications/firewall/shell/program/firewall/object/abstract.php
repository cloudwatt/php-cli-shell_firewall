<?php
	namespace App\Firewall;

	use ArrayObject;

	use Cli as Cli;

	use App\Firewall\Core;

	abstract class Shell_Program_Firewall_Object_Abstract extends Shell_Program_Firewall_Abstract
	{
		const OBJECT_IDS = array();

		const OBJECT_KEYS = array();

		const OBJECT_CLASSES = array();

		const FILTER_DUPLICATES = 'filter_duplicates';

		/**
		  * @var Cli\Shell\Main
		  */
		protected $_SHELL;

		/**
		  * @var Cli\Terminal\Main
		  */
		protected $_TERMINAL;

		/**
		  * @var ArrayObject
		  */
		protected $_objects;


		public function __construct(Cli\Shell\Main $SHELL, ArrayObject $objects)
		{
			$this->_SHELL = $SHELL;
			$this->_TERMINAL = $SHELL->terminal;

			$this->_objects = $objects;
		}

		/**
		  * @param $type string
		  * @param $arg string
		  * @param $strictKey bool
		  * @param $strictMatch bool
		  * @return bool
		  */
		public function objectExists($type, $arg, $strictKey = true, $strictMatch = true)
		{
			return ($this->getObject($type, $arg, $strictKey, $strictMatch) !== false);
		}

		/**
		  * @param $type string
		  * @param $arg string
		  * @param $strictKey bool
		  * @param $strictMatch bool
		  * @return false|App\Firewall\Core\Api_Abstract
		  */
		public function getObject($type, $arg, $strictKey = true, $strictMatch = true)
		{
			$object = $this->getObjects($type, $arg, $strictKey, $strictMatch, 1);
			return (count($object) > 0) ? (current($object)) : (false);
		}

		/**
		  * @param $type string
		  * @param $arg string
		  * @param $strictKey bool
		  * @param $strictMatch bool
		  * @param $limit int
		  * @return array
		  */
		public function getObjects($type, $arg, $strictKey = true, $strictMatch = true, $limit = null)
		{
			$name = $this->normalizeName($arg);

			/**
			  * Normalisation du nom impossible
			  * Recherche par correspondance (match)
			  */
			if($name === false) {
				$name = $arg;
			}
			/**
			  * Normalisation du nom possible
			  * Dans ce cas on force le mode strictKey
			  */
			elseif($name !== $arg) {
				$strictKey = true;
			}

			return $this->_getObjects($type, $name, $strictKey, $strictMatch, $limit);
		}

		/**
		  * /!\ Publique, doit accepter un ID "humain"
		  * @return false|mixed Name
		  */
		public static function normalizeName($name)
		{
			return $name;
		}

		protected function _objectExists($type, $name)
		{
			return ($this->_getObject($type, $name) !== false);
		}

		protected function _getObject($type, $name)
		{
			$objects = $this->_getObjects($type, $name, true);
			return (count($objects) === 1) ? (current($objects)) : (false);
		}

		protected function _getObjects($type, $name, $strictKey = true, $strictMatch = true, $limit = null)
		{
			$results = array();
			$key = $this->_typeToKey($type, false);

			if($key !== false && array_key_exists($key, $this->_objects))
			{
				$objects = $this->_objects[$key];
			
				if(array_key_exists($name, $objects)) {
					return array($objects[$name]);
				}
				elseif(!$strictKey)
				{
					$counter = 0;

					foreach($objects as $id => $object)
					{
						if($object->match($name, $strictMatch))
						{
							$counter++;
							$results[$id] = $object;

							if($counter === $limit) {
								break;
							}
						}
					}
				}
			}

			return $results;
		}

		/**
		  * /!\ Protégée, doit accepter un ID "machine"
		  * @return false|mixed Name
		  */
		protected static function _normalizeName($name)
		{
			return $name;
		}

		abstract public function locate($type, $search, $strict = false);

		abstract public function create($type, array $args);

		abstract public function modify($type, array $args);

		abstract public function rename($type, array $args);

		abstract public function remove($type, array $args);

		abstract public function filter($type, $filter);

		public function clear($type)
		{
			$class = $this->_typeToClass($type);

			if($class !== false)
			{
				$objects =& $this->_objects[$class::OBJECT_KEY];		// /!\ Important
				$objects = array();

				$objectName = ucfirst($class::OBJECT_NAME);
				$this->_SHELL->print($objectName." réinitialisé", 'green');
				return true;
			}
			else {
				return false;
			}
		}

		public function format(Core\Api_Abstract $objectApi, array $listFields)
		{
			return $objectApi;
		}

		protected function _register(Core\Api_Abstract $objectApi, $checkValidity = false)
		{
			if(!$checkValidity || $objectApi->isValid())
			{
				$name = $this->normalizeName($objectApi->name);

				if($name !== false) {
					$key = $objectApi::OBJECT_KEY;
					$this->_objects[$key][$name] = $objectApi;
					return true;
				}
			}

			return false;
		}

		protected function _unregister(Core\Api_Abstract $objectApi, $checkPresence = false)
		{
			$key = $objectApi::OBJECT_KEY;
			$name = $this->normalizeName($objectApi->name);

			if(!$checkPresence || ($name !== false && array_key_exists($name, $this->_objects[$key]))) {
				unset($this->_objects[$key][$name]);
				return true;
			}
			else {
				return false;
			}
		}
	}