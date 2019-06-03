<?php
	namespace App\Firewall;

	use ArrayObject;

	use Core as C;
	use Core\Exception as E;

	use Cli as Cli;

	use App\Firewall\Core;

	abstract class Shell_Program_Firewall_Object_Abstract extends Shell_Program_Firewall_Abstract
	{
		const OBJECT_IDS = array();

		const OBJECT_KEYS = array();

		const OBJECT_CLASSES = array();

		const VIEW_EXTENSIVE = 'extensive';
		const VIEW_SUMMARY = 'summary';
		const VIEW_DETAILS = 'summary';
		const VIEW_BRIEF = 'brief';
		const VIEW_TERSE = 'brief';

		const RETURN_OBJECT = 'object';
		const RETURN_ARRAY = 'array';
		const RETURN_TABLE = 'table';

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
			  * Normalisation du nom possible/réussi
			  * Dans ce cas on force le mode strictKey
			  *
			  * NON car si l'utilisateur demande TOTO alors normalizeName peut retourner toto
			  * Dans ce cas là $arg !== $name mais il ne faut pas forcer le mode strict
			  * car TOTO n'est pas forcément le nom complet de l'objet
			  */
			/*elseif($name !== $arg) {
				$strictKey = true;
			}*/

			return $this->_getObjects($type, $name, $strictKey, $strictMatch, $limit);
		}

		/**
		  * /!\ Publique, doit accepter un ID "humain"
		  * @return false|mixed Name
		  */
		public static function normalizeName($name)
		{
			return mb_strtolower($name);
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

					foreach($objects as $object)
					{
						if($object->match($name, $strictMatch))
						{
							$counter++;
							$results[] = $object;

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

		public function add(Core\Api_Abstract $objectApi, $checkValidity = true)
		{
			$type = $objectApi::OBJECT_TYPE;

			if($this->_typeIsAllowed($type) && (!$checkValidity || $objectApi->isValid()) && !$this->objectExists($type, $objectApi->name)) {
				$this->_register($objectApi);
				return true;
			}
			else {
				return false;
			}
		}

		public function insert($type, $name)
		{
			return false;
		}

		abstract public function create($type, array $args);

		public function clone($type, array $args)
		{
			return false;
		}

		/**
		  * @param string $type
		  * @param array $object
		  * @return false|App\Firewall\Core\Api_Abstract
		  */
		public function wakeup($type, array $object)
		{
			$objectApiClass = $this->_typeToClass($type);

			if($objectApiClass !== false) {
				$Core_Api_Abstract = new $objectApiClass();
				$status = $this->_wakeup($Core_Api_Abstract, $object);
				return ($status) ? ($Core_Api_Abstract): (false);
			}
			else {
				return false;
			}
		}

		/**
		  * @param string $type
		  * @param array $objects
		  * @param bool $checkValidity
		  * @return App\Firewall\Core\Api_Abstract[]
		  * @throw Exception|Core\Exception\Message
		  */
		public function restore($type, array $objects, $checkValidity = true)
		{
			$results = array();
			$objectApiClass = $this->_typeToClass($type);

			if($objectApiClass !== false)
			{
				foreach($objects as $index => $object)
				{
					$Core_Api_Abstract = new $objectApiClass();

					if(array_key_exists($objectApiClass::FIELD_NAME, $object)) {
						$name = $object[$objectApiClass::FIELD_NAME];
					}
					else {
						throw new E\Message("L'objet '".$Core_Api_Abstract::OBJECT_NAME."' index '".$index."' ne possède pas de nom", E_USER_ERROR);
					}

					if(!$this->objectExists($type, $name))
					{
						try {
							$status = $this->_wakeup($Core_Api_Abstract, $object);
						}
						catch(E\Message $exception) {
							$eMessage = "Une erreur s'est produite lors de la restauration de l'objet ";
							$eMessage .= "'".$Core_Api_Abstract::OBJECT_NAME."' '".$name."':";
							$eMessage .= PHP_EOL.$exception->getMessage();
							throw new E\Message($eMessage, E_USER_ERROR);
						}

						if($status)
						{
							if($checkValidity) {
								$invalidFieldNames = $Core_Api_Abstract->isValid(true);
							}
							else {
								$invalidFieldNames = array();
							}

							if(count($invalidFieldNames) === 0)
							{
								$isAdded = $this->add($Core_Api_Abstract, false);

								if($isAdded) {
									$results[] = $Core_Api_Abstract;
								}
								else {
									throw new E\Message("L'objet '".$Core_Api_Abstract::OBJECT_NAME."' '".$name."' n'a pas pu être ajouté", E_USER_ERROR);
								}
							}
							else {
								$invalidFields = "(".implode(', ', $invalidFieldNames).")";
								throw new E\Message("L'objet '".$Core_Api_Abstract::OBJECT_NAME."' '".$name."' ne semble pas valide ".$invalidFields, E_USER_ERROR);
							}
						}
						else {
							throw new E\Message("L'objet '".$Core_Api_Abstract::OBJECT_NAME."' '".$name."' ne peut être restauré", E_USER_ERROR);
						}
					}
				}

				return $results;
			}
			else {
				throw new Exception("Unknown ".static::OBJECT_NAME." type '".$type."'", E_USER_ERROR);
			}
		}

		/**
		  * @param App\Firewall\Core\Api_Abstract $Core_Api_Abstract
		  * @param array $object
		  * @return bool
		  */
		protected function _wakeup(Core\Api_Abstract $Core_Api_Abstract, array $object)
		{
			return $Core_Api_Abstract->wakeup($object);
		}

		public function edit(Core\Api_Abstract $objectApi, $checkValidity = true)
		{
			return false;
		}

		public function update($type, $name)
		{
			return false;
		}

		abstract public function modify($type, array $args);

		public function move(Core\Api_Abstract $objectApi, $newName)
		{
			return false;
		}

		public function appoint($type, $name, $newName)
		{
			return false;
		}

		public function rename($type, array $args)
		{
			return false;
		}

		public function drop(Core\Api_Abstract $objectApi, $checkInstance = false)
		{
			return false;
		}

		public function delete($type, $name)
		{
			return false;
		}

		abstract public function remove($type, array $args);

		public function locate($type, $search, $strict = false)
		{
			return false;
		}

		public function filter($type, $filter, $strict = false)
		{
			return false;
		}

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

		public function format(Core\Api_Abstract $objectApi, array $listFields, $view)
		{
			return $this->_format($objectApi, $listFields, $view, self::RETURN_OBJECT);
		}

		public function formatToObject(Core\Api_Abstract $objectApi, array $listFields, $view)
		{
			return $this->_format($objectApi, $listFields, $view, self::RETURN_OBJECT);
		}

		public function formatToArray(Core\Api_Abstract $objectApi, array $listFields, $view)
		{
			return $this->_format($objectApi, $listFields, $view, self::RETURN_ARRAY);
		}

		public function formatToTable(Core\Api_Abstract $objectApi, array $listFields, $view)
		{
			return $this->_format($objectApi, $listFields, $view, self::RETURN_TABLE);
		}

		protected function _format(Core\Api_Abstract $objectApi, array $listFields, $view, $return)
		{
			switch($return)
			{
				case self::RETURN_OBJECT: {
					return $objectApi->toObject();
				}
				case self::RETURN_ARRAY: {
					return $objectApi->toArray();
				}
				case self::RETURN_TABLE: {
					$item = $objectApi->toArray();
					return C\Tools::formatShellTable(array($item));
				}
				default: {
					throw new Exception("Format return type '".$return."' is not valid", E_USER_ERROR);
				}
			}
		}

		/**
		  * @param App\Firewall\Core\Api_Abstract $objectApi
		  * @param bool $checkPresence
		  * @param bool $checkValidity
		  * @return bool
		  */
		protected function _register(Core\Api_Abstract $objectApi, $checkPresence = false, $checkValidity = false)
		{
			$key = $objectApi::OBJECT_KEY;
			$name = $this->normalizeName($objectApi->name);

			if(!$checkPresence || ($name !== false && array_key_exists($name, $this->_objects[$key])))
			{
				if(!$checkValidity || $objectApi->isValid())
				{
					$this->_objects[$key][$name] = $objectApi;

					/**
					  * Permet de s'assurer que l'ordre des objets est correct
					  * /!\ NE PAS EFFECTUER UN KSORT SINON LE GIT DIFF NE SERA PAS LISIBLE
					  */
					//uksort($this->_objects[$key], 'strnatcasecmp');

					return true;
				}
			}

			return false;
		}

		/**
		  * @param App\Firewall\Core\Api_Abstract $objectApi
		  * @param bool $checkPresence
		  * @param bool $checkInstance
		  * @return bool
		  */
		protected function _unregister(Core\Api_Abstract $objectApi, $checkPresence = false, $checkInstance = false)
		{
			$key = $objectApi::OBJECT_KEY;
			$name = $this->normalizeName($objectApi->name);

			if(!$checkPresence || ($name !== false && array_key_exists($name, $this->_objects[$key])))
			{
				// http://php.net/manual/fr/language.oop5.object-comparison.php
				if(!$checkInstance || $objectApi === $this->_objects[$key][$name]) {
					unset($this->_objects[$key][$name]);
					return true;
				}
			}
	
			return false;
		}
	}