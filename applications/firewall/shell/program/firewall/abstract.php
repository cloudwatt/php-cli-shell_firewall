<?php
	namespace App\Firewall;

	abstract class Shell_Program_Firewall_Abstract
	{
		const OBJECT_IDS = array();

		const OBJECT_KEYS = array();

		const OBJECT_CLASSES = array();


		/**
		  * @param $type string
		  * @return bool
		  */
		public function isType($type)
		{
			return in_array($type, static::OBJECT_IDS, true);
		}

		/**
		  * @param $type string
		  * @return false|string
		  */
		public function typeToName($type, $ucFirst = false, $strToUpper = false)
		{
			$class = $this->_typeToClass($type);

			if($class !== false)
			{
				if($ucFirst) {
					return ucfirst($class::OBJECT_NAME);
				}
				elseif($strToUpper) {
					return strtoupper($class::OBJECT_NAME);
				}
				else {
					return $class::OBJECT_NAME;
				}
			}
			else {
				return false;
			}
		}

		/**
		  * @param $type string
		  * @param $throwException bool
		  * @throw App\Firewall\Exception
		  * @return bool
		  */
		protected function _typeIsAllowed($type, $throwException = true)
		{
			if(array_key_exists($type, static::OBJECT_KEYS)) {
				return true;
			}
			elseif($throwException) {
				throw new Exception("Objects of type '".$type."' can not be managed by '".get_class()."'", E_USER_ERROR);
			}
			else {
				return false;
			}
		}

		/**
		  * @param $type string
		  * @return false|string
		  */
		protected function _typeToKey($type)
		{
			return (array_key_exists($type, static::OBJECT_KEYS)) ? (static::OBJECT_KEYS[$type]) : (false);
		}

		/**
		  * @param $type string
		  * @return false|string
		  */
		protected function _typeToClass($type)
		{
			return (array_key_exists($type, static::OBJECT_CLASSES)) ? (static::OBJECT_CLASSES[$type]) : (false);
		}

		/**
		  * @param $key string
		  * @return false|string
		  */
		protected function _keyToType($key)
		{
			$types = array_keys(static::OBJECT_KEYS, $key, true);
			return (count($types) === 1) ? (current($types)) : (false);
		}

		/**
		  * @param $class string
		  * @return false|string
		  */
		protected function _classToType($class)
		{
			$types = array_keys(static::OBJECT_CLASSES, $class, true);
			return (count($types) === 1) ? (current($types)) : (false);
		}
	}