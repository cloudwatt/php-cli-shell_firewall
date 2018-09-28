<?php
	abstract class Firewall_Api_Abstract implements IteratorAggregate, ArrayAccess, Countable
	{
		protected $_datas = array(
			'type' => null,			// /!\ Réservé pour le type de l'objet, voir toArray()
			'name' => null,			// /!\ Réservé pour le nom de l'objet, voir toArray()
		);


		public function name($name)
		{
			if(Tools::is('string&&!empty', $name) || Tools::is('int&&>=0', $name)) {
				$this->_datas['name'] = (string) $name;
				return true;
			}

			return false;
		}

		public function match($search)
		{
			foreach(static::FIELD_ATTRS as $attribute)
			{
				$result = preg_match("#^".preg_quote($search)."#", $this->_datas[$attribute]);

				if($result > 0) {
					return true;
				}
			}

			return false;
		}

		public function isValid($returnInvalidAttributes = false)
		{
			foreach(static::FIELD_ATTRS as $attribute)
			{
				$isValid = ($this->_datas[$attribute] !== null);

				if(!$isValid) {
					return false;
				}
			}

			return ($this->_datas['name'] !== null);
		}

		public function getIterator()
		{
			return new ArrayIterator($this->_datas);
		}

		public function offsetSet($offset, $value)
		{
		}

		public function offsetExists($offset)
		{
			return isset($this->_datas[$offset]);
		}

		public function offsetUnset($offset)
		{
		}

		public function offsetGet($offset)
		{
			if($this->offsetExists($offset)) {
				return $this->_datas[$offset];
			}
			else {
				return null;
			}
		}

		public function count()
		{
			return count($this->_datas);
		}

		public function toArray()
		{
			$datas = $this->_datas;
			$datas['type'] = static::OBJECT_TYPE;

			// /!\ Permet de garder une cohérence
			if(static::FIELD_NAME !== 'name') {
				$datas['name'] = $datas[static::FIELD_NAME];
			}
			
			return $datas;
		}

		public function toObject()
		{		
			return new ArrayObject($this->toArray(), ArrayObject::ARRAY_AS_PROPS);
		}

		public function __isset($name)
		{
			return array_key_exists($name, $this->_datas);
		}

		public function __get($name)
		{
			switch($name)
			{
				case 'type': {
					return static::OBJECT_TYPE;
				}
				case 'name':
				case 'label': {
					return $this->_datas[static::FIELD_NAME];
				}
				default:
				{
					if(isset($this->{$name})) {
						return $this->_datas[$name];
					}
					else {
						throw new Exception("This attribute '".$name."' does not exist", E_USER_ERROR);
					}
				}
			}
		}

		public function __toString()
		{
			return $this->name;
		}

		public function sleep()
		{
			return $this->_datas;
		}

		public function wakeup(array $datas, ArrayObject $objects = null)
		{
			$this->_datas = $datas;
			return true;
		}
	}