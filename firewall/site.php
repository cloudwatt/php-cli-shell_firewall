<?php
	class Firewall_Site implements IteratorAggregate, ArrayAccess, Countable
	{
		protected $_name;
		protected $_datas;


		public function __construct($name, array $datas)
		{
			$this->_name = $name;
			$this->_datas = $datas;
		}

		public function getGuiProtocol()
		{
			return $this->_datas['gui'];
		}

		public function getGuiAddress()
		{
			return $this->_datas['ip'];
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
				return $this->{$offset};
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
			return $this->_datas;
		}

		public function toObject()
		{
			return new MyArrayObject($this->_datas);
		}

		protected function _format($data)
		{
			if(is_array($data)) {
				$className = static::class;
				return new $className($this->_name, $data);
			}
			else {
				return $data;
			}
		}

		public function __isset($name)
		{
			return array_key_exists($name, $this->_datas);
		}

		public function __get($name)
		{
			switch($name)
			{
				case 'name': {
					return $this->_name;
				}
				default:
				{
					if(isset($this->{$name})) {
						return $this->_format($this->_datas[$name]);
					}
					else {
						throw new Exception("Attribute name '".$name."' does not exist", E_USER_ERROR);
					}
				}
			}
		}
	}