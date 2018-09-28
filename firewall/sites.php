<?php
	require_once(__DIR__ . '/site.php');

	class Firewall_Sites implements IteratorAggregate, ArrayAccess, Countable
	{
		protected $_CONFIG;
		protected $_sites;


		public function __construct(CONFIG $config)
		{
			$this->_CONFIG = $config;
			$this->_sites = $this->_CONFIG->FIREWALL->sites;
		}

		public function getSiteKeys()
		{
			return $this->_sites->keys();
		}

		public function key_exists($key)
		{
			return $this->_sites->key_exists($key);
		}

		public function getIterator()
		{
			return $this->_sites->getIterator();
		}

		public function offsetSet($offset, $value)
		{
		}

		public function offsetExists($offset)
		{
			return isset($this->_sites[$offset]);
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
			return $this->_sites->count();
		}

		public function __isset($name)
		{
			return $this->key_exists($name);
		}

		public function __get($name)
		{
			if(isset($this->{$name})) {
				return new Firewall_Site($name, $this->_sites[$name]->toArray());
			}
			else {
				throw new Exception("Site '".$name."' does not exist", E_USER_ERROR);
			}
		}
	}