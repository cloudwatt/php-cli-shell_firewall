<?php
	namespace App\Firewall\Core;

	use Core as C;

	abstract class Api_Address extends Api_Abstract implements Api_Interface
	{
		/**
		  * @param string $address
		  * @return App\Firewall\Core\Api_Address
		  */
		public static function factory($address)
		{
			switch(true)
			{
				case Tools::isIP($address): {
					return new Api_Host($address, $address, $address);
				}
				case Tools::isSubnet($address): {
					return new Api_Subnet($address, $address, $address);
				}
				case Tools::isNetwork($address, Api_Network::SEPARATOR): {
					return new Api_Network($address, $address, $address);
				}
				default: {
					return false;
				}
			}
		}

		abstract public function configure($address);

		public function isIPv($IPv)
		{
			switch($IPv)
			{
				case 4:
					return $this->isIPv4();
				case 6:
					return $this->isIPv6();
				default:
					throw new Exception("IP version must be 4 or 6 only", E_USER_ERROR);
			}
		}

		public function isIPv4()
		{
			return ($this->{static::FIELD_ATTRv4} !== null);
		}

		public function isIPv6()
		{
			return ($this->{static::FIELD_ATTRv6} !== null);
		}

		public function isDualStack()
		{
			return ($this->isIPv4() && $this->isIPv6());
		}

		public function isANY($IPv)
		{
			switch($IPv)
			{
				case 4:
					return $this->isANYv4();
				case 6:
					return $this->isANYv6();
				default:
					throw new Exception("IP version must be 4 or 6 only", E_USER_ERROR);
			}
		}

		abstract public function isANYv4();

		abstract public function isANYv6();

		public function reset($attribute = null)
		{
			switch($attribute)
			{
				case static::FIELD_ATTRv4:
				case static::FIELD_ATTRv6:
					$this->_datas[$attribute] = null;
					break;
				default:
					return false;
			}

			return true;
		}

		abstract public function includes(Api_Address $addressApi);

		public function isValid($returnInvalidAttributes = false)
		{		
			$tests = array(
				array(static::FIELD_NAME => 'string&&!empty'),
				array(
					static::FIELD_ATTRv4 => 'string&&!empty',
					static::FIELD_ATTRv6 => 'string&&!empty',
					/*static::FIELD_ATTRv4 => 'ipv4',
					static::FIELD_ATTRv6 => 'ipv6',*/
				),
			);

			return $this->_isValid($tests, $returnInvalidAttributes);
		}

		public function __get($name)
		{
			switch($name)
			{
				case 'ipv4':
				case 'attrV4':
				case 'attributeV4':
				case static::FIELD_ATTRv4: {
					return $this->_datas[static::FIELD_ATTRv4];
				}
				case 'ipv6':
				case 'attrV6':
				case 'attributeV6':
				case static::FIELD_ATTRv6: {
					return $this->_datas[static::FIELD_ATTRv6];
				}
				case 'ip':
				case 'attrs':
				case 'attributes':
				{
					return array(
						'ipv4' => $this->_datas[static::FIELD_ATTRv4],
						'ipv6' => $this->_datas[static::FIELD_ATTRv6]
					);
				}
				default: {
					return parent::__get($name);
				}
			}
		}

		/**
		  * @return array
		  */
		public function sleep()
		{
			$datas = parent::sleep();

			foreach(static::FIELD_ATTRS as $attribute)
			{
				if(array_key_exists($attribute, $this->_datas)) {
					$datas[$attribute] = $this->_datas[$attribute];
				}
			}

			return $datas;
		}

		/**
		  * @param $datas array
		  * @return bool
		  */
		public function wakeup(array $datas)
		{
			$parentStatus = parent::wakeup($datas);

			$attributeStatus = true;

			foreach(static::FIELD_ATTRS as $attribute)
			{
				if(array_key_exists($attribute, $datas) && $datas[$attribute] !== null) {
					$status = $this->configure($datas[$attribute]);
					if(!$status) { $attributeStatus = false; }	// On essaye d'attribuer tous les attributs
				}
			}

			return ($parentStatus && $attributeStatus);
		}
	}