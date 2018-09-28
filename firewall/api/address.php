<?php
	abstract class Firewall_Api_Address extends Firewall_Api_Abstract
	{
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

		public function isValid($returnInvalidAttributes = false)
		{
			return ($this->_datas['name'] !== null && ($this->_datas[static::FIELD_ATTRv4] !== null || $this->_datas[static::FIELD_ATTRv6] !== null));
		}

		public function __get($name)
		{
			switch($name)
			{
				case 'ipv4':
				case 'attrV4':
				case 'attributeV4': {
					return $this->_datas[static::FIELD_ATTRv4];
				}
				case 'ipv6':
				case 'attrV6':
				case 'attributeV6': {
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
	}