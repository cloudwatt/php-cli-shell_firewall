<?php
	namespace App\Firewall\Core;

	use Core as C;

	abstract class Api_Address extends Api_Abstract implements Api_Interface
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
				'string&&!empty' => static::FIELD_ATTRS
			);

			return (C\Tools::is('string&&!empty', $this->_datas[static::FIELD_NAME]) && $this->_isValid($tests, $returnInvalidAttributes, 'OR'));
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

		public function wakeup(array $datas)
		{
			$datas = array_intersect_key($datas, $this->_datas);
			$datas = array_merge($this->_datas, $datas);

			// /!\ Permets de s'assurer que les traitements spéciaux sont bien appliqués
			$this->name($datas['name']);

			foreach(static::FIELD_ATTRS as $attribute)
			{
				if(array_key_exists($attribute, $datas)) {
					call_user_func(array($this, static::FIELD_ATTR_FCT), $datas[$attribute]);
				}
			}

			return true;
		}
	}