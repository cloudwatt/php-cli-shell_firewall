<?php
	class Firewall_Api_Host extends Firewall_Api_Address
	{
		const OBJECT_TYPE = 'host';
		const OBJECT_NAME = 'host';
		const FIELD_NAME = 'name';
		const FIELD_ATTRv4 = 'addressV4';
		const FIELD_ATTRv6 = 'addressV6';
		const FIELD_ATTRS = array(
			'addressV4', 'addressV6'
		);
		const FIELD_ATTR_FCT = 'address';
		const FIELD_ATTRS_FCT = 'addresses';

		protected $_datas = array(
			'name' => null,
			'addressV4' => null,
			'addressV6' => null,
		);


		public function __construct($name = null, $addressV4 = null, $addressV6 = null)
		{
			$this->name($name);
			$this->address($addressV4);
			$this->address($addressV6);
		}

		public function address($address)
		{
			if(Tools::is('ipv4', $address)) {
				$this->_datas['addressV4'] = $address;
				return true;
			}
			elseif(Tools::is('ipv6', $address)) {
				$this->_datas['addressV6'] = $address;
				return true;
			}

			return false;
		}

		public function addresses($addressV4, $addressV6)
		{
			$statusV4 = $this->address($addressV4);
			$statusV6 = $this->address($addressV6);
			return ($statusV4 && $statusV6);
		}
	}