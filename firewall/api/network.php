<?php
	class Firewall_Api_Network extends Firewall_Api_Address
	{
		const OBJECT_TYPE = 'network';
		const OBJECT_NAME = 'network';
		const FIELD_NAME = 'name';
		const FIELD_ATTRv4 = 'networkV4';
		const FIELD_ATTRv6 = 'networkV6';
		const FIELD_ATTRS = array(
			'networkV4', 'networkV6'
		);
		const FIELD_ATTR_FCT = 'network';
		const FIELD_ATTRS_FCT = 'networks';

		protected $_datas = array(
			'name' => null,
			'networkV4' => null,
			'networkV6' => null,
		);


		public function __construct($name = null, $networkV4 = null, $networkV6 = null)
		{
			$this->name($name);
			$this->network($networkV4);
			$this->network($networkV6);
		}

		public function network($network)
		{
			$networkParts = explode('-', $network, 2);

			if(count($networkParts) === 2)
			{
				if(Tools::is('ipv4', $networkParts[0]) && Tools::is('ipv4', $networkParts[1])) {
					$this->_datas['networkV4'] = $network;
					return true;
				}
				elseif(Tools::is('ipv6', $networkParts[0]) && Tools::is('ipv6', $networkParts[1])) {
					$this->_datas['networkV6'] = $network;
					return true;
				}
			}

			return false;
		}

		public function networks($networkV4, $networkV6)
		{
			$statusV4 = $this->network($networkV4);
			$statusV6 = $this->network($networkV6);
			return ($statusV4 && $statusV6);
		}

		public function __get($name)
		{
			switch($name)
			{
				case 'firstV4':
				case 'beginV4': {
					$parts = explode('-', $this->_datas['networkV4'], 2);
					return $parts[0];
				}
				case 'secondV4':
				case 'finishV4': {
					$parts = explode('-', $this->_datas['networkV4'], 2);
					return $parts[1];
				}
				case 'firstV6':
				case 'beginV6': {
					$parts = explode('-', $this->_datas['networkV6'], 2);
					return $parts[0];
				}
				case 'secondV6':
				case 'finishV6': {
					$parts = explode('-', $this->_datas['networkV6'], 2);
					return $parts[1];
				}
				default: {
					return parent::__get($name);
				}
			}
		}
	}