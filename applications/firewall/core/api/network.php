<?php
	namespace App\Firewall\Core;

	class Api_Network extends Api_Address
	{
		const OBJECT_KEY = 'Firewall_Api_Network';
		const OBJECT_TYPE = 'network';
		const OBJECT_NAME = 'network';

		const FIELD_NAME = 'name';
		const FIELD_ATTRv4 = 'networkV4';
		const FIELD_ATTRv6 = 'networkV6';
		const FIELD_ATTRS = array(
			4 => 'networkV4', 6 => 'networkV6'
		);
		const FIELD_ATTR_FCT = 'network';
		const FIELD_ATTRS_FCT = 'networks';

		const SEPARATOR = '-';

		protected $_datas = array(
			'_id_' => null,
			'name' => null,
			'networkV4' => null,
			'networkV6' => null,
		);


		/**
		  * @param string $id ID
		  * @param string $name Name
		  * @param string $networkV4 Network v4
		  * @param string $networkV6 Network v6
		  * @return $this
		  */
		public function __construct($id = null, $name = null, $networkV4 = null, $networkV6 = null)
		{
			$this->id($id);
			$this->name($name);
			$this->network($networkV4);
			$this->network($networkV6);
		}

		public function configure($address)
		{
			return $this->network($address);
		}

		public function network($network)
		{
			$networkParts = explode(self::SEPARATOR, $network, 2);

			if(count($networkParts) === 2)
			{
				if(Tools::isIPv4($networkParts[0]) && Tools::isIPv4($networkParts[1])) {
					$this->_datas['networkV4'] = $network;
					return true;
				}
				elseif(Tools::isIPv6($networkParts[0]) && Tools::isIPv6($networkParts[1])) {
					$this->_datas['networkV6'] = mb_strtolower($network);
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

		public function isANYv4()
		{
			return ($this->_datas['networkV4'] === '0.0.0.0'.self::SEPARATOR.'255.255.255.255');
		}

		public function isANYv6()
		{
			if($this->isIPv6()) {
				$networkParts = explode(self::SEPARATOR, $this->_datas['networkV6']);
				$IPv6_first = Tools::formatIPv6($networkParts[0]);
				$IPv6_second = Tools::formatIPv6($networkParts[1]);
				return ($IPv6_first === '::' && $IPv6_second === 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');
			}
			else {
				return false;
			}
		}

		public function includes(Api_Address $addressApi)
		{
			switch($addressApi::OBJECT_TYPE)
			{
				case Api_Host::OBJECT_TYPE:
				{
					if($this->isIPv4() && $addressApi->isIPv4() && 
							Tools::IpToBin($addressApi->attributeV4) >= Tools::IpToBin($this->beginV4) &&
							Tools::IpToBin($addressApi->attributeV4) <= Tools::IpToBin($this->finishV4)
					) {
						return true;
					}
					elseif($this->isIPv6() && $addressApi->isIPv6() && 
							Tools::IpToBin($addressApi->attributeV6) >= Tools::IpToBin($this->beginV6) &&
							Tools::IpToBin($addressApi->attributeV6) <= Tools::IpToBin($this->finishV6)
					) {
						return true;
					}

					break;
				}

				case Api_Subnet::OBJECT_TYPE:
				{
					if($this->isIPv4() && $addressApi->isIPv4())
					{
						$firstIPv4 = Tools::firstSubnetIp($addressApi->attributeV4);
						$lastIPv4 = Tools::lastSubnetIp($addressApi->attributeV4);

						if(Tools::IpToBin($firstIPv4) >= Tools::IpToBin($this->beginV4) &&
							Tools::IpToBin($lastIPv4) <= Tools::IpToBin($this->finishV4)
						) {
							return true;
						}
					}

					if($this->isIPv6() && $addressApi->isIPv6())
					{
						$firstIPv6 = Tools::firstSubnetIp($addressApi->attributeV6);
						$lastIPv6 = Tools::lastSubnetIp($addressApi->attributeV6);

						if(Tools::IpToBin($firstIPv6) >= Tools::IpToBin($this->beginV6) &&
							Tools::IpToBin($lastIPv6) <= Tools::IpToBin($this->finishV6)
						) {
							return true;
						}
					}

					break;
				}

				case self::OBJECT_TYPE:
				{
					if($this->isIPv4() && $addressApi->isIPv4() && 
							Tools::IpToBin($addressApi->beginV4) >= Tools::IpToBin($this->beginV4) &&
							Tools::IpToBin($addressApi->finishV4) <= Tools::IpToBin($this->finishV4)
					) {
						return true;
					}
					elseif($this->isIPv6() && $addressApi->isIPv6() && 
							Tools::IpToBin($addressApi->beginV6) >= Tools::IpToBin($this->beginV6) &&
							Tools::IpToBin($addressApi->finishV6) <= Tools::IpToBin($this->finishV6)
					) {
						return true;
					}

					break;
				}
			}

			return false;
		}

		public function __get($name)
		{
			switch($name)
			{
				case 'firstV4':
				case 'beginV4': {
					$parts = explode(self::SEPARATOR, $this->_datas['networkV4'], 2);
					return $parts[0];
				}
				case 'secondV4':
				case 'finishV4': {
					$parts = explode(self::SEPARATOR, $this->_datas['networkV4'], 2);
					return $parts[1];
				}
				case 'firstV6':
				case 'beginV6': {
					$parts = explode(self::SEPARATOR, $this->_datas['networkV6'], 2);
					return $parts[0];
				}
				case 'secondV6':
				case 'finishV6': {
					$parts = explode(self::SEPARATOR, $this->_datas['networkV6'], 2);
					return $parts[1];
				}
				default: {
					return parent::__get($name);
				}
			}
		}
	}