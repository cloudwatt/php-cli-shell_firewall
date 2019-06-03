<?php
	namespace App\Firewall\Core;

	class Api_Host extends Api_Address
	{
		const OBJECT_KEY = 'Firewall_Api_Host';
		const OBJECT_TYPE = 'host';
		const OBJECT_NAME = 'host';

		const FIELD_NAME = 'name';
		const FIELD_ATTRv4 = 'addressV4';
		const FIELD_ATTRv6 = 'addressV6';
		const FIELD_ATTRS = array(
			4 => 'addressV4', 6 => 'addressV6'
		);
		const FIELD_ATTR_FCT = 'address';
		const FIELD_ATTRS_FCT = 'addresses';

		protected $_datas = array(
			'_id_' => null,
			'name' => null,
			'addressV4' => null,
			'addressV6' => null,
		);


		/**
		  * @param string $id ID
		  * @param string $name Name
		  * @param string $addressV4 Adress IP v4
		  * @param string $addressV6 Adress IP v6
		  * @return $this
		  */
		public function __construct($id = null, $name = null, $addressV4 = null, $addressV6 = null)
		{
			$this->id($id);
			$this->name($name);
			$this->address($addressV4);
			$this->address($addressV6);
		}

		public function configure($address)
		{
			return $this->address($address);
		}

		public function address($address)
		{
			if(Tools::isIPv4($address)) {
				$this->_datas['addressV4'] = $address;
				return true;
			}
			elseif(Tools::isIPv6($address)) {
				$this->_datas['addressV6'] = Tools::formatIPv6($address);
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

		public function isANYv4()
		{
			return ($this->_datas['addressV4'] === '0.0.0.0');
		}

		public function isANYv6()
		{
			if($this->isIPv6()) {
				$IPv6 = Tools::formatIPv6($this->_datas['addressV6']);
				return ($IPv6 === '::');
			}
			else {
				return false;
			}
		}

		public function includes(Api_Address $addressApi)
		{
			switch($addressApi::OBJECT_TYPE)
			{
				case self::OBJECT_TYPE:
				{
					if($this->isIPv4() && $addressApi->isIPv4() && $this->attributeV4 === $addressApi->attributeV4) {
						return true;
					}
					elseif($this->isIPv6() && $addressApi->isIPv6() && $this->attributeV6 === $addressApi->attributeV6) {
						return true;
					}

					break;
				}

				case Api_Subnet::OBJECT_TYPE:
				{
					// /!\ Qu'est-ce qui impacte $addressApi (subnet) ? Un host ($this) ne peut pas impacter un subnet ($addressApi)
					/*if($this->isIPv4() && $addressApi->isIPv4() && Tools::cidrMatch($this->attributeV4, $addressApi->attributeV4)) {
						return true;
					}
					elseif($this->isIPv6() && $addressApi->isIPv6() && Tools::cidrMatch($this->attributeV6, $addressApi->attributeV6)) {
						return true;
					}*/

					break;
				}

				case Api_Network::OBJECT_TYPE:
				{
					// /!\ Qu'est-ce qui impacte $addressApi (network) ? Un host ($this) ne peut pas impacter un network ($addressApi)
					/*if($this->isIPv4() && $addressApi->isIPv4() && 
							Tools::IpToBin($this->attributeV4) > Tools::IpToBin($addressApi->beginV4) &&
							Tools::IpToBin($this->attributeV4) < Tools::IpToBin($addressApi->finishV4)
					) {
						return true;
					}
					elseif($this->isIPv6() && $addressApi->isIPv6() && 
							Tools::IpToBin($this->attributeV6) > Tools::IpToBin($addressApi->beginV6) &&
							Tools::IpToBin($this->attributeV6) < Tools::IpToBin($addressApi->finishV6)
					) {
						return true;
					}*/

					break;
				}
			}

			return false;
		}
	}