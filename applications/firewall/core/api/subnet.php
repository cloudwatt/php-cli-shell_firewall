<?php
	namespace App\Firewall\Core;

	class Api_Subnet extends Api_Address
	{
		const OBJECT_KEY = 'Firewall_Api_Subnet';
		const OBJECT_TYPE = 'subnet';
		const OBJECT_NAME = 'subnet';

		const FIELD_NAME = 'name';
		const FIELD_ATTRv4 = 'subnetV4';
		const FIELD_ATTRv6 = 'subnetV6';
		const FIELD_ATTRS = array(
			4 => 'subnetV4', 6 => 'subnetV6'
		);
		const FIELD_ATTR_FCT = 'subnet';
		const FIELD_ATTRS_FCT = 'subnets';

		const SEPARATOR = '/';

		protected $_datas = array(
			'_id_' => null,
			'name' => null,
			'subnetV4' => null,
			'subnetV6' => null,
		);


		/**
		  * @param string $id ID
		  * @param string $name Name
		  * @param string $subnetV4 Subnet v4
		  * @param string $subnetV6 Subnet v6
		  * @return $this
		  */
		public function __construct($id = null, $name = null, $subnetV4 = null, $subnetV6 = null)
		{
			$this->id($id);
			$this->name($name);
			$this->subnet($subnetV4);
			$this->subnet($subnetV6);
		}

		public function configure($address)
		{
			return $this->subnet($address);
		}

		public function subnet($subnet)
		{
			$subnetParts = explode('/', $subnet);

			if(count($subnetParts) === 2)
			{
				$networkIp = Tools::networkIp($subnetParts[0], $subnetParts[1]);

				if($networkIp !== false)
				{
					$subnet = $networkIp.'/'.$subnetParts[1];

					switch(true)
					{
						case Tools::isIPv4($networkIp):
						{
							// Autoriser 0.0.0.0/0 mais pas un /32
							if($subnetParts[1] >= 0 && $subnetParts[1] <= 31) {
								$this->_datas['subnetV4'] = $subnet;
								return true;
							}
							break;
						}

						case Tools::isIPv6($networkIp):
						{
							// Autoriser ::/0 mais pas un /128
							if($subnetParts[1] >= 0 && $subnetParts[1] <= 127) {
								$this->_datas['subnetV6'] = mb_strtolower($subnet);
								return true;
							}
							break;
						}
						default: {
							throw new Exception("Unable to know the version of this subnet '".$subnet."'", E_USER_ERROR);
						}
					}
				}
			}

			return false;
		}

		public function subnets($subnetV4, $subnetV6)
		{
			$statusV4 = $this->subnet($subnetV4);
			$statusV6 = $this->subnet($subnetV6);
			return ($statusV4 && $statusV6);
		}

		public function isANYv4()
		{
			return ($this->_datas['subnetV4'] === '0.0.0.0/0');
		}

		public function isANYv6()
		{
			if($this->isIPv6()) {
				$subnetParts = explode('/', $this->_datas['subnetV6']);
				$IPv6 = Tools::formatIPv6($subnetParts[0]);
				return ($IPv6 === '::' && $subnetParts[1] === '0');
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
					if($this->isIPv4() && $addressApi->isIPv4() && Tools::cidrMatch($addressApi->attributeV4, $this->attributeV4)) {
						return true;
					}
					elseif($this->isIPv6() && $addressApi->isIPv6() && Tools::cidrMatch($addressApi->attributeV6, $this->attributeV6)) {
						return true;
					}

					break;
				}

				case self::OBJECT_TYPE:
				{
					if($this->isIPv4() && $addressApi->isIPv4() && Tools::subnetInSubnet($addressApi->attributeV4, $this->attributeV4)) {
						return true;
					}
					elseif($this->isIPv6() && $addressApi->isIPv6() && Tools::subnetInSubnet($addressApi->attributeV6, $this->attributeV6)) {
						return true;
					}

					break;
				}

				case Api_Network::OBJECT_TYPE:
				{
					if($this->isIPv4() && $addressApi->isIPv4() &&
							Tools::cidrMatch($addressApi->beginV4, $this->attributeV4) &&
							Tools::cidrMatch($addressApi->finishV4, $this->attributeV4)
					) {
						return true;
					}
					elseif($this->isIPv6() && $addressApi->isIPv6() && 
							Tools::cidrMatch($addressApi->beginV6, $this->attributeV6) &&
							Tools::cidrMatch($addressApi->finishV6, $this->attributeV6)
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
				case 'networkV4':
				case 'networkIpV4':
				{
					if($this->isIPv4()) {
						$subnetParts = explode('/', $this->subnetV4);
						return $subnetParts[0];
					}
					else {
						return false;
					}
				}
				case 'maskV4':
				{
					if($this->isIPv4()) {
						$subnetParts = explode('/', $this->subnetV4);
						return $subnetParts[1];
					}
					else {
						return false;
					}
				}
				case 'netMaskV4':
				{
					if($this->isIPv4()) {
						$subnetParts = explode('/', $this->subnetV4);
						return Tools::cidrMaskToNetMask($subnetParts[1]);
					}
					else {
						return false;
					}
				}
				case 'broadcastIpV4':
				{
					if($this->isIPv4()) {
						$subnetParts = explode('/', $this->subnetV4);
						return Tools::broadcastIp($subnetParts[0], $subnetParts[1]);
					}
					else {
						return false;
					}
				}
				case 'networkV6':
				case 'networkIpV6':
				{
					if($this->isIPv6()) {
						$subnetParts = explode('/', $this->subnetV6);
						return $subnetParts[0];
					}
					else {
						return false;
					}
				}
				case 'maskV6':
				{
					if($this->isIPv6()) {
						$subnetParts = explode('/', $this->subnetV6);
						return $subnetParts[1];
					}
					else {
						return false;
					}
				}
				case 'broadcastIpV6':
				{
					if($this->isIPv6()) {
						$subnetParts = explode('/', $this->subnetV6);
						return Tools::broadcastIp($subnetParts[0], $subnetParts[1]);
					}
					else {
						return false;
					}
				}
				default: {
					return parent::__get($name);
				}
			}
		}
	}