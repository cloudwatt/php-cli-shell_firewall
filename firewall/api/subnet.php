<?php
	class Firewall_Api_Subnet extends Firewall_Api_Address
	{
		const OBJECT_TYPE = 'subnet';
		const OBJECT_NAME = 'subnet';
		const FIELD_NAME = 'name';
		const FIELD_ATTRv4 = 'subnetV4';
		const FIELD_ATTRv6 = 'subnetV6';
		const FIELD_ATTRS = array(
			'subnetV4', 'subnetV6'
		);
		const FIELD_ATTR_FCT = 'subnet';
		const FIELD_ATTRS_FCT = 'subnets';

		protected $_datas = array(
			'name' => null,
			'subnetV4' => null,
			'subnetV6' => null,
		);


		public function __construct($name = null, $subnetV4 = null, $subnetV6 = null)
		{
			$this->name($name);
			$this->subnet($subnetV4);
			$this->subnet($subnetV6);
		}

		public function subnet($subnet)
		{
			$subnetParts = explode('/', $subnet, 2);

			if(count($subnetParts) === 2)
			{
				$networkIp = NETWORK_Tools::networkIp($subnetParts[0], $subnetParts[1]);

				if($networkIp !== false)
				{
					$subnet = $networkIp.'/'.$subnetParts[1];

					switch(true)
					{
						case Tools::is('ipv4', $networkIp):
							if($subnetParts[1] >= 1 && $subnetParts[1] <= 31) {
								$this->_datas['subnetV4'] = $subnet;
								return true;
							}
							break;
						case Tools::is('ipv6', $networkIp):
							if($subnetParts[1] >= 1 && $subnetParts[1] <= 127) {
								$this->_datas['subnetV6'] = $subnet;
								return true;
							}
							break;
						default:
							throw new Exception("Unable to know the version of this subnet '".$subnet."'", E_USER_ERROR);
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
	}