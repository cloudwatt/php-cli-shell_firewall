<?php
	class Service_Shell_Firewall_Ipam
	{
		/*public function getObject($type, $id)
		{
			$results = $this->getObjects($type, $id, true);

			switch(count($results))
			{
				case 0: {
					return false;
				}
				case 1: {
					return current($results);
				}
				default:
				{
					// Best effort: Ne traite que le champs name
					$nameField = constant(self::OBJECT_TYPE_CLASS[$type].'::FIELD_NAME');

					foreach($results as $result)
					{
						if($result[$nameField] === $id) {
							return $result;
						}
					}

					return false;
				}
			}
		}*/

		public function getObjects($type, $arg, $strict = true)
		{
			switch($type)
			{
				case Firewall_Api_Host::OBJECT_TYPE: {
					$results = $this->searchAddresses($arg, $strict);
					break;
				}
				case Firewall_Api_Subnet::OBJECT_TYPE: {
					$results = $this->searchSubnets($arg, $strict);
					break;
				}
				default: {
					throw new Exception("Unknown type '".$type."'", E_USER_ERROR);
				}
			}

			return $results;
		}

		public function searchSubnets($search, $strict = false)
		{
			$subnets = array();

			$aIPAM = Ipam_Api_Abstract::getIpam();

			if(Tools::is('array&&count>0', $aIPAM))
			{
				foreach($aIPAM as $key => $IPAM)
				{
					Ipam_Api_Abstract::enableIpam($key);
					$cidrSubnets = Ipam_Api_Subnet::searchCidrSubnets($search, $strict);
					$subnetNames = Ipam_Api_Subnet::searchSubnetNames($search, $strict);

					foreach(array($cidrSubnets, $subnetNames) as $_subnets)
					{
						if(Tools::is('array&&count>0', $_subnets)) {
							$subnets = array_merge($subnets, $_subnets);
						}
					}
				}

				foreach($subnets as &$subnet)
				{
					$subnetObject = new ArrayObject(array('name' => $subnet[Ipam_Api_Subnet::FIELD_NAME]), ArrayObject::ARRAY_AS_PROPS);

					$cidrSubnet = $subnet['subnet'].'/'.$subnet['mask'];

					if(Tools::is('ipv4', $subnet['subnet'])) {
						$subnetObject['subnetV4'] = $cidrSubnet;
						$subnetObject['subnetV6'] = null;
					}
					elseif(Tools::is('ipv6', $subnet['subnet'])) {
						$subnetObject['subnetV4'] = null;
						$subnetObject['subnetV6'] = $cidrSubnet;
					}
					else {
						throw new Exception("Unable to know the version of this subnet '".$cidrSubnet."'", E_USER_ERROR);
					}

					$subnet = $subnetObject;
				}
			}

			return $subnets;
		}

		public function searchAddresses($search, $strict = false)
		{
			$addresses = array();

			$aIPAM = Ipam_Api_Abstract::getIpam();

			if(Tools::is('array&&count>0', $aIPAM))
			{
				foreach($aIPAM as $key => $IPAM)
				{
					Ipam_Api_Abstract::enableIpam($key);
					$addressIps = Ipam_Api_Address::searchIpAddresses($search, $strict);
					$addressNames = Ipam_Api_Address::searchAddressNames($search, $strict);
					$addressDescs = Ipam_Api_Address::searchAddressDescs($search, $strict);

					foreach(array($addressIps, $addressNames, $addressDescs) as $_addresses)
					{
						if(Tools::is('array&&count>0', $_addresses)) {
							$addresses = array_merge($addresses, $_addresses);
						}
					}
				}

				foreach($addresses as &$address)
				{
					$name = $address[Ipam_Api_Address::FIELD_NAME];

					if(!Tools::is('string&&!empty', $name)) {
						$name = $address[Ipam_Api_Address::FIELD_DESC];
					}

					$addressObject = new ArrayObject(array('name' => $name), ArrayObject::ARRAY_AS_PROPS);

					if(Tools::is('ipv4', $address['ip'])) {
						$addressObject['addressV4'] = $address['ip'];
						$addressObject['addressV6'] = null;
					}
					elseif(Tools::is('ipv6', $address['ip'])) {
						$addressObject['addressV4'] = null;
						$addressObject['addressV6'] = $address['ip'];
					}
					else {
						throw new Exception("Unable to know the version of this address '".$address['ip']."'", E_USER_ERROR);
					}

					$address = $addressObject;
				}
			}

			return $addresses;
		}
	}