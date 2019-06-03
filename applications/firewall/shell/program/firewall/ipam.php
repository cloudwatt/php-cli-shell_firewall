<?php
	namespace App\Firewall;

	use ArrayObject;

	use Core as C;

	use Addon\Ipam;

	use App\Firewall\Core;

	class Shell_Program_Firewall_Ipam
	{
		const FIELD_IPAM_SERVICE = '__ipam-srv__';
		const FIELD_IPAM_ATTRIBUTES = '__ipam-attrs__';


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
				case Core\Api_Host::OBJECT_TYPE: {
					$results = $this->getAddresses($arg, $strict);
					break;
				}
				case Core\Api_Subnet::OBJECT_TYPE: {
					$results = $this->getSubnets($arg, $strict);
					break;
				}
				case Core\Api_Network::OBJECT_TYPE: {
					$results = array();
					break;
				}
				default: {
					throw new Exception("Unknown type '".$type."'", E_USER_ERROR);
				}
			}

			return $results;
		}

		public function getSubnets($search, $strict = false)
		{
			$results = array();
			$subnets = $this->searchSubnets($search, $strict);

			foreach($subnets as $subnet)
			{
				$subnetName = $subnet[Core\Api_Subnet::FIELD_NAME];

				if(array_key_exists($subnetName, $results)) {
					$subnetObject = $results[$subnetName];
				}
				else {
					$results[$subnetName] = $subnet;
					continue;
				}

				$cidrIsIPv4 = ($subnet[Core\Api_Subnet::FIELD_ATTRv4] !== null);
				$cidrIsIPv6 = ($subnet[Core\Api_Subnet::FIELD_ATTRv6] !== null);

				if($cidrIsIPv4 && $subnetObject[Core\Api_Subnet::FIELD_ATTRv4] === null) {
					$subnetObject[Core\Api_Subnet::FIELD_ATTRv4] = $subnet[Core\Api_Subnet::FIELD_ATTRv4];
					//$subnetObject['attributeV4'] = $subnetObject[Core\Api_Subnet::FIELD_ATTRv4];
				}
				elseif($cidrIsIPv6 && $subnetObject[Core\Api_Subnet::FIELD_ATTRv6] === null) {
					$subnetObject[Core\Api_Subnet::FIELD_ATTRv6] = $subnet[Core\Api_Subnet::FIELD_ATTRv6];
					//$subnetObject['attributeV6'] = $subnetObject[Core\Api_Subnet::FIELD_ATTRv6];
				}
				elseif(!$cidrIsIPv4 && !$cidrIsIPv6) {
					throw new Exception("Unable to know the IP version of this subnet '".$subnetName."'", E_USER_ERROR);
				}
				else {
					throw new Exception("Duplicate subnet name found in IPAM '".$subnetName."'", E_USER_ERROR);
				}
			}

			return array_values($results);
		}

		public function getAddresses($search, $strict = false)
		{
			$results = array();
			$addresses = $this->searchAddresses($search, $strict);

			foreach($addresses as $address)
			{
				$addressName = $address[Core\Api_Host::FIELD_NAME];

				if(array_key_exists($addressName, $results)) {
					$addressObject = $results[$addressName];
				}
				else {
					$results[$addressName] = $address;
					continue;
				}

				$addressIsIPv4 = ($address[Core\Api_Host::FIELD_ATTRv4] !== null);
				$addressIsIPv6 = ($address[Core\Api_Host::FIELD_ATTRv6] !== null);

				if($addressIsIPv4 && $addressObject[Core\Api_Host::FIELD_ATTRv4] === null) {
					$addressObject[Core\Api_Host::FIELD_ATTRv4] = $address[Core\Api_Host::FIELD_ATTRv4];
					//$addressObject['attributeV4'] = $addressObject[Core\Api_Host::FIELD_ATTRv4];
				}
				elseif($addressIsIPv6 && $addressObject[Core\Api_Host::FIELD_ATTRv6] === null) {
					$addressObject[Core\Api_Host::FIELD_ATTRv6] = $address[Core\Api_Host::FIELD_ATTRv6];
					//$addressObject['attributeV6'] = $addressObject[Core\Api_Host::FIELD_ATTRv6];
				}
				elseif(!$addressIsIPv4 && !$addressIsIPv6) {
					throw new Exception("Unable to know the IP version of this address '".$address['ip']."'", E_USER_ERROR);
				}
				else {
					throw new Exception("Duplicate address name found in IPAM '".$addressName."'", E_USER_ERROR);
				}
			}

			return array_values($results);
		}

		public function searchObjects($type, $arg, $strict = true)
		{
			switch($type)
			{
				case Core\Api_Host::OBJECT_TYPE: {
					$results = $this->searchAddresses($arg, $strict);
					break;
				}
				case Core\Api_Subnet::OBJECT_TYPE: {
					$results = $this->searchSubnets($arg, $strict);
					break;
				}
				case Core\Api_Network::OBJECT_TYPE: {
					$results = array();
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
			$results = array();

			if($this->hasIpamAddon())
			{
				$IpamEnabled = Ipam\Orchestrator::hasInstance();

				if($IpamEnabled)
				{
					$subnets = array();
					$Ipam_Orchestrator = Ipam\Orchestrator::getInstance();

					foreach($Ipam_Orchestrator as $Ipam_Service)
					{
						$subnets[$Ipam_Service->id] = array();
						$Ipam_Orchestrator->useServiceId($Ipam_Service->id);

						$cidrSubnets = Ipam\Api_Subnet::searchCidrSubnets($search, null, null, null, $strict);

						/**
						  * Toujours rechercher un nom de subnet avec $search même si des résultats CIDR subnet ont été trouvés
						  * Un subnet peut se nommer par son CIDR dans l'IPAM donc il faut toujours effectuer la recherche
						  */
						$subnetNames = Ipam\Api_Subnet::searchSubnetNames($search, null, null, null, null, $strict);

						/**
						  * Recherche les entrées correspondants au nom des résultats de la recherche par subnet
						  * Permet d'obtenir l'ensemble des entrées correspondant à un subnet en partant d'un subnet
						  *
						  * Par exemple: Je recherche un subnet V4, je trouve un nom, je recherche ce nom, je trouve le subnet V6
						  */
						if(C\Tools::is('array&&count>0', $cidrSubnets))
						{
							if(!is_array($subnetNames)) {
								$subnetNames = array();
							}

							foreach($cidrSubnets as $index => $cidrSubnet)
							{
								if(C\Tools::is('string&&!empty', $cidrSubnet[Ipam\Api_Subnet::FIELD_NAME]))
								{
									$_subnetNames = Ipam\Api_Subnet::searchSubnetNames($cidrSubnet[Ipam\Api_Subnet::FIELD_NAME], null, null, null, null, $strict);

									if(C\Tools::is('array&&count>0', $_subnetNames))
									{
										$subnetNames = array_merge($subnetNames, $_subnetNames);

										/**
										  * /!\ Puisque l'on recherche dans un second temps par nom
										  * alors on aura des doublons si on ne réinitialise par les résultats de subnets
										  */
										unset($cidrSubnets[$index]);
									}
								}
							}
						}

						foreach(array($cidrSubnets, $subnetNames) as $_subnets)
						{
							if(C\Tools::is('array&&count>0', $_subnets)) {
								$subnets[$Ipam_Service->id] = array_merge($subnets[$Ipam_Service->id], $_subnets);
							}
						}
					}

					foreach($subnets as $serviceId => $_subnets)
					{
						$Ipam_Service = $Ipam_Orchestrator->getService($serviceId);

						foreach($_subnets as $subnet)
						{
							$subnetName = $subnet[Ipam\Api_Subnet::FIELD_NAME];
							$subnetName = preg_replace('#(^\s+)|(\s+$)#i', '', $subnetName);

							$subnetDatas = array(
								Core\Api_Subnet::FIELD_NAME => $subnetName,
								Core\Api_Subnet::FIELD_ATTRv4 => null,
								Core\Api_Subnet::FIELD_ATTRv6 => null,
								self::FIELD_IPAM_SERVICE => $Ipam_Service,
								self::FIELD_IPAM_ATTRIBUTES => $subnet
							);

							$subnetObject = new ArrayObject($subnetDatas, ArrayObject::ARRAY_AS_PROPS);

							$cidrSubnet = $subnet['subnet'].'/'.$subnet['mask'];

							if(C\Tools::is('ipv4', $subnet['subnet'])) {
								$subnetObject[Core\Api_Subnet::FIELD_ATTRv4] = $cidrSubnet;
							}
							elseif(C\Tools::is('ipv6', $subnet['subnet'])) {
								$subnetObject[Core\Api_Subnet::FIELD_ATTRv6] = $cidrSubnet;
							}
							else {
								throw new Exception("Unable to know the IP version of this subnet '".$subnet['subnet']."'", E_USER_ERROR);
							}

							$results[] = $subnetObject;
						}
					}
				}
			}

			return $results;
		}

		public function searchAddresses($search, $strict = false)
		{
			$results = array();

			if($this->hasIpamAddon())
			{
				$IpamEnabled = Ipam\Orchestrator::hasInstance();

				if($IpamEnabled)
				{
					$addresses = array();
					$Ipam_Orchestrator = Ipam\Orchestrator::getInstance();

					foreach($Ipam_Orchestrator as $Ipam_Service)
					{
						$addresses[$Ipam_Service->id] = array();
						$Ipam_Orchestrator->useServiceId($Ipam_Service->id);

						$addressIps = Ipam\Api_Address::searchIpAddresses($search, null, $strict);

						/**
						  * Toujours rechercher un nom d'hôte avec $search même si des résultats IP ont été trouvés
						  * Un hôte peut se nommer par son IP dans l'IPAM donc il faut toujours effectuer la recherche
						  */
						$addressNames = Ipam\Api_Address::searchAddressNames($search, null, null, $strict);
						$addressDescs = Ipam\Api_Address::searchAddressDescs($search, null, null, $strict);

						/**
						  * Recherche les entrées correspondants au nom des résultats de la recherche par IP
						  * Permet d'obtenir l'ensemble des entrées correspondant à une IP en partant d'une IP
						  *
						  * Par exemple: Je recherche une IPv4, je trouve un nom, je recherche ce nom, je trouve l'IPv6
						  */
						if(C\Tools::is('array&&count>0', $addressIps))
						{
							if(!is_array($addressNames)) {
								$addressNames = array();
							}

							foreach($addressIps as $index => $addressIp)
							{
								if(C\Tools::is('string&&!empty', $addressIp[Ipam\Api_Address::FIELD_NAME]))
								{
									$_addressNames = Ipam\Api_Address::searchAddressNames($addressIp[Ipam\Api_Address::FIELD_NAME], null, null, $strict);

									if(C\Tools::is('array&&count>0', $_addressNames))
									{
										$addressNames = array_merge($addressNames, $_addressNames);

										/**
										  * /!\ Puisque l'on recherche dans un second temps par nom
										  * alors on aura des doublons si on ne réinitialise par les résultats d'IPs
										  */
										unset($addressIps[$index]);
									}
								}
							}
						}

						foreach(array($addressIps, $addressNames, $addressDescs) as $_addresses)
						{
							if(C\Tools::is('array&&count>0', $_addresses)) {
								$addresses[$Ipam_Service->id] = array_merge($addresses[$Ipam_Service->id], $_addresses);
							}
						}
					}

					foreach($addresses as $serviceId => $_addresses)
					{
						$Ipam_Service = $Ipam_Orchestrator->getService($serviceId);

						foreach($_addresses as $address)
						{
							$addressName = $address[Ipam\Api_Address::FIELD_NAME];
							$addressName = preg_replace('#(^\s+)|(\s+$)#i', '', $addressName);

							if(!C\Tools::is('string&&!empty', $addressName)) {
								$addressName = $address[Ipam\Api_Address::FIELD_DESC];
							}

							$addressDatas = array(
								Core\Api_Host::FIELD_NAME => $addressName,
								Core\Api_Host::FIELD_ATTRv4 => null,
								Core\Api_Host::FIELD_ATTRv6 => null,
								self::FIELD_IPAM_SERVICE => $Ipam_Service,
								self::FIELD_IPAM_ATTRIBUTES => $address
							);

							$addressObject = new ArrayObject($addressDatas, ArrayObject::ARRAY_AS_PROPS);
							
							if(C\Tools::is('ipv4', $address['ip'])) {
								$addressObject[Core\Api_Host::FIELD_ATTRv4] = $address['ip'];
							}
							elseif(C\Tools::is('ipv6', $address['ip'])) {
								$addressObject[Core\Api_Host::FIELD_ATTRv6] = $address['ip'];
							}
							else {
								throw new Exception("Unable to know the IP version of this address '".$address['ip']."'", E_USER_ERROR);
							}

							$results[] = $addressObject;
						}
					}
				}
			}

			return $results;
		}

		public function isIpamAvailable()
		{
			if($this->hasIpamAddon()) {
				$Ipam_Orchestrator = Ipam\Orchestrator::getInstance();
				return (count($Ipam_Orchestrator) > 0);
			}
			else {
				return false;
			}
		}

		public static function hasIpamAddon()
		{
			return class_exists('Addon\Ipam\Orchestrator');
		}
	}
