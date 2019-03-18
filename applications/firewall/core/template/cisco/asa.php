<?php
	namespace App\Firewall\Core;

	use ArrayObject;

	use Addon\Ipam;

	class Template_Cisco_Asa extends Template_Abstract
	{
		const PLATFORM = 'cisco';
		const TEMPLATE = 'asa';

		const ALLOW_RULE_MULTIZONES = self::RULE_MULTIZONES_DST;

		const ADD_NAME_PREFIX = '';
		const APP_NAME_PREFIX = '';
		const ACL_NAME_PREFIX = '';

		const ADDRESS_IPv_SEPARATOR = '-';
		const ADDRESS_ESCAPE_CHARACTERS = '---';

		const ADDRESS_SUBNET_IPv_SEPARATOR = '-network';


		protected function _toObjectAdd(Api_Address $addressApi, $zone = null)
		{
			$objectAdd = $this->_getObjectAdd($addressApi, $zone);

			if($objectAdd !== false) {
				return $objectAdd;
			}

			$addresses = array();

			$apiAddressName = $addressApi->name;
			$isSubnet = ($addressApi::OBJECT_TYPE === Api_Subnet::OBJECT_TYPE);

			/**
			  * CLEANER
			  */
			if($isSubnet) {
				$addressName = ltrim($apiAddressName, Ipam\Api_Subnet::SEPARATOR_SECTION);
				$addressName = str_ireplace(Ipam\Api_Subnet::SEPARATOR_SECTION, self::ADDRESS_ESCAPE_CHARACTERS, $addressName);
			}
			else {
				$addressName = $apiAddressName;
			}

			foreach(array('4' => $addressApi::FIELD_ATTRv4, '6' => $addressApi::FIELD_ATTRv6) as $IPv => $attrName)
			{
				if(!$addressApi->isIPv($IPv)) {
					continue;
				}		

				// Permet d'économiser de la mémoire en retournant un objet, voir _toPolicyAcl
				$result = new ArrayObject(array(), ArrayObject::ARRAY_AS_PROPS);

				if($addressApi->isANY($IPv)) {
					$name = 'any'.$IPv;
					$result['__doNotCreateAdd__'] = true;
				}
				else {
					$addressIPvSeparator = ($isSubnet) ? (self::ADDRESS_SUBNET_IPv_SEPARATOR) : (self::ADDRESS_IPv_SEPARATOR);
					$name = self::ADD_NAME_PREFIX.$addressName.$addressIPvSeparator.$IPv;
				}

				$type = $addressApi::OBJECT_TYPE;
				$address = $addressApi->{$attrName};

				if($addressApi::OBJECT_TYPE === Api_Network::OBJECT_TYPE) {
					$address = explode(Api_Network::SEPARATOR, $address);
				}

				$result['name'] = $name;
				$result['type'] = $type;
				$result['address'] = $address;
				$result['IPv'] = $IPv;

				$addresses[] = $result;

				/**
				  * /!\ Important, utiliser $apiAddressName et non $addressName
				  * Voir méthode _getObjectAdd, la vérification est effectuée avec le nom d'origine
				  */
				$this->_addressBook[$apiAddressName][] = $result;
			}

			return $addresses;
		}

		protected function _toProtocolApp(Api_Protocol $protocolApi, $zone = null)
		{
			$protocolApp = $this->_getProtocolApp($protocolApi, $zone);

			if($protocolApp !== false) {
				return $protocolApp;
			}

			// Permet d'économiser de la mémoire en retournant un objet, voir _toPolicyAcl
			$result = new ArrayObject(array(), ArrayObject::ARRAY_AS_PROPS);

			$protocolName = $protocolApi->name;
			$protocol = $protocolApi->protocol;

			$result['name'] = self::APP_NAME_PREFIX;

			$result['name'].= str_replace(
				array(
					$protocolApi::PROTO_SEPARATOR,
					$protocolApi::PROTO_RANGE_SEPARATOR,
					$protocolApi::PROTO_OPTIONS_SEPARATOR
				),
				array('-', '-', '-'),
				$protocol
			);

			$protocolParts = explode($protocolApi::PROTO_SEPARATOR, $protocol);

			$result['protocol'] = $protocolParts[0];

			if(array_key_exists(1, $protocolParts))
			{
				switch($result['protocol'])
				{
					case 'tcp':
					case 'udp': {
						$result['options'] = explode($protocolApi::PROTO_RANGE_SEPARATOR, $protocolParts[1]);
						break;
					}
					case 'icmp':
					case 'icmp4':
					case 'icmp6':
					{
						$options = explode($protocolApi::PROTO_OPTIONS_SEPARATOR, $protocolParts[1], 2);

						$result['options']['type'] = $options[0];

						if(array_key_exists(1, $options)) { 
							$result['options']['code'] = $options[1];
						}
						break;
					}
				}
			}

			$this->_applications[$protocolName] = $result;
			return $result;
		}

		protected function _toPolicyAcl(Api_Rule $ruleApi, $srcZone, array $sources, $dstZone, array $destinations)
		{
			$policyAcl = $this->_getPolicyAcl($ruleApi);

			if($policyAcl !== false) {
				return $policyAcl;
			}

			$result = array();
			$ruleName = $ruleApi->name;

			$result['aclName'] = self::ACL_NAME_PREFIX;
			$result['aclName'] .= $ruleApi->timestamp.'-'.$ruleName;

			$result['state'] = $ruleApi->state;
			$result['action'] = $ruleApi->action;

			$result['sources'] = $sources;
			$result['destinations'] = $destinations;

			$result['interface'] = $srcZone;

			$result['srcAdds'] = array();
			$result['dstAdds'] = array();

			foreach(array('src' => &$sources, 'dst' => &$destinations) as $attr => $attributes)
			{
				foreach($attributes as $attribute) {
					$addresses = $this->_toObjectAdd($attribute);
					$result[$attr.'Adds'] = array_merge($result[$attr.'Adds'], $addresses);
				}
			}

			$result['protoApps'] = array();

			foreach($ruleApi->protocols as $protocol) {
				$protocol = $this->_toProtocolApp($protocol);
				$result['protoApps'][] = $protocol;
			}

			$result['description'] = (string) $ruleApi->description;
			$this->_accessLists[$ruleName] = $result;
			return $result;
		}
	}