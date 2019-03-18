<?php
	namespace App\Firewall\Core;

	use Addon\Ipam;

	class Template_Juniper_Junos extends Template_Abstract
	{
		const PLATFORM = 'juniper';
		const TEMPLATE = 'junos';

		const ALLOW_RULE_MULTIZONES = self::RULE_MULTIZONES_NONE;

		const ADD_NAME_PREFIX = 'AD_';
		const APP_NAME_PREFIX = 'APP_';
		const ACL_NAME_PREFIX = 'PL_AUTO_';

		const ADDRESS_IPv_SEPARATOR = '-';
		const ADDRESS_ESCAPE_CHARACTERS = '---';


		/**
		  * @param App\Firewall\Core\Api_Address $addressApi
		  * @param string $zone
		  * @return array|false Address datas
		  */
		protected function _getObjectAdd(Api_Address $addressApi, $zone = null)
		{
			$addressName = $addressApi->name;

			if(isset($this->_addressBook[$zone]) && array_key_exists($addressName, $this->_addressBook[$zone])) {
				return $this->_addressBook[$zone][$addressName];
			}
			else {
				return false;
			}
		}

		protected function _toObjectAdd(Api_Address $addressApi, $zone = null)
		{
			$objectAdd = $this->_getObjectAdd($addressApi, $zone);

			if($objectAdd !== false) {
				return $objectAdd;
			}

			$addresses = array();

			$apiAddressName = $addressApi->name;

			/**
			  * CLEANER
			  */
			if($addressApi::OBJECT_TYPE === Api_Subnet::OBJECT_TYPE) {
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

				$result = array();

				if($addressApi->isANY($IPv)) {
					$name = 'any-ipv'.$IPv;
					$result['__doNotCreateAdd__'] = true;
				}
				else {
					$name = self::ADD_NAME_PREFIX.$addressName.self::ADDRESS_IPv_SEPARATOR.$IPv;
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
				$this->_addressBook[$zone][$apiAddressName][] = $result;
			}

			return $addresses;
		}

		protected function _toProtocolApp(Api_Protocol $protocolApi, $zone = null)
		{
			$protocolApp = $this->_getProtocolApp($protocolApi, $zone);

			if($protocolApp !== false) {
				return $protocolApp;
			}

			$result = array();

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
						$result['options'] = str_replace($protocolApi::PROTO_RANGE_SEPARATOR, '-', $protocolParts[1]);
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

			$result['srcZone'] = $srcZone;
			$result['dstZone'] = $dstZone;

			$result['srcAdds'] = array();
			$result['dstAdds'] = array();

			foreach(array('src' => &$sources, 'dst' => &$destinations) as $attr => $attributes)
			{
				foreach($attributes as $attribute)
				{
					$addresses = $this->_toObjectAdd($attribute, ${$attr.'Zone'});

					foreach($addresses as $address) {
						$result[$attr.'Adds'][] = $address['name'];
					}
				}
			}

			$result['protoApps'] = array();

			foreach($ruleApi->protocols as $protocol) {
				$protocol = $this->_toProtocolApp($protocol);
				$result['protoApps'][] = $protocol['name'];
			}

			$result['description'] = (string) $ruleApi->description;
			$this->_accessLists[$ruleName] = $result;
			return $result;
		}
	}