<?php
	namespace App\Firewall\Core;

	use ArrayObject;

	use Core\Exception as E;

	use Addon\Ipam;

	class Template_Cisco_Asa extends Template_Appliance
	{
		const VENDOR = 'cisco';
		const PLATFORM = 'asa';
		const TEMPLATE = null;

		const ALLOW_RULE_MULTIZONES = self::RULE_MULTIZONES_DST;

		const ADD_NAME_PREFIX = '';
		const APP_NAME_PREFIX = '';
		const ACL_NAME_PREFIX = '';

		const ADDRESS_IPv_SEPARATOR = '-';
		const ADDRESS_ESCAPE_CHARACTERS = '---';

		const ADDRESS_SUBNET_IPv_SEPARATOR = '-network';

		const ADDRESS_NAME_MAX_LENGTH = 64;			// https://www.cisco.com/c/en/us/td/docs/security/asa/asa98/configuration/firewall/asa-98-firewall-config/access-objects.html
		const RULE_NAME_MAX_LENGTH = 241;			// https://www.cisco.com/c/en/us/td/docs/security/asa/asa98/configuration/firewall/asa-98-firewall-config/access-acls.html
		const RULE_DESCRIPTION_MAX_LENGTH = 101;


		/**
		  * @return array Variables for rendering template
		  */
		protected function _getTemplateVars()
		{
			$vars = parent::_getTemplateVars();
			$vars['globalZone'] = $this->_siteApi->globalZone;
			return $vars;
		}

		/**
		  * @param App\Firewall\Core\Api_Address $addressApi
		  * @param string $zone
		  * @return array|ArrayObject Object address datas
		  */
		protected function _toObjectAdd(Api_Address $addressApi, $zone = null)
		{
			$objectAdd = $this->_getObjectAdd($addressApi, null);

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

			// https://www.cisco.com/c/en/us/td/docs/security/asa/asa98/configuration/firewall/asa-98-firewall-config/access-objects.html#ID-2122-00000008
			$addressName = preg_replace('#[^a-z0-9.!@\#\$%\^&()\-_{}]#ui', self::ADDRESS_ESCAPE_CHARACTERS, $addressName);

			if(mb_strlen($addressName) > static::ADDRESS_NAME_MAX_LENGTH) {
				$eMessage = "The address object '".$apiAddressName."' has its template name '".$addressName."' too long: ";
				$eMessage .= static::ADDRESS_NAME_MAX_LENGTH." characters max are allowed!";
				throw new E\Message($eMessage, E_USER_WARNING);
			}

			foreach(array(4 => $addressApi::FIELD_ATTRv4, 6 => $addressApi::FIELD_ATTRv6) as $IPv => $attrName)
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

				switch($addressApi::OBJECT_TYPE)
				{
					case Api_Subnet::OBJECT_TYPE:
					{
						if($IPv === 4) {
							$address = explode(Api_Subnet::SEPARATOR, $address);
							$address[1] = Tools::cidrMaskToNetMask($address[1]);
						}
						else {
							$address = array($address);
						}
						break;
					}
					case Api_Network::OBJECT_TYPE: {
						$address = explode(Api_Network::SEPARATOR, $address);
						break;
					}
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

		/**
		  * @param App\Firewall\Core\Api_Protocol $protocolApi
		  * @param string $zone
		  * @return array|ArrayObject Protocol application datas
		  */
		protected function _toProtocolApp(Api_Protocol $protocolApi, $zone = null)
		{
			$protocolApp = $this->_getProtocolApp($protocolApi, null);

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

		/**
		  * @param App\Firewall\Core\Api_Rule $ruleApi
		  * @param array $srcZones
		  * @param array $sources
		  * @param array $dstZones
		  * @param array $destinations
		  * @return array|ArrayObject Policy accesslist datas
		  */
		protected function _toPolicyAcl(Api_Rule $ruleApi, array $srcZones, array $sources, array $dstZones, array $destinations)
		{
			$policyAcl = $this->_getPolicyAcl($ruleApi);

			if($policyAcl !== false) {
				return $policyAcl;
			}

			$ruleName = $ruleApi->name;
			$result = new ArrayObject(array(), ArrayObject::ARRAY_AS_PROPS);

			$result['aclName'] = self::ACL_NAME_PREFIX;
			$result['aclName'] .= $ruleApi->timestamp.'-'.$ruleName;

			if(mb_strlen($result['aclName']) > static::RULE_NAME_MAX_LENGTH) {
				$eMessage = "The rule object '".$ruleName."' has its template name '".$result['aclName']."' too long: ";
				$eMessage .= static::RULE_NAME_MAX_LENGTH." characters max are allowed!";
				throw new E\Message($eMessage, E_USER_WARNING);
			}

			$result['state'] = $ruleApi->state;
			$result['action'] = $ruleApi->action;

			$result['sources'] = $sources;
			$result['destinations'] = $destinations;

			$srcZones = array_unique($srcZones);

			if(count($srcZones) === 1) {
				$result['interface'] = current($srcZones);
			}
			else {
				throw new E\Message("Ce template '".static::VENDOR."-".static::PLATFORM."' n'est pas compatible avec l'ACL multi-zones '".$ruleApi->name."'", E_USER_ERROR);
			}

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

			$result['tags'] = array();

			foreach($ruleApi->tags as $tag) {
				$result['tags'][] = $tag->tag;
			}

			$result['description'] = mb_substr($ruleApi->description, 0, static::RULE_DESCRIPTION_MAX_LENGTH);

			$this->_accessLists[$ruleName] = $result;
			return $result;
		}
	}