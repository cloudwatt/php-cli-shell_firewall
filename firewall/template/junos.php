<?php
	class Firewall_Template_Junos extends Firewall_Template_Abstract
	{
		const PLATFORM = 'juniper';
		const TEMPLATE = 'junos';


		protected function _toObjectAdd(Firewall_Api_Address $Firewall_Api_Address, $zone)
		{
			$objectAdd = $this->_getObjectAdd($Firewall_Api_Address, $zone);

			if($objectAdd !== false) {
				return $objectAdd;
			}

			$addresses = array();
			$addressName = $Firewall_Api_Address->name;

			foreach(array('4' => $Firewall_Api_Address::FIELD_ATTRv4, '6' => $Firewall_Api_Address::FIELD_ATTRv6) as $IPv => $attrName)
			{
				if(!$Firewall_Api_Address->isIPv($IPv)) {
					continue;
				}

				$name = 'AD_'.$addressName.'-'.$IPv;
				$address = $Firewall_Api_Address->{$attrName};

				if($Firewall_Api_Address::OBJECT_TYPE === 'network') {
					$option = 'range-address';
					$address = explode('-', $address);
					$address = $option.' '.implode(' to ', $address);
				}

				$result = array();
				$result['name'] = $name;
				$result['address'] = $address;

				$addresses[] = $result;
				$this->_addressBook[$zone][$addressName][] = $result;
			}

			return $addresses;
		}

		protected function _toProtocolApp(Firewall_Api_Protocol $Firewall_Api_Protocol)
		{
			$protocolApp = $this->_getProtocolApp($Firewall_Api_Protocol);

			if($protocolApp !== false) {
				return $protocolApp;
			}

			$result = array();
			$protocolName = $Firewall_Api_Protocol->name;
			$protocol = $Firewall_Api_Protocol->protocol;

			$result['name'] = 'APP_';
			$result['name'].= str_replace(
				array($Firewall_Api_Protocol::PROTO_SEPARATOR, ':'),
				array('-', '-'),
				$protocol
			);

			$protocolParts = explode($Firewall_Api_Protocol::PROTO_SEPARATOR, $protocol);

			$result['protocol'] = $protocolParts[0];

			if(isset($protocolParts[1])) {
				$result['options'] = $protocolParts[1];
			}

			$this->_applications[$protocolName] = $result;
			return $result;
		}

		protected function _toPolicyAcl(Firewall_Api_Rule $Firewall_Api_Rule, $srcZone, array $sources, $dstZone, array $destinations)
		{
			$policyAcl = $this->_getPolicyAcl($Firewall_Api_Rule);

			if($policyAcl !== false) {
				return $policyAcl;
			}

			$result = array();
			$ruleName = $Firewall_Api_Rule->name;

			$result['aclName'] = 'PL_AUTO_'.$Firewall_Api_Rule->timestamp.'-'.$ruleName;
			$result['action'] = $Firewall_Api_Rule->action;

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

			foreach($Firewall_Api_Rule->protocols as $protocol) {
				$protocol = $this->_toProtocolApp($protocol);
				$result['protoApps'][] = $protocol['name'];
			}

			$result['description'] = (string) $Firewall_Api_Rule->description;
			$this->_accessLists[$ruleName] = $result;
			return $result;
		}
	}