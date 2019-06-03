<?php
	namespace App\Firewall\Core;

	use ArrayObject;

	use Addon\Ipam;

	class Template_Web_Html extends Template_Software
	{
		const VENDOR = 'web';
		const PLATFORM = 'html';
		const TEMPLATE = null;

		const TEMPLATE_EXT = 'html';


		/**
		  * @param App\Firewall\Core\Api_Address $addressApi
		  * @return array|ArrayObject Object address datas
		  */
		protected function _toObjectAdd(Api_Address $addressApi)
		{
			$objectAdd = $this->_getObjectAdd($addressApi);

			if($objectAdd !== false) {
				return $objectAdd;
			}

			$addressName = $addressApi->name;
			$address = $addressApi->toObject();

			$this->_addresses[$addressName] = $address;
			return $address;
		}

		/**
		  * @param App\Firewall\Core\Api_Protocol $protocolApi
		  * @return array|ArrayObject Protocol application datas
		  */
		protected function _toProtocolApp(Api_Protocol $protocolApi)
		{
			$protocolApp = $this->_getProtocolApp($protocolApi);

			if($protocolApp !== false) {
				return $protocolApp;
			}

			$protocolName = $protocolApi->name;
			$protocol = $protocolApi->toObject();

			$this->_protocols[$protocolName] = $protocol;
			return $protocol;
		}

		/**
		  * @param App\Firewall\Core\Api_Rule $ruleApi
		  * @return array|ArrayObject Policy accesslist datas
		  */
		protected function _toPolicyAcl(Api_Rule $ruleApi)
		{
			$policyAcl = $this->_getPolicyAcl($ruleApi);

			if($policyAcl !== false) {
				return $policyAcl;
			}

			$ruleName = $ruleApi->name;
			$rule = $ruleApi->toObject();

			$rule['fullmesh'] = ($rule['fullmesh']) ? ('yes') : ('no');
			$rule['state'] = ($rule['state']) ? ('enabled') : ('disabled');
			$rule['action'] = ($rule['action']) ? ('permit') : ('deny');

			foreach(array('sources', 'destinations') as $attributes)
			{
				foreach($rule[$attributes] as &$Api_Address)
				{
					$address = array(
						'name' => $Api_Address->name,
						'attributeV4' => $Api_Address->attributeV4,
						'attributeV6' => $Api_Address->attributeV6,
					);

					$Api_Address = $address;
				}
				unset($Api_Address);
			}

			foreach($rule['protocols'] as &$Api_Protocol) {
				$Api_Protocol = $Api_Protocol->protocol;
			}
			unset($Api_Protocol);

			foreach($rule['tags'] as &$Api_Tag) {
				$Api_Tag = $Api_Tag->tag;
			}
			unset($Api_Tag);

			$rule['date'] = date('Y-m-d H:i:s', $rule['timestamp']);

			$this->_rules[$ruleName] = $rule;
			return $rule;
		}
	}