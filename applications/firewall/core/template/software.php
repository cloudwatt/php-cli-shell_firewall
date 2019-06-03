<?php
	namespace App\Firewall\Core;

	use Core as C;
	use Core\Exception as E;

	use Cli as Cli;

	abstract class Template_Software extends Template_Abstract
	{
		/**
		  * Addresses
		  * @var array
		  */
		protected $_addresses = array();

		/**
		  * Applications
		  * @var array
		  */
		protected $_protocols = array();

		/**
		  * Access lists
		  * @var array
		  */
		protected $_rules = array();


		/**
		  * @return array Variables for rendering template
		  */
		protected function _getTemplateVars()
		{
			return array(
				'addresses' => $this->_addresses,
				'protocols' => $this->_protocols,
				'rules' => $this->_rules,
			);
		}

		/**
		  * @param App\Firewall\Core\Api_Site[] $sites
		  * @param array $objects
		  * @return bool
		  */
		protected function _processing(array $sites, array $objects)
		{
			$ruleSection = self::OBJECT_TYPE_SECTION[Api_Rule::OBJECT_TYPE];

			if(array_key_exists($ruleSection, $objects))
			{
				foreach($objects[$ruleSection] as $Api_Rule) {
					$this->_prepareToPolicyAcl($Api_Rule);
				}

				return true;
			}

			return false;
		}

		/**
		  * @param App\Firewall\Core\Api_Address $addressApi
		  * @param string $zone
		  * @return array|ArrayObject|false Address datas
		  */
		protected function _getObjectAdd(Api_Address $addressApi)
		{
			$addressName = $addressApi->name;

			if(array_key_exists($addressName, $this->_addresses)) {
				return $this->_addresses[$addressName];
			}
			else {
				return false;
			}
		}

		/**
		  * @param App\Firewall\Core\Api_Address $addressApi
		  * @return array|ArrayObject Object address datas
		  */
		protected function _prepareToObjectAdd(Api_Address $addressApi)
		{
			return $this->_toObjectAdd($addressApi);
		}

		/**
		  * @param App\Firewall\Core\Api_Address $addressApi
		  * @return array|ArrayObject Object address datas
		  */
		abstract protected function _toObjectAdd(Api_Address $addressApi);

		/**
		  * @param App\Firewall\Core\Api_Protocol $protocolApi
		  * @return array|ArrayObject|false Protocol datas
		  */
		protected function _getProtocolApp(Api_Protocol $protocolApi)
		{
			$protocolName = $protocolApi->name;

			if(array_key_exists($protocolName, $this->_protocols)) {
				return $this->_protocols[$protocolName];
			}
			else {
				return false;
			}
		}

		/**
		  * @param App\Firewall\Core\Api_Protocol $protocolApi
		  * @return array|ArrayObject Protocol application datas
		  */
		protected function _prepareToProtocolApp(Api_Protocol $protocolApi)
		{
			return $this->_toProtocolApp($protocolApi);
		}

		/**
		  * @param App\Firewall\Core\Api_Protocol $protocolApi
		  * @return array|ArrayObject Protocol application datas
		  */
		abstract protected function _toProtocolApp(Api_Protocol $protocolApi);

		/**
		  * @param App\Firewall\Core\Api_Rule $ruleApi
		  * @return array|ArrayObject|false Rule datas
		  */
		protected function _getPolicyAcl(Api_Rule $ruleApi)
		{
			$ruleName = $ruleApi->name;

			if(array_key_exists($ruleName, $this->_rules)) {
				return $this->_rules[$ruleName];
			}
			else {
				return false;
			}
		}

		/**
		  * @param App\Firewall\Core\Api_Rule $ruleApi
		  * @return array|ArrayObject Policy accesslist datas
		  */
		protected function _prepareToPolicyAcl(Api_Rule $ruleApi)
		{
			return $this->_toPolicyAcl($ruleApi);
		}

		/**
		  * @param App\Firewall\Core\Api_Rule $ruleApi
		  * @return array|ArrayObject Policy accesslist datas
		  */
		abstract protected function _toPolicyAcl(Api_Rule $ruleApi);
	}